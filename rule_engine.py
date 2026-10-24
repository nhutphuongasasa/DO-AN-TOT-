"""Rule Engine for Encrypted Traffic Classification.

This module provides the core multi-layer classification engine for network flows.
It inspects SNI, correlates DNS queries/responses, checks TLS fingerprints (JA3/JA4),
evaluates port/protocol mappings, and checks destination IP/ASN allocations to identify
the underlying application even under TLS 1.3 / QUIC encryption.

Components:
    - Evidence: Dataclass recording classification clues per layer.
    - ClassificationResult: Dataclass recording final classification outcome.
    - DomainMatcher: Reversed-label trie for efficient domain and subdomain matching.
    - DnsCache: Thread-safe cache correlating client IP + resolved IP with domains.
    - FlowTable: Thread-safe state table caching flow classification decisions.
    - RuleEngine: Central orchestrator combining evidence across layers.
"""

from __future__ import annotations

import copy
import ipaddress
import math
import re
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

import yaml

__all__ = [
    "Evidence",
    "ClassificationResult",
    "DomainMatcher",
    "DnsCache",
    "FlowTable",
    "RuleEngine",
    "load_rules",
    "LAYER_PRIORITY",
]

# Layer priority hierarchy: Lower number = higher precedence during conflicts.
LAYER_PRIORITY: Dict[str, int] = {
    "sni": 1,
    "dns": 2,
    "ja3": 3,
    "ja4": 3,
    "port": 4,
    "ip_asn": 5,
}


@dataclass
class Evidence:
    """Represents a piece of classification evidence gathered from an inspection layer.

    Attributes:
        app: Application identifier identified by this layer (e.g., 'youtube', 'facebook').
        confidence: Confidence score in the range [0.0, 1.0].
        source: Source layer ('sni', 'dns', 'ja3', 'ja4', 'port', 'ip_asn').
        matched_rule: String representation of the rule that matched (if applicable).
        group: Rule group category, such as 'A' (primary), 'B' (shared CDN/cloud),
            'B-' (ambiguous), 'C' (generic tracker/ad).
        conflict: Whether this evidence conflicts with evidence from other layers.
        details: Optional diagnostic or contextual information.
    """

    app: str
    confidence: float
    source: str
    matched_rule: Optional[str] = None
    group: Optional[str] = None
    conflict: bool = False
    details: Optional[str] = None

    def __repr__(self) -> str:
        return (
            f"Evidence(app={self.app!r}, confidence={self.confidence:.4f}, "
            f"source={self.source!r}, matched_rule={self.matched_rule!r}, "
            f"group={self.group!r}, conflict={self.conflict}, details={self.details!r})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence instance to a dictionary with rounded confidence."""
        return {
            "app": self.app,
            "confidence": round(float(self.confidence), 4),
            "source": self.source,
            "matched_rule": self.matched_rule,
            "group": self.group,
            "conflict": self.conflict,
            "details": self.details,
        }


@dataclass
class ClassificationResult:
    """The outcome of flow classification produced by the Rule Engine.

    Attributes:
        app: The determined application name or 'unknown'.
        confidence: Confidence score in [0.0, 1.0], rounded to 4 decimals.
        source: Determinant source ('sni', 'dns', 'ja3', 'ja4', 'port', 'ip_asn',
            'combined', or 'none').
        matched_rule: The specific pattern or rule identifier that decided the match.
        evidence: List of evidence items (represented as dictionaries).
    """

    app: str
    confidence: float
    source: str
    matched_rule: Optional[str] = None
    evidence: List[Dict[str, Any]] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"ClassificationResult(app={self.app!r}, confidence={self.confidence:.4f}, "
            f"source={self.source!r}, matched_rule={self.matched_rule!r}, "
            f"evidence_count={len(self.evidence)})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert result instance to a dictionary formatted for serialization."""
        return {
            "app": self.app,
            "confidence": round(float(self.confidence), 4),
            "source": self.source,
            "matched_rule": self.matched_rule,
            "evidence": copy.deepcopy(self.evidence),
        }


class DomainMatcher:
    """Reversed-label trie for high-performance O(k) domain and subdomain matching.

    Supports three pattern types:
        - Regular rules (`domain.com`): Matches `domain.com` and all subdomains `*.domain.com`.
        - Wildcard rules (`*.domain.com`): Matches strictly subdomains, NOT bare `domain.com`.
        - Exact rules (`=domain.com`): Matches strictly `domain.com`, NOT subdomains.

    Maintains label boundary integrity so that `youtube.com` matches `www.youtube.com`
    but will never match `notyoutube.com` or `youtube.com.evil.com`.
    """

    def __init__(
        self,
        domain_rules: Optional[List[Dict[str, Any]]] = None,
        ignored_domains: Optional[Iterable[str]] = None,
    ) -> None:
        """Initialize the DomainMatcher.

        Args:
            domain_rules: List of domain rule dictionaries containing patterns,
                app name, confidence, group, etc.
            ignored_domains: Domains that should be ignored/skipped during matching.

        Raises:
            ValueError: If duplicate domains across rules, invalid confidence,
                or invalid wildcard syntax are detected.
        """
        # Node structure: {'children': {}, 'rules': [], 'wildcard_rules': [], 'exact_rules': []}
        self.root: Dict[str, Any] = self._new_node()
        self.ignored_domains: Set[str] = set()

        if ignored_domains:
            for d in ignored_domains:
                normalized = self.normalize_domain(d)
                if normalized:
                    self.ignored_domains.add(normalized)

        if domain_rules:
            self._load_and_validate_rules(domain_rules)

    @staticmethod
    def _new_node() -> Dict[str, Any]:
        return {
            "children": {},
            "rules": [],
            "wildcard_rules": [],
            "exact_rules": [],
        }

    @staticmethod
    def normalize_domain(domain: Optional[str]) -> Optional[str]:
        """Normalize a domain name string.

        Performs:
            - Lowercasing
            - Whitespace and trailing dot stripping
            - Punycode (IDNA) decoding check
            - IP literal rejection

        Args:
            domain: Raw domain string.

        Returns:
            Normalized domain string or None if empty, invalid, or an IP address literal.
        """
        if not domain or not isinstance(domain, str):
            return None

        clean = domain.strip().lower().rstrip(".")
        if not clean:
            return None

        # Check if it is an IP address literal
        try:
            ipaddress.ip_address(clean)
            return None
        except ValueError:
            pass

        # Handle punycode decoding if present
        if "xn--" in clean:
            try:
                # Validate punycode decoding
                clean.encode("ascii").decode("idna")
            except Exception:
                # If invalid punycode, keep as-is or reject if unparseable
                pass

        # Validate that domain contains valid characters (labels separated by dots)
        labels = clean.split(".")
        if any(len(label) == 0 for label in labels):
            return None

        return clean

    def _load_and_validate_rules(self, domain_rules: List[Dict[str, Any]]) -> None:
        """Validate and insert rules into the reversed-label trie."""
        seen_patterns: Dict[str, str] = {}  # pattern -> app name

        for rule in domain_rules:
            app = rule.get("app")
            if not app:
                raise ValueError(f"Domain rule missing required 'app' field: {rule}")

            confidence = rule.get("confidence", 1.0)
            if not isinstance(confidence, (int, float)) or not (0.0 <= confidence <= 1.0):
                raise ValueError(
                    f"Rule for app '{app}' has invalid confidence {confidence!r}. Must be in [0.0, 1.0]."
                )

            patterns = rule.get("domains") or rule.get("patterns") or []
            if isinstance(patterns, str):
                patterns = [patterns]

            group = rule.get("group", "A")
            exclude_patterns = rule.get("exclude", [])
            variants = rule.get("variants", [])

            for raw_pattern in patterns:
                pattern_type, clean_pattern = self._parse_pattern(raw_pattern)

                # Check duplicate patterns across rules
                if clean_pattern in seen_patterns:
                    existing_app = seen_patterns[clean_pattern]
                    if existing_app != app:
                        raise ValueError(
                            f"Duplicate domain pattern {raw_pattern!r} found across applications: "
                            f"'{existing_app}' and '{app}'."
                        )

                seen_patterns[clean_pattern] = app

                rule_meta = {
                    "app": app,
                    "confidence": float(confidence),
                    "group": group,
                    "pattern": raw_pattern,
                    "clean_pattern": clean_pattern,
                    "pattern_type": pattern_type,
                    "exclude": [
                        self.normalize_domain(e)
                        for e in exclude_patterns
                        if self.normalize_domain(e)
                    ],
                    "variants": variants,
                }
                self._insert_pattern(clean_pattern, pattern_type, rule_meta)

    @classmethod
    def _parse_pattern(cls, pattern: str) -> Tuple[str, str]:
        """Parse pattern syntax into (type, normalized_domain).

        Types:
            - 'exact': starts with '='
            - 'wildcard': starts with '*.'
            - 'regular': standard domain matching domain and subdomains
        """
        raw = pattern.strip()
        if not raw:
            raise ValueError("Domain pattern cannot be empty.")

        if raw.startswith("="):
            clean = cls.normalize_domain(raw[1:])
            if not clean:
                raise ValueError(f"Invalid exact domain pattern syntax: {raw!r}")
            return "exact", clean

        if raw.startswith("*."):
            rest = raw[2:]
            if "*" in rest:
                raise ValueError(
                    f"Invalid wildcard syntax in {raw!r}: wildcard '*' is only permitted as '*.' prefix."
                )
            clean = cls.normalize_domain(rest)
            if not clean:
                raise ValueError(f"Invalid wildcard domain pattern: {raw!r}")
            return "wildcard", clean

        if "*" in raw:
            raise ValueError(
                f"Invalid wildcard syntax in {raw!r}: wildcards must be formatted as '*.domain.com'."
            )

        clean = cls.normalize_domain(raw)
        if not clean:
            raise ValueError(f"Invalid regular domain pattern: {raw!r}")
        return "regular", clean

    def _insert_pattern(self, domain: str, pattern_type: str, rule_meta: Dict[str, Any]) -> None:
        """Insert a rule into the trie along reversed labels."""
        labels = domain.split(".")
        labels.reverse()

        current = self.root
        for label in labels:
            if label not in current["children"]:
                current["children"][label] = self._new_node()
            current = current["children"][label]

        if pattern_type == "exact":
            current["exact_rules"].append(rule_meta)
        elif pattern_type == "wildcard":
            current["wildcard_rules"].append(rule_meta)
        else:
            current["rules"].append(rule_meta)

    def match(self, domain: str) -> Optional[Dict[str, Any]]:
        """Match a domain against the reversed-label trie.

        Matching semantics:
            - Normalizes the input domain.
            - Evaluates against the ignored_domains set.
            - Traverses the trie reversed-label by reversed-label.
            - Enforces rule types (exact, wildcard, regular).
            - Discards candidate rules whose exclude list matches the input domain.
            - Selects the rule with the LONGEST suffix match (most specific).

        Args:
            domain: The query domain string (e.g. 'meet.google.com').

        Returns:
            Dictionary containing 'app', 'confidence', 'group', 'matched_rule',
            and 'variants', or None if no match found or domain ignored.
        """
        normalized = self.normalize_domain(domain)
        if not normalized:
            return None

        # Check ignored domains
        if normalized in self.ignored_domains:
            return None
        # Also check if any parent domain is ignored
        labels_check = normalized.split(".")
        for i in range(1, len(labels_check)):
            parent_dom = ".".join(labels_check[i:])
            if parent_dom in self.ignored_domains:
                return None

        reversed_labels = normalized.split(".")
        reversed_labels.reverse()
        total_labels = len(reversed_labels)

        current = self.root
        candidates: List[Tuple[int, Dict[str, Any]]] = []

        # Traverse trie along reversed labels
        for depth, label in enumerate(reversed_labels, start=1):
            if label not in current["children"]:
                break
            current = current["children"][label]
            is_exact_end = depth == total_labels

            # Exact rules: match ONLY if the query domain ends exactly here (depth == total_labels)
            if is_exact_end and current["exact_rules"]:
                for r in current["exact_rules"]:
                    candidates.append((depth, r))

            # Wildcard rules (*.domain.com): match ONLY subdomains, NOT the bare domain
            if not is_exact_end and current["wildcard_rules"]:
                for r in current["wildcard_rules"]:
                    candidates.append((depth, r))

            # Regular rules (domain.com): match both the domain itself and any subdomain
            if current["rules"]:
                for r in current["rules"]:
                    candidates.append((depth, r))

        if not candidates:
            return None

        # Sort candidates by depth descending (longest suffix match first)
        candidates.sort(key=lambda item: item[0], reverse=True)

        for depth, rule in candidates:
            # Check exclude patterns
            excluded = False
            for exc in rule.get("exclude", []):
                if normalized == exc or normalized.endswith("." + exc):
                    excluded = True
                    break

            if excluded:
                continue

            return {
                "app": rule["app"],
                "confidence": rule["confidence"],
                "group": rule["group"],
                "matched_rule": rule["pattern"],
                "variants": rule.get("variants", []),
            }

        return None


class DnsCache:
    """Thread-safe DNS response cache for client IP to resolved IP correlation.

    Note:
        DNS over HTTPS (DoH) and DNS over TLS (DoT) encrypt DNS traffic and therefore
        cannot be passively observed or correlated by this system unless decrypted upstream.
    """

    def __init__(
        self,
        max_entries: int = 50000,
        min_ttl: float = 10.0,
        max_ttl: float = 86400.0,
        default_ttl: float = 300.0,
    ) -> None:
        """Initialize the DnsCache.

        Args:
            max_entries: Maximum number of entries kept in the LRU cache.
            min_ttl: Minimum enforced TTL in seconds.
            max_ttl: Maximum enforced TTL in seconds.
            default_ttl: Default fallback TTL in seconds if not provided or 0.
        """
        self._max_entries = max_entries
        self._min_ttl = min_ttl
        self._max_ttl = max_ttl
        self._default_ttl = default_ttl

        self._lock = threading.Lock()
        # _cache: (client_ip, resolved_ip) -> {domain, cname_chain, expires_at, inserted_at}
        self._cache: OrderedDict[Tuple[str, str], Dict[str, Any]] = OrderedDict()
        # _domain_index: (client_ip, resolved_ip) -> list of domains seen
        self._domain_index: Dict[Tuple[str, str], List[str]] = {}

    def ingest_dns_response(
        self,
        client_ip: str,
        query_name: str,
        answers: List[str],
        cnames: Optional[List[str]] = None,
        ttl: Optional[float] = None,
        timestamp: Optional[float] = None,
    ) -> None:
        """Ingest DNS response records into the cache.

        Args:
            client_ip: IP address of the client that issued the query.
            query_name: Queried domain name.
            answers: List of resolved IP addresses (A/AAAA records).
            cnames: List of CNAME records encountered in the resolution chain.
            ttl: Time-To-Live reported in the DNS answer.
            timestamp: Unix timestamp when the DNS response was observed.
        """
        if timestamp is None:
            timestamp = time.time()

        if cnames is None:
            cnames = []

        # Clamp TTL
        effective_ttl = self._default_ttl if (ttl is None or ttl <= 0) else float(ttl)
        clamped_ttl = max(self._min_ttl, min(self._max_ttl, effective_ttl))
        expires_at = timestamp + clamped_ttl

        with self._lock:
            for ip in answers:
                if not isinstance(ip, str) or not ip.strip():
                    continue

                key = (client_ip, ip.strip())
                entry = {
                    "domain": query_name,
                    "cname_chain": list(cnames),
                    "expires_at": expires_at,
                    "inserted_at": timestamp,
                }

                # Update or store entry in LRU cache
                if key in self._cache:
                    self._cache.move_to_end(key)
                self._cache[key] = entry

                # Maintain multi-domain index
                if key not in self._domain_index:
                    self._domain_index[key] = []
                domain_list = self._domain_index[key]
                if query_name not in domain_list:
                    domain_list.append(query_name)
                for cn in cnames:
                    if cn and cn not in domain_list:
                        domain_list.append(cn)

                # Evict oldest entry if exceeding max capacity
                if len(self._cache) > self._max_entries:
                    oldest_key, _ = self._cache.popitem(last=False)
                    self._domain_index.pop(oldest_key, None)

    def lookup(
        self, client_ip: str, dest_ip: str, timestamp: Optional[float] = None
    ) -> Optional[Dict[str, Any]]:
        """Look up the domain associated with a client IP and destination IP.

        Args:
            client_ip: Client source IP address.
            dest_ip: Destination server IP address.
            timestamp: Unix timestamp of the query lookup.

        Returns:
            Dictionary with 'domain', 'cname_chain', and 'multi_domain' (bool),
            or None if not found or expired.
        """
        if timestamp is None:
            timestamp = time.time()

        key = (client_ip, dest_ip)
        with self._lock:
            if key not in self._cache:
                return None

            entry = self._cache[key]
            if entry["expires_at"] < timestamp:
                # Expired - remove from cache
                del self._cache[key]
                self._domain_index.pop(key, None)
                return None

            # Refresh LRU position
            self._cache.move_to_end(key)

            # Check multi-domain condition
            domains_seen = self._domain_index.get(key, [])
            multi_domain = len(set(domains_seen)) > 1

            return {
                "domain": entry["domain"],
                "cname_chain": list(entry["cname_chain"]),
                "multi_domain": multi_domain,
            }

    def cleanup_expired(self, timestamp: Optional[float] = None) -> int:
        """Evict all expired entries from the cache.

        Args:
            timestamp: Current Unix timestamp.

        Returns:
            Number of entries evicted.
        """
        if timestamp is None:
            timestamp = time.time()

        evicted = 0
        with self._lock:
            expired_keys = [k for k, v in self._cache.items() if v["expires_at"] < timestamp]
            for k in expired_keys:
                del self._cache[k]
                self._domain_index.pop(k, None)
                evicted += 1

        return evicted


class FlowTable:
    """Thread-safe flow classification state table.

    Caches classification decisions by 5-tuple flow key:
    `(src_ip, src_port, dst_ip, dst_port, protocol)`.
    """

    def __init__(
        self,
        max_entries: int = 100000,
        flow_ttl: float = 120.0,
        cache_threshold: float = 0.8,
        flow_reclassify_packets: int = 5,
    ) -> None:
        """Initialize the FlowTable.

        Args:
            max_entries: Maximum number of flows cached.
            flow_ttl: Inactivity timeout in seconds after which flow expires.
            cache_threshold: Minimum confidence required to cache a classification.
            flow_reclassify_packets: Number of initial packets during which
                flow can be reclassified or upgraded.
        """
        self._max_entries = max_entries
        self._flow_ttl = flow_ttl
        self._cache_threshold = cache_threshold
        self._flow_reclassify_packets = flow_reclassify_packets

        self._lock = threading.Lock()
        # Key: 5-tuple -> {'result': ClassificationResult, 'last_seen': float,
        #                  'packet_count': int, 'created_at': float}
        self._table: OrderedDict[Tuple[str, int, str, int, str], Dict[str, Any]] = OrderedDict()

    def lookup(
        self, flow_key: Tuple[str, int, str, int, str], timestamp: Optional[float] = None
    ) -> Optional[ClassificationResult]:
        """Look up flow classification in the table.

        Args:
            flow_key: 5-tuple `(src_ip, src_port, dst_ip, dst_port, protocol)`.
            timestamp: Current Unix timestamp.

        Returns:
            ClassificationResult if cached and not expired, else None.
        """
        if timestamp is None:
            timestamp = time.time()

        with self._lock:
            if flow_key not in self._table:
                return None

            entry = self._table[flow_key]
            if timestamp - entry["last_seen"] > self._flow_ttl:
                del self._table[flow_key]
                return None

            entry["last_seen"] = timestamp
            self._table.move_to_end(flow_key)
            return entry["result"]

    def store(
        self,
        flow_key: Tuple[str, int, str, int, str],
        result: ClassificationResult,
        timestamp: Optional[float] = None,
    ) -> None:
        """Store flow classification result into the table.

        Only stores if confidence meets or exceeds `cache_threshold` and app is not 'unknown'.

        Args:
            flow_key: 5-tuple `(src_ip, src_port, dst_ip, dst_port, protocol)`.
            result: The classification result to store.
            timestamp: Current Unix timestamp.
        """
        if result.confidence < self._cache_threshold or result.app == "unknown":
            return

        if timestamp is None:
            timestamp = time.time()

        with self._lock:
            if flow_key in self._table:
                entry = self._table[flow_key]
                entry["result"] = result
                entry["last_seen"] = timestamp
                entry["packet_count"] += 1
                self._table.move_to_end(flow_key)
            else:
                if len(self._table) >= self._max_entries:
                    self._table.popitem(last=False)

                self._table[flow_key] = {
                    "result": result,
                    "last_seen": timestamp,
                    "packet_count": 1,
                    "created_at": timestamp,
                }

    def should_reclassify(self, flow_key: Tuple[str, int, str, int, str]) -> bool:
        """Determine whether flow should be re-evaluated.

        Args:
            flow_key: 5-tuple `(src_ip, src_port, dst_ip, dst_port, protocol)`.

        Returns:
            True if flow is not in table or packet count < flow_reclassify_packets.
        """
        with self._lock:
            if flow_key not in self._table:
                return True
            entry = self._table[flow_key]
            entry["packet_count"] += 1
            return entry["packet_count"] <= self._flow_reclassify_packets

    def upgrade(
        self,
        flow_key: Tuple[str, int, str, int, str],
        new_result: ClassificationResult,
        timestamp: Optional[float] = None,
    ) -> None:
        """Upgrade existing flow result if new result has strictly higher confidence.

        Args:
            flow_key: 5-tuple flow key.
            new_result: Proposed upgraded result.
            timestamp: Current Unix timestamp.
        """
        if timestamp is None:
            timestamp = time.time()

        with self._lock:
            if flow_key in self._table:
                current_entry = self._table[flow_key]
                if new_result.confidence > current_entry["result"].confidence:
                    current_entry["result"] = new_result
                    current_entry["last_seen"] = timestamp
                    self._table.move_to_end(flow_key)
            else:
                self.store(flow_key, new_result, timestamp)

    def cleanup_expired(self, timestamp: Optional[float] = None) -> int:
        """Remove expired flows from table."""
        if timestamp is None:
            timestamp = time.time()

        evicted = 0
        with self._lock:
            expired_keys = [
                k
                for k, v in self._table.items()
                if (timestamp - v["last_seen"]) > self._flow_ttl
            ]
            for k in expired_keys:
                del self._table[k]
                evicted += 1
        return evicted


def load_rules(path: Union[str, Path]) -> Dict[str, Any]:
    """Load and validate rules configuration from a YAML file.

    Args:
        path: Path to the YAML rules file.

    Returns:
        Parsed rules dictionary.

    Raises:
        FileNotFoundError: If the rules file does not exist.
        ValueError: If YAML parsing fails or version is missing.
    """
    rule_file = Path(path)
    if not rule_file.is_file():
        raise FileNotFoundError(f"Rules configuration file not found at: {rule_file}")

    try:
        with open(rule_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise ValueError(f"Failed to parse YAML rules file: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Rules file root must be a YAML mapping/dictionary.")

    if "version" not in data:
        raise ValueError("Rules configuration missing mandatory 'version' field.")

    return data


class RuleEngine:
    """Core multi-layer Rule Engine for Encrypted Traffic Classification.

    Coordinates 5 inspection layers:
        1. SNI / Domain matching (via reversed-label trie)
        2. DNS Correlation (via DnsCache + DomainMatcher)
        3. TLS Fingerprinting (JA4 preferred, JA3 fallback)
        4. Port & Transport Protocol inspection
        5. Destination IP & ASN CIDR allocations

    Combines evidence using probabilistic noisy-OR and layer hierarchy resolution.
    """

    def __init__(self, rules_path: Union[str, Path] = "rules.yaml") -> None:
        """Initialize RuleEngine from a YAML rules configuration file.

        Args:
            rules_path: Path to the rules YAML file.
        """
        self.rules_data = load_rules(rules_path)
        self._validate_rules(self.rules_data)

        # Extract settings with defaults
        settings = self.rules_data.get("settings", {})
        self.dns_confidence_factor = float(settings.get("dns_confidence_factor", 0.9))
        self.supplementary_max_confidence = float(
            settings.get("supplementary_max_confidence", 0.6)
        )
        self.ip_asn_max_confidence = float(settings.get("ip_asn_max_confidence", 0.4))
        self.conflict_penalty = float(settings.get("conflict_penalty", 0.2))
        self.min_confidence = float(settings.get("min_confidence", 0.5))

        dns_max_entries = int(settings.get("dns_max_entries", 50000))
        dns_min_ttl = float(settings.get("dns_min_ttl", 10.0))
        dns_max_ttl = float(settings.get("dns_max_ttl", 86400.0))
        dns_default_ttl = float(settings.get("dns_default_ttl", 300.0))

        flow_max_entries = int(settings.get("flow_max_entries", 100000))
        flow_ttl = float(settings.get("flow_ttl", 120.0))
        cache_threshold = float(settings.get("cache_threshold", 0.8))
        flow_reclassify_packets = int(settings.get("flow_reclassify_packets", 5))

        # Instantiate components
        domain_rules = self.rules_data.get("domain_rules", [])
        ignored_domains = self.rules_data.get("ignored_domains", [])
        self.domain_matcher = DomainMatcher(domain_rules, ignored_domains)

        self.dns_cache = DnsCache(
            max_entries=dns_max_entries,
            min_ttl=dns_min_ttl,
            max_ttl=dns_max_ttl,
            default_ttl=dns_default_ttl,
        )

        self.flow_table = FlowTable(
            max_entries=flow_max_entries,
            flow_ttl=flow_ttl,
            cache_threshold=cache_threshold,
            flow_reclassify_packets=flow_reclassify_packets,
        )

        # Index JA3 and JA4 rules
        self.ja3_rules: Dict[str, Dict[str, Any]] = {}
        for r in self.rules_data.get("ja3_rules", []):
            h = str(r.get("hash", "")).strip().lower()
            if h:
                self.ja3_rules[h] = r

        self.ja4_rules: Dict[str, Dict[str, Any]] = {}
        for r in self.rules_data.get("ja4_rules", []):
            h = str(r.get("hash", "")).strip().lower()
            if h:
                self.ja4_rules[h] = r

        # Index port rules: (port, protocol) -> rule
        self.port_rules: Dict[Tuple[int, str], Dict[str, Any]] = {}
        for r in self.rules_data.get("port_rules", []):
            p = int(r.get("port", 0))
            proto = str(r.get("protocol", "tcp")).strip().lower()
            if p > 0:
                self.port_rules[(p, proto)] = r

        # Parse IP / ASN rules
        self.ip_asn_rules: List[Dict[str, Any]] = []
        for r in self.rules_data.get("ip_asn_rules", []):
            subnets = []
            for cidr in r.get("cidrs", []):
                try:
                    subnets.append(ipaddress.ip_network(cidr.strip(), strict=False))
                except ValueError:
                    continue
            self.ip_asn_rules.append(
                {
                    "app": r.get("app"),
                    "confidence": float(r.get("confidence", 0.4)),
                    "subnets": subnets,
                    "asns": [str(a).strip().upper() for a in r.get("asns", [])],
                    "matched_rule": r.get("name") or r.get("app"),
                }
            )

    def _validate_rules(self, rules_data: Dict[str, Any]) -> None:
        """Validate YAML rule schema, confidence bounds, and wildcard patterns."""
        if "version" not in rules_data:
            raise ValueError("Rules configuration missing 'version' attribute.")

        # Validate domain rules
        seen_domains_by_group: Dict[str, Dict[str, str]] = {}
        for rule in rules_data.get("domain_rules", []):
            app = rule.get("app")
            if not app:
                raise ValueError(f"Domain rule missing 'app': {rule}")

            conf = rule.get("confidence", 1.0)
            if not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
                raise ValueError(
                    f"Invalid confidence {conf!r} in domain rule for app '{app}'. Must be in [0, 1]."
                )

            group = rule.get("group", "A")
            if group not in seen_domains_by_group:
                seen_domains_by_group[group] = {}

            patterns = rule.get("domains") or rule.get("patterns") or []
            if isinstance(patterns, str):
                patterns = [patterns]

            for pat in patterns:
                clean = pat.strip().lower()
                if clean.startswith("="):
                    clean = clean[1:]
                elif clean.startswith("*."):
                    clean = clean[2:]
                    if "*" in clean:
                        raise ValueError(f"Invalid wildcard syntax in domain pattern: {pat!r}")
                elif "*" in clean:
                    raise ValueError(f"Invalid wildcard syntax in domain pattern: {pat!r}")

                if clean in seen_domains_by_group[group]:
                    existing_app = seen_domains_by_group[group][clean]
                    if existing_app != app:
                        raise ValueError(
                            f"Duplicate domain '{clean}' in group '{group}' "
                            f"shared by different apps: '{existing_app}' and '{app}'."
                        )
                seen_domains_by_group[group][clean] = app

        # Validate JA3/JA4 rules
        for r in rules_data.get("ja3_rules", []) + rules_data.get("ja4_rules", []):
            conf = r.get("confidence", 0.5)
            if not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
                raise ValueError(f"Invalid fingerprint confidence {conf!r} in rule: {r}")

        # Validate Port rules
        for r in rules_data.get("port_rules", []):
            conf = r.get("confidence", 0.5)
            if not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
                raise ValueError(f"Invalid port rule confidence {conf!r} in rule: {r}")

        # Validate IP/ASN rules
        for r in rules_data.get("ip_asn_rules", []):
            conf = r.get("confidence", 0.4)
            if not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
                raise ValueError(f"Invalid IP/ASN confidence {conf!r} in rule: {r}")

    def ingest_dns_response(
        self,
        client_ip: str,
        query_name: str,
        answers: List[str],
        cnames: Optional[List[str]] = None,
        ttl: Optional[float] = None,
        timestamp: Optional[float] = None,
    ) -> None:
        """Delegate DNS response ingestion directly to DnsCache.

        Args:
            client_ip: IP address of querying client.
            query_name: Domain name queried.
            answers: List of resolved IP addresses.
            cnames: List of intermediate CNAME canonical names.
            ttl: Time-To-Live in seconds.
            timestamp: Unix timestamp.
        """
        self.dns_cache.ingest_dns_response(
            client_ip=client_ip,
            query_name=query_name,
            answers=answers,
            cnames=cnames,
            ttl=ttl,
            timestamp=timestamp,
        )

    def classify(self, flow_info: Dict[str, Any]) -> Dict[str, Any]:
        """Classify a network flow across all 5 inspection layers.

        Assumes the packet parsing layer has already extracted SNI from both TLS
        ClientHello and QUIC Initial (UDP 443).

        Args:
            flow_info: Dictionary containing flow attributes:
                - sni (Optional[str])
                - dns_domain (Optional[str])
                - ja3 (Optional[str])
                - ja4 (Optional[str])
                - port / dst_port (int)
                - protocol / transport (str: 'tcp'|'udp')
                - alpn (Optional[str])
                - client_ip / src_ip (str)
                - dest_ip / dst_ip (str)
                - src_port (int)
                - timestamp (Optional[float])

        Returns:
            Dictionary containing:
                - app (str): Classified application or 'unknown'
                - confidence (float): Confidence score rounded to 4 decimals
                - source (str): Determinant layer or 'combined' / 'none'
                - matched_rule (Optional[str]): Matching pattern/rule
                - evidence (List[dict]): List of Evidence objects as dicts
        """
        ts = flow_info.get("timestamp")
        timestamp = float(ts) if ts is not None else time.time()

        # Extract 5-tuple parameters
        src_ip = str(flow_info.get("src_ip") or flow_info.get("client_ip") or "").strip()
        src_port = int(flow_info.get("src_port") or 0)
        dst_ip = str(flow_info.get("dest_ip") or flow_info.get("dst_ip") or "").strip()
        dst_port = int(flow_info.get("port") or flow_info.get("dst_port") or 0)
        proto = str(
            flow_info.get("protocol") or flow_info.get("transport") or "tcp"
        ).strip().lower()

        flow_key = (src_ip, src_port, dst_ip, dst_port, proto)

        # 1. Fast Path: FlowTable hit
        if src_ip and dst_ip and src_port and dst_port:
            cached_result = self.flow_table.lookup(flow_key, timestamp)
            if cached_result is not None:
                return cached_result.to_dict()

        # 2. Slow Path: 5 Inspection Layers
        evidence_list: List[Evidence] = []

        # --- Layer 1: SNI / Domain ---
        raw_sni = flow_info.get("sni")
        has_sni = bool(raw_sni and isinstance(raw_sni, str) and raw_sni.strip())

        if has_sni:
            matched = self.domain_matcher.match(raw_sni)
            if matched:
                ev_sni = Evidence(
                    app=matched["app"],
                    confidence=float(matched["confidence"]),
                    source="sni",
                    matched_rule=matched["matched_rule"],
                    group=matched.get("group"),
                    details=f"SNI: {raw_sni}",
                )
                evidence_list.append(ev_sni)

                # Early exit condition: high confidence primary rule
                if ev_sni.confidence >= 0.90 and ev_sni.group not in ("C",):
                    result = ClassificationResult(
                        app=ev_sni.app,
                        confidence=round(ev_sni.confidence, 4),
                        source="sni",
                        matched_rule=ev_sni.matched_rule,
                        evidence=[ev_sni.to_dict()],
                    )
                    self.flow_table.store(flow_key, result, timestamp)
                    return result.to_dict()
        else:
            # Note missing SNI (potentially Encrypted Client Hello or cleartext)
            evidence_list.append(
                Evidence(
                    app="unknown",
                    confidence=0.0,
                    source="sni",
                    details="no_sni_or_ech",
                )
            )

        # --- Layer 2: DNS Correlation ---
        dns_domain_cand = flow_info.get("dns_domain")
        dns_cache_hit = None

        if src_ip and dst_ip:
            dns_cache_hit = self.dns_cache.lookup(src_ip, dst_ip, timestamp)

        target_dns_domain = None
        is_multi_domain = False
        if dns_cache_hit:
            target_dns_domain = dns_cache_hit["domain"]
            is_multi_domain = dns_cache_hit.get("multi_domain", False)
        elif dns_domain_cand and isinstance(dns_domain_cand, str) and dns_domain_cand.strip():
            target_dns_domain = dns_domain_cand.strip()

        if target_dns_domain:
            matched_dns = self.domain_matcher.match(target_dns_domain)
            if matched_dns:
                conf = float(matched_dns["confidence"]) * self.dns_confidence_factor
                if is_multi_domain:
                    conf *= 0.5

                ev_dns = Evidence(
                    app=matched_dns["app"],
                    confidence=conf,
                    source="dns",
                    matched_rule=matched_dns["matched_rule"],
                    group=matched_dns.get("group"),
                    details=(
                        f"DNS: {target_dns_domain}"
                        + (" (multi-domain IP)" if is_multi_domain else "")
                    ),
                )
                evidence_list.append(ev_dns)

                # Early exit if highly confident and no SNI was present
                if (
                    not has_sni
                    and ev_dns.confidence >= 0.90
                    and ev_dns.group not in ("C",)
                ):
                    result = ClassificationResult(
                        app=ev_dns.app,
                        confidence=round(ev_dns.confidence, 4),
                        source="dns",
                        matched_rule=ev_dns.matched_rule,
                        evidence=[e.to_dict() for e in evidence_list if e.app != "unknown"],
                    )
                    self.flow_table.store(flow_key, result, timestamp)
                    return result.to_dict()

        # --- Layer 3: JA3 / JA4 Fingerprints ---
        ja4 = flow_info.get("ja4")
        ja3 = flow_info.get("ja3")
        fp_evidence: Optional[Evidence] = None

        if ja4 and isinstance(ja4, str):
            ja4_clean = ja4.strip().lower()
            if ja4_clean in self.ja4_rules:
                r = self.ja4_rules[ja4_clean]
                fp_conf = min(
                    float(r.get("confidence", 0.5)), self.supplementary_max_confidence
                )
                fp_evidence = Evidence(
                    app=r["app"],
                    confidence=fp_conf,
                    source="ja4",
                    matched_rule=ja4_clean,
                    group=r.get("group"),
                    details=f"JA4 hash: {ja4_clean}",
                )

        if not fp_evidence and ja3 and isinstance(ja3, str):
            ja3_clean = ja3.strip().lower()
            if ja3_clean in self.ja3_rules:
                r = self.ja3_rules[ja3_clean]
                fp_conf = min(
                    float(r.get("confidence", 0.5)), self.supplementary_max_confidence
                )
                fp_evidence = Evidence(
                    app=r["app"],
                    confidence=fp_conf,
                    source="ja3",
                    matched_rule=ja3_clean,
                    group=r.get("group"),
                    details=f"JA3 hash: {ja3_clean}",
                )

        if fp_evidence:
            evidence_list.append(fp_evidence)

        # --- Layer 4: Port + Protocol ---
        # Ports 80 and 443 are generic web transport; port rules skip them
        if dst_port not in (80, 443, 0):
            port_key = (dst_port, proto)
            if port_key in self.port_rules:
                r = self.port_rules[port_key]
                p_conf = min(
                    float(r.get("confidence", 0.5)), self.supplementary_max_confidence
                )
                evidence_list.append(
                    Evidence(
                        app=r["app"],
                        confidence=p_conf,
                        source="port",
                        matched_rule=f"{dst_port}/{proto}",
                        group=r.get("group"),
                        details=f"Port rule {dst_port}/{proto}",
                    )
                )

        # --- Layer 5: IP / ASN ---
        if dst_ip:
            try:
                ip_obj = ipaddress.ip_address(dst_ip)
                for r in self.ip_asn_rules:
                    matched_subnet = False
                    for subnet in r["subnets"]:
                        if ip_obj in subnet:
                            matched_subnet = True
                            break
                    if matched_subnet:
                        ip_conf = min(
                            float(r.get("confidence", 0.4)), self.ip_asn_max_confidence
                        )
                        evidence_list.append(
                            Evidence(
                                app=r["app"],
                                confidence=ip_conf,
                                source="ip_asn",
                                matched_rule=str(r.get("matched_rule")),
                                group="B",
                                details=f"Destination IP {dst_ip} in subnet",
                            )
                        )
                        break
            except ValueError:
                pass

        # Filter out informational placeholders (like 'no_sni_or_ech' with app='unknown')
        valid_evidences = [e for e in evidence_list if e.app != "unknown" and e.confidence > 0.0]

        if not valid_evidences:
            res_unknown = ClassificationResult(
                app="unknown",
                confidence=0.0,
                source="none",
                matched_rule=None,
                evidence=[e.to_dict() for e in evidence_list],
            )
            return res_unknown.to_dict()

        # 3. Combine Evidence
        apps_found = set(e.app for e in valid_evidences)

        if len(apps_found) == 1:
            # All evidence agrees on the same app -> Noisy-OR combination
            winner_app = valid_evidences[0].app
            # Noisy-OR: 1 - prod(1 - c_i)
            combined_conf = 1.0 - math.prod(1.0 - e.confidence for e in valid_evidences)
            final_conf = min(0.99, combined_conf)
            source = "combined" if len(valid_evidences) > 1 else valid_evidences[0].source
            matched_rule = valid_evidences[0].matched_rule
        else:
            # Conflicting evidence across layers -> Layer Priority Resolution
            # Group C domains (shared platforms) yield to specific application evidence from other layers
            non_group_c = [e for e in valid_evidences if e.group != "C"]
            candidates = non_group_c if non_group_c else valid_evidences
            # Lower priority integer = higher precedence (SNI=1, DNS=2, JA3/4=3, Port=4, IP=5)
            candidates.sort(key=lambda e: LAYER_PRIORITY.get(e.source, 99))
            winner_evidence = candidates[0]
            winner_app = winner_evidence.app
            source = winner_evidence.source
            matched_rule = winner_evidence.matched_rule

            # Mark conflict and penalize confidence: reduce by conflict_penalty (e.g. * 0.8)
            for e in valid_evidences:
                e.conflict = True

            final_conf = winner_evidence.confidence * (1.0 - self.conflict_penalty)

        # Check minimum confidence threshold
        if final_conf < self.min_confidence:
            res_low_conf = ClassificationResult(
                app="unknown",
                confidence=round(final_conf, 4),
                source="none",
                matched_rule=None,
                evidence=[e.to_dict() for e in evidence_list],
            )
            return res_low_conf.to_dict()

        result = ClassificationResult(
            app=winner_app,
            confidence=round(final_conf, 4),
            source=source,
            matched_rule=matched_rule,
            evidence=[e.to_dict() for e in evidence_list],
        )

        # 4. Store in FlowTable if meets caching threshold
        if src_ip and dst_ip and src_port and dst_port:
            self.flow_table.store(flow_key, result, timestamp)

        return result.to_dict()
