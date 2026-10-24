"""Comprehensive pytest unit tests for the Rule Engine for Encrypted Traffic Classification.

Covers:
    - Domain Matching (Label boundary safety, longest suffix, wildcards, exact match, normalization, exclusions, ignored domains)
    - DNS Cache (Ingest, lookup, expiry, LRU eviction, multi-domain tracking, CNAME chains, cleanup)
    - Flow Table (Fast-path caching, upgrading, reclassification limits, inactivity expiry)
    - Multi-layer RuleEngine (Conflict resolution, Group C fall-through, ECH/no-SNI fallback, Noisy-OR combination, confidence caps)
    - Rule Validation (Schema, confidence bounds, version checking)
    - Integration tests across specific target applications
"""

import ipaddress
import time
from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

from rule_engine import (
    ClassificationResult,
    DnsCache,
    DomainMatcher,
    Evidence,
    FlowTable,
    RuleEngine,
    load_rules,
)


# ==============================================================================
# Pytest Fixtures
# ==============================================================================


@pytest.fixture
def rules_path() -> Path:
    """Path to the default rules.yaml configuration file."""
    path = Path(__file__).parent / "rules.yaml"
    assert path.is_file(), f"rules.yaml not found at {path}"
    return path


@pytest.fixture
def engine(rules_path: Path) -> RuleEngine:
    """Fixture providing a fresh RuleEngine initialized with rules.yaml."""
    return RuleEngine(rules_path)


@pytest.fixture
def domain_matcher(rules_path: Path) -> DomainMatcher:
    """Fixture providing an isolated DomainMatcher initialized with rules.yaml."""
    rules_data = load_rules(rules_path)
    return DomainMatcher(
        domain_rules=rules_data.get("domain_rules", []),
        ignored_domains=rules_data.get("ignored_domains", []),
    )


@pytest.fixture
def dns_cache() -> DnsCache:
    """Fixture providing a clean DnsCache instance."""
    return DnsCache(
        max_entries=50000,
        min_ttl=10.0,
        max_ttl=86400.0,
        default_ttl=300.0,
    )


@pytest.fixture
def flow_table() -> FlowTable:
    """Fixture providing a clean FlowTable instance."""
    return FlowTable(
        max_entries=100000,
        flow_ttl=120.0,
        cache_threshold=0.8,
        flow_reclassify_packets=5,
    )


# ==============================================================================
# 1. DomainMatcher Tests
# ==============================================================================


class TestDomainMatcher:
    """Unit tests for DomainMatcher reversed-label trie."""

    # --- 1. Label Boundary Safety ---

    def test_suffix_spoof_youtube_com_evil_com(self, domain_matcher: DomainMatcher) -> None:
        """youtube.com.evil.com must NOT match youtube.com rule."""
        assert domain_matcher.match("youtube.com.evil.com") is None

    def test_suffix_spoof_notyoutube_com(self, domain_matcher: DomainMatcher) -> None:
        """notyoutube.com must NOT match youtube.com rule."""
        assert domain_matcher.match("notyoutube.com") is None

    def test_suffix_spoof_microsoft_co_vs_t_co(self, domain_matcher: DomainMatcher) -> None:
        """microsoft.co must NOT match t.co rule."""
        assert domain_matcher.match("microsoft.co") is None

    # --- 2. Longest Suffix Match ---

    def test_longest_suffix_meet_google_com(self, domain_matcher: DomainMatcher) -> None:
        """meet.google.com should match 'meet' app, not 'generic_google'."""
        match = domain_matcher.match("meet.google.com")
        assert match is not None
        assert match["app"] == "meet"
        assert match["app"] != "generic_google"

    def test_longest_suffix_gemini_google_com(self, domain_matcher: DomainMatcher) -> None:
        """gemini.google.com should match 'gemini' app."""
        match = domain_matcher.match("gemini.google.com")
        assert match is not None
        assert match["app"] == "gemini"

    def test_google_com_alone_is_group_c(self, domain_matcher: DomainMatcher) -> None:
        """google.com alone should return generic_google with low confidence."""
        match = domain_matcher.match("google.com")
        assert match is not None
        assert match["app"] == "generic_google"
        assert match["group"] == "C"
        assert match["confidence"] <= 0.30

    # --- 3. Wildcard Rules ---

    def test_wildcard_subdomain_matches(self, domain_matcher: DomainMatcher) -> None:
        """rr1.googlevideo.com should match *.googlevideo.com or googlevideo.com rule."""
        match = domain_matcher.match("rr1.googlevideo.com")
        assert match is not None
        assert match["app"] == "youtube"

    def test_wildcard_bare_domain(self) -> None:
        """If rule is *.example.com, bare example.com should NOT match the wildcard."""
        custom_matcher = DomainMatcher(
            [{"app": "test_app", "domains": ["*.example.com"], "confidence": 0.9}]
        )
        assert custom_matcher.match("example.com") is None
        sub_match = custom_matcher.match("sub.example.com")
        assert sub_match is not None
        assert sub_match["app"] == "test_app"

    def test_regular_rule_matches_both(self, domain_matcher: DomainMatcher) -> None:
        """Regular rule googlevideo.com matches both googlevideo.com and rr1.googlevideo.com."""
        bare = domain_matcher.match("googlevideo.com")
        sub = domain_matcher.match("rr1.googlevideo.com")
        assert bare is not None and bare["app"] == "youtube"
        assert sub is not None and sub["app"] == "youtube"

    # --- 4. Domain Normalization (Matcher Level) ---

    def test_uppercase_domain(self, domain_matcher: DomainMatcher) -> None:
        """YOUTUBE.COM should match youtube.com rule."""
        match = domain_matcher.match("YOUTUBE.COM")
        assert match is not None
        assert match["app"] == "youtube"

    def test_trailing_dot(self, domain_matcher: DomainMatcher) -> None:
        """youtube.com. should match youtube.com rule."""
        match = domain_matcher.match("youtube.com.")
        assert match is not None
        assert match["app"] == "youtube"

    # --- 13. Exclude Domains ---

    def test_excluded_domain_not_matched(self, domain_matcher: DomainMatcher) -> None:
        """pixel.facebook.com should be excluded from facebook rule."""
        assert domain_matcher.match("pixel.facebook.com") is None
        assert domain_matcher.match("connect.facebook.net") is None

    def test_non_excluded_subdomain_matches(self, domain_matcher: DomainMatcher) -> None:
        """www.facebook.com should still match facebook rule."""
        match = domain_matcher.match("www.facebook.com")
        assert match is not None
        assert match["app"] == "facebook"

    # --- 14. Ignored Domains ---

    def test_ignored_domain_no_evidence(
        self, domain_matcher: DomainMatcher, engine: RuleEngine
    ) -> None:
        """cloudflare.com, akamai.net etc should produce no evidence."""
        assert domain_matcher.match("cloudflare.com") is None
        assert domain_matcher.match("sub.cloudflare.com") is None
        assert domain_matcher.match("akamai.net") is None
        assert domain_matcher.match("sub.akamai.net") is None

        # Verify through RuleEngine classification
        res = engine.classify({"sni": "cloudflare.com"})
        assert res["app"] == "unknown"

    # --- 15. Exact Match Syntax ---

    def test_exact_match_gemini(self, domain_matcher: DomainMatcher) -> None:
        """=gemini.google.com should match gemini.google.com exactly."""
        match = domain_matcher.match("gemini.google.com")
        assert match is not None
        assert match["app"] == "gemini"

    def test_exact_match_subdomain_no_match(self, domain_matcher: DomainMatcher) -> None:
        """=gemini.google.com should NOT match sub.gemini.google.com."""
        match = domain_matcher.match("sub.gemini.google.com")
        # sub.gemini.google.com falls back to google.com (generic_google) and not gemini
        assert match is None or match["app"] != "gemini"


# ==============================================================================
# 2. DnsCache Tests
# ==============================================================================


class TestDnsCache:
    """Unit tests for DnsCache TTL handling and IP correlation."""

    def test_dns_lookup_basic(self, dns_cache: DnsCache) -> None:
        """Basic DNS ingest and lookup."""
        client_ip = "192.168.1.50"
        dest_ip = "93.184.216.34"
        query_name = "example.com"

        dns_cache.ingest_dns_response(
            client_ip=client_ip,
            query_name=query_name,
            answers=[dest_ip],
            cnames=[],
            ttl=300.0,
            timestamp=1000.0,
        )

        entry = dns_cache.lookup(client_ip, dest_ip, timestamp=1050.0)
        assert entry is not None
        assert entry["domain"] == query_name
        assert entry["cname_chain"] == []
        assert entry["multi_domain"] is False

    def test_dns_expired(self, dns_cache: DnsCache) -> None:
        """DNS entry past TTL should not be returned."""
        client_ip = "192.168.1.50"
        dest_ip = "93.184.216.34"

        dns_cache.ingest_dns_response(
            client_ip=client_ip,
            query_name="example.com",
            answers=[dest_ip],
            ttl=25.0,
            timestamp=1000.0,
        )

        # Before expiration
        assert dns_cache.lookup(client_ip, dest_ip, timestamp=1020.0) is not None
        # Past expiration (timestamp > 1000.0 + 25.0)
        assert dns_cache.lookup(client_ip, dest_ip, timestamp=1030.0) is None

    def test_dns_cache_full_lru(self) -> None:
        """When cache is full, oldest entries should be evicted."""
        small_cache = DnsCache(max_entries=5)

        for i in range(5):
            small_cache.ingest_dns_response(
                client_ip="10.0.0.1",
                query_name=f"domain{i}.com",
                answers=[f"1.1.1.{i}"],
                timestamp=1000.0,
            )

        # Refresh entry 0 to top of LRU
        refreshed = small_cache.lookup("10.0.0.1", "1.1.1.0", timestamp=1000.0)
        assert refreshed is not None

        # Add 6th entry: oldest unaccessed entry (domain1) must be evicted
        small_cache.ingest_dns_response(
            client_ip="10.0.0.1",
            query_name="domain5.com",
            answers=["1.1.1.5"],
            timestamp=1000.0,
        )

        assert small_cache.lookup("10.0.0.1", "1.1.1.1", timestamp=1000.0) is None
        assert small_cache.lookup("10.0.0.1", "1.1.1.0", timestamp=1000.0) is not None
        assert small_cache.lookup("10.0.0.1", "1.1.1.5", timestamp=1000.0) is not None

    def test_dns_multi_domain_same_ip(self, dns_cache: DnsCache) -> None:
        """When dest_ip maps to multiple domains from different apps, multi_domain should be True."""
        client_ip = "192.168.1.100"
        shared_ip = "104.16.123.96"

        dns_cache.ingest_dns_response(
            client_ip=client_ip,
            query_name="app1.com",
            answers=[shared_ip],
            timestamp=1000.0,
        )
        entry1 = dns_cache.lookup(client_ip, shared_ip, timestamp=1000.0)
        assert entry1 is not None
        assert entry1["multi_domain"] is False

        dns_cache.ingest_dns_response(
            client_ip=client_ip,
            query_name="app2.com",
            answers=[shared_ip],
            timestamp=1001.0,
        )
        entry2 = dns_cache.lookup(client_ip, shared_ip, timestamp=1001.0)
        assert entry2 is not None
        assert entry2["multi_domain"] is True

    def test_dns_cname_chain(self, dns_cache: DnsCache) -> None:
        """CNAME chain should be stored and used for correlation."""
        client_ip = "192.168.1.100"
        dest_ip = "151.101.1.140"
        cnames = ["cname1.reddit.com", "cname2.reddit.map.fastly.net"]

        dns_cache.ingest_dns_response(
            client_ip=client_ip,
            query_name="reddit.com",
            answers=[dest_ip],
            cnames=cnames,
            timestamp=1000.0,
        )

        entry = dns_cache.lookup(client_ip, dest_ip, timestamp=1000.0)
        assert entry is not None
        assert entry["cname_chain"] == cnames

    def test_dns_cleanup_expired(self, dns_cache: DnsCache) -> None:
        """cleanup_expired should remove only expired entries."""
        dns_cache.ingest_dns_response(
            client_ip="10.0.0.1",
            query_name="exp.com",
            answers=["1.1.1.1"],
            ttl=20.0,
            timestamp=1000.0,
        )
        dns_cache.ingest_dns_response(
            client_ip="10.0.0.1",
            query_name="valid.com",
            answers=["2.2.2.2"],
            ttl=500.0,
            timestamp=1000.0,
        )

        evicted = dns_cache.cleanup_expired(timestamp=1050.0)
        assert evicted == 1
        assert dns_cache.lookup("10.0.0.1", "1.1.1.1", timestamp=1050.0) is None
        assert dns_cache.lookup("10.0.0.1", "2.2.2.2", timestamp=1050.0) is not None


# ==============================================================================
# 3. FlowTable Tests
# ==============================================================================


class TestFlowTable:
    """Unit tests for FlowTable caching, upgrade, and expiry."""

    def test_flow_table_fast_path(self, flow_table: FlowTable) -> None:
        """Second classify of same flow should hit flow table cache."""
        now = time.time()
        flow_key = ("192.168.1.10", 45000, "142.250.190.46", 443, "tcp")
        result = ClassificationResult(
            app="youtube",
            confidence=0.95,
            source="sni",
            matched_rule="googlevideo.com",
        )

        flow_table.store(flow_key, result, timestamp=now)
        cached = flow_table.lookup(flow_key, timestamp=now + 5.0)

        assert cached is not None
        assert cached.app == "youtube"
        assert cached.confidence == 0.95

    def test_flow_table_upgrade(self, flow_table: FlowTable) -> None:
        """If stronger evidence arrives, flow table entry should be upgraded."""
        now = time.time()
        flow_key = ("192.168.1.10", 45000, "142.250.190.46", 443, "tcp")
        initial_result = ClassificationResult(
            app="youtube",
            confidence=0.82,
            source="dns",
        )
        flow_table.store(flow_key, initial_result, timestamp=now)

        # Propose higher confidence result
        upgraded_result = ClassificationResult(
            app="youtube",
            confidence=0.96,
            source="sni",
        )
        flow_table.upgrade(flow_key, upgraded_result, timestamp=now + 5.0)
        cached_upgraded = flow_table.lookup(flow_key, timestamp=now + 6.0)
        assert cached_upgraded is not None
        assert cached_upgraded.confidence == 0.96

        # Propose lower confidence result -> should NOT downgrade
        weaker_result = ClassificationResult(
            app="youtube",
            confidence=0.75,
            source="port",
        )
        flow_table.upgrade(flow_key, weaker_result, timestamp=now + 10.0)
        cached_kept = flow_table.lookup(flow_key, timestamp=now + 11.0)
        assert cached_kept is not None
        assert cached_kept.confidence == 0.96

    def test_flow_table_reclassify_packets(self, flow_table: FlowTable) -> None:
        """First N packets of a flow should allow reclassification."""
        flow_key = ("192.168.1.10", 45000, "142.250.190.46", 443, "tcp")
        res = ClassificationResult(app="youtube", confidence=0.9, source="sni")
        flow_table.store(flow_key, res)  # packet_count = 1

        # flow_reclassify_packets is 5
        assert flow_table.should_reclassify(flow_key) is True   # count 2
        assert flow_table.should_reclassify(flow_key) is True   # count 3
        assert flow_table.should_reclassify(flow_key) is True   # count 4
        assert flow_table.should_reclassify(flow_key) is True   # count 5
        assert flow_table.should_reclassify(flow_key) is False  # count 6 (> 5)

    def test_flow_table_expiry(self, flow_table: FlowTable) -> None:
        """Expired flow entries should not be returned."""
        now = time.time()
        flow_key = ("192.168.1.10", 45000, "142.250.190.46", 443, "tcp")
        res = ClassificationResult(app="youtube", confidence=0.9, source="sni")

        flow_table.store(flow_key, res, timestamp=now)
        # Still active at now + 50s
        assert flow_table.lookup(flow_key, timestamp=now + 50.0) is not None
        # Default flow_ttl is 120s; lookup at now + 180s (> 50s + 120s) must expire
        assert flow_table.lookup(flow_key, timestamp=now + 180.0) is None

    def test_unknown_not_cached_in_flow_table(self, flow_table: FlowTable) -> None:
        """Unknown results should not be cached in flow table."""
        flow_key = ("192.168.1.10", 45000, "142.250.190.46", 443, "tcp")
        unknown_res = ClassificationResult(
            app="unknown",
            confidence=0.0,
            source="none",
        )
        flow_table.store(flow_key, unknown_res)
        assert flow_table.lookup(flow_key) is None


# ==============================================================================
# 4. RuleEngine Multi-Layer & Policy Tests
# ==============================================================================


class TestRuleEngine:
    """Unit tests for the orchestrating RuleEngine."""

    # --- 4. Domain Normalization (Engine Level) ---

    def test_empty_sni(self, engine: RuleEngine) -> None:
        """Empty SNI should return unknown."""
        res = engine.classify({"sni": ""})
        assert res["app"] == "unknown"
        assert res["source"] in ("none", "sni")

    def test_sni_is_ip_literal(self, engine: RuleEngine) -> None:
        """SNI = '1.2.3.4' should return unknown (not a domain)."""
        res = engine.classify({"sni": "1.2.3.4"})
        assert res["app"] == "unknown"

    def test_sni_is_ipv6_literal(self, engine: RuleEngine) -> None:
        """SNI = '::1' or '[::1]' should return unknown."""
        assert engine.classify({"sni": "::1"})["app"] == "unknown"
        assert engine.classify({"sni": "[::1]"})["app"] == "unknown"

    # --- 5. Group C Fall-Through with DNS ---

    def test_sni_group_c_plus_dns_youtube(self, engine: RuleEngine) -> None:
        """SNI = google.com (group C) + DNS points to youtube.com -> result should be youtube."""
        client_ip = "192.168.1.100"
        dest_ip = "142.250.190.46"

        engine.ingest_dns_response(
            client_ip=client_ip,
            query_name="youtube.com",
            answers=[dest_ip],
            ttl=300.0,
        )

        result = engine.classify(
            {
                "sni": "google.com",
                "client_ip": client_ip,
                "dest_ip": dest_ip,
                "src_port": 54321,
                "dst_port": 443,
                "protocol": "tcp",
            }
        )

        assert result["app"] == "youtube"
        assert result["app"] != "generic_google"
        assert result["source"] == "dns"
        assert result["confidence"] >= 0.50

    # --- 7. Conflict Resolution ---

    def test_conflict_sni_vs_dns(self, engine: RuleEngine) -> None:
        """When SNI says app A and DNS says app B, SNI (higher priority) should win with reduced confidence."""
        res = engine.classify(
            {
                "sni": "facebook.com",
                "dns_domain": "youtube.com",
                "src_ip": "10.0.0.1",
                "src_port": 1234,
                "dst_ip": "1.2.3.4",
                "dst_port": 443,
            }
        )
        assert res["app"] == "facebook"
        assert res["source"] == "sni"
        assert any(e.get("conflict") is True for e in res["evidence"])
        # facebook confidence 0.75 * (1 - 0.2 penalty) = 0.60
        assert res["confidence"] == pytest.approx(0.60, rel=1e-3)

    # --- 8. ECH / No SNI ---

    def test_no_sni_no_dns_is_unknown(self, engine: RuleEngine) -> None:
        """Flow with no SNI (ECH) and no DNS correlation should be unknown."""
        res = engine.classify(
            {
                "src_ip": "10.0.0.1",
                "src_port": 1234,
                "dst_ip": "192.0.2.1",
                "dst_port": 443,
                "protocol": "tcp",
            }
        )
        assert res["app"] == "unknown"
        assert res["confidence"] < engine.min_confidence

    def test_no_sni_with_dns_correlation(self, engine: RuleEngine) -> None:
        """Flow with no SNI but DNS correlation should use DNS result."""
        client_ip = "192.168.1.50"
        dest_ip = "104.18.0.1"
        engine.ingest_dns_response(
            client_ip=client_ip,
            query_name="chatgpt.com",
            answers=[dest_ip],
        )

        res = engine.classify(
            {
                "sni": None,
                "client_ip": client_ip,
                "dest_ip": dest_ip,
                "src_port": 50000,
                "dst_port": 443,
            }
        )
        assert res["app"] == "chatgpt"
        assert res["source"] == "dns"
        assert res["confidence"] >= 0.8

    # --- 9. Confidence Thresholds ---

    def test_below_min_confidence_is_unknown(self, engine: RuleEngine) -> None:
        """Result below min_confidence threshold should return unknown."""
        # google.com alone has confidence 0.10, which is below min_confidence (0.50)
        res = engine.classify({"sni": "google.com"})
        assert res["app"] == "unknown"
        assert res["confidence"] < engine.min_confidence

    # --- 11. Noisy-OR Combination ---

    def test_noisy_or_same_app(self, engine: RuleEngine) -> None:
        """Multiple evidence for same app should combine via noisy-OR."""
        # facebook.com rule has group B- (0.75 confidence, avoids early exit)
        engine.ingest_dns_response("192.168.1.5", "facebook.com", ["157.240.1.35"])

        res = engine.classify(
            {
                "sni": "facebook.com",
                "client_ip": "192.168.1.5",
                "dest_ip": "157.240.1.35",
                "src_port": 1234,
                "dst_port": 443,
            }
        )

        assert res["app"] == "facebook"
        assert res["source"] == "combined"
        # Noisy-OR: 1 - (1 - 0.75) * (1 - 0.75 * 0.9) = 1 - 0.25 * 0.325 = 0.91875
        assert res["confidence"] > 0.75
        assert res["confidence"] == pytest.approx(0.9187, abs=1e-3)

    def test_noisy_or_capped_at_099(self, engine: RuleEngine) -> None:
        """Combined confidence should never exceed 0.99."""
        engine.ingest_dns_response("192.168.1.5", "facebook.com", ["157.240.1.35"])
        engine.ja3_rules["fb_ja3"] = {"app": "facebook", "confidence": 0.6}
        engine.port_rules[(8444, "tcp")] = {"app": "facebook", "confidence": 0.6}

        res = engine.classify(
            {
                "sni": "facebook.com",
                "client_ip": "192.168.1.5",
                "dest_ip": "157.240.1.35",
                "src_port": 1234,
                "dst_port": 8444,
                "protocol": "tcp",
                "ja3": "fb_ja3",
            }
        )

        assert res["app"] == "facebook"
        assert res["confidence"] <= 0.99

    # --- 12. Supplementary Layer Caps ---

    def test_ja3_alone_capped(self, engine: RuleEngine) -> None:
        """JA3 alone should have confidence capped at supplementary_max_confidence."""
        engine.ja3_rules["test_capped_ja3"] = {"app": "test_app", "confidence": 0.95}
        res = engine.classify({"ja3": "test_capped_ja3"})

        assert res["confidence"] <= engine.supplementary_max_confidence
        for ev in res["evidence"]:
            if ev["source"] == "ja3":
                assert ev["confidence"] <= engine.supplementary_max_confidence

    def test_port_alone_capped(self, engine: RuleEngine) -> None:
        """Port alone should have confidence capped at supplementary_max_confidence."""
        engine.port_rules[(7777, "udp")] = {
            "app": "custom_port_app",
            "confidence": 0.95,
        }
        res = engine.classify({"port": 7777, "protocol": "udp"})

        assert res["confidence"] <= engine.supplementary_max_confidence
        for ev in res["evidence"]:
            if ev["source"] == "port":
                assert ev["confidence"] <= engine.supplementary_max_confidence

    def test_ip_asn_alone_capped(self, engine: RuleEngine) -> None:
        """IP/ASN alone should have confidence capped at ip_asn_max_confidence."""
        engine.ip_asn_rules.append(
            {
                "app": "custom_ip_app",
                "confidence": 0.95,
                "subnets": [ipaddress.ip_network("198.51.100.0/24")],
                "asns": [],
                "matched_rule": "custom_cidr",
            }
        )
        res = engine.classify({"dest_ip": "198.51.100.25"})

        assert res["confidence"] <= engine.ip_asn_max_confidence
        for ev in res["evidence"]:
            if ev["source"] == "ip_asn":
                assert ev["confidence"] <= engine.ip_asn_max_confidence

    # --- 17. Rule Validation ---

    def test_invalid_confidence_raises(self) -> None:
        """Confidence outside [0,1] should raise ValueError."""
        with pytest.raises(ValueError, match="confidence"):
            DomainMatcher(
                [{"app": "invalid_app", "domains": ["example.com"], "confidence": 1.5}]
            )

        with pytest.raises(ValueError, match="confidence"):
            DomainMatcher(
                [{"app": "invalid_app", "domains": ["example.com"], "confidence": -0.2}]
            )

    def test_missing_version_raises(self, tmp_path: Path) -> None:
        """Missing version field should raise ValueError."""
        bad_yaml = tmp_path / "missing_version.yaml"
        bad_yaml.write_text("domain_rules: []\n", encoding="utf-8")

        with pytest.raises(ValueError, match="version"):
            RuleEngine(bad_yaml)


# ==============================================================================
# 5. Integration: Specific Application Classification
# ==============================================================================


class TestIntegration:
    """Integration tests classifying specific major consumer applications."""

    def test_classify_youtube_sni(self, engine: RuleEngine) -> None:
        """SNI=youtube.com should return youtube with high confidence."""
        res = engine.classify({"sni": "youtube.com"})
        assert res["app"] == "youtube"
        assert res["confidence"] >= 0.90
        assert res["source"] == "sni"

    def test_classify_tiktok_cdn(self, engine: RuleEngine) -> None:
        """SNI=tiktokcdn.com should return tiktok."""
        res = engine.classify({"sni": "tiktokcdn.com"})
        assert res["app"] == "tiktok"
        assert res["confidence"] >= 0.90

    def test_classify_chatgpt(self, engine: RuleEngine) -> None:
        """SNI=chatgpt.com should return chatgpt."""
        res = engine.classify({"sni": "chatgpt.com"})
        assert res["app"] == "chatgpt"
        assert res["confidence"] >= 0.90

    def test_classify_netflix(self, engine: RuleEngine) -> None:
        """SNI=nflxvideo.net should return netflix."""
        res = engine.classify({"sni": "nflxvideo.net"})
        assert res["app"] == "netflix"
        assert res["confidence"] >= 0.90

    def test_classify_discord(self, engine: RuleEngine) -> None:
        """SNI=discord.com should return discord."""
        res = engine.classify({"sni": "discord.com"})
        assert res["app"] == "discord"
        assert res["confidence"] >= 0.90

    def test_classify_zalo(self, engine: RuleEngine) -> None:
        """SNI=zaloapp.com should return zalo."""
        res = engine.classify({"sni": "zaloapp.com"})
        assert res["app"] == "zalo"
        assert res["confidence"] >= 0.90
