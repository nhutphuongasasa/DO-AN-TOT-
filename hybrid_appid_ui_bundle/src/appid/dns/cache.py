"""Session- and client-scoped DNS cache with CNAME-chain TTL semantics."""
from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict

from appid.dns.domain_rules import normalize_domain
from appid.dns.models import DNSBinding, DNSCandidate, DNSObservation

logger = logging.getLogger("appid.dns.cache")


class DNSCache:
    def __init__(self, *, max_cname_depth: int = 16) -> None:
        self.max_cname_depth = max_cname_depth
        self._bindings: dict[tuple[str, str, str], list[DNSBinding]] = defaultdict(list)

    def update(self, observation: DNSObservation) -> int:
        if observation.client_ip is None or observation.response_code != 0:
            logger.debug("[DNS][CACHE_SKIP] reason=%s client=%s rcode=%s qname=%s", "DNS_CLIENT_UNKNOWN" if observation.client_ip is None else "DNS_RCODE_NONZERO", observation.client_ip, observation.response_code, observation.query_name)
            return 0
        qname = normalize_domain(observation.query_name)
        cnames: dict[str, tuple[str, int]] = {}
        addresses: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
        for record in observation.answers:
            owner = normalize_domain(record.owner_name)
            if record.ttl_seconds <= 0:
                continue
            if record.record_type == "CNAME":
                target = normalize_domain(record.value)
                previous = cnames.get(owner)
                if previous is not None and previous[0] != target:
                    return 0  # conflicting CNAME targets in one response are not safe to infer
                cnames[owner] = (target, record.ttl_seconds)
            elif record.record_type in {"A", "AAAA"}:
                try:
                    ipaddress.ip_address(record.value)
                except ValueError:
                    continue
                addresses[owner].append((record.value, record.record_type, record.ttl_seconds))
        domain = qname
        chain_domains = [domain]
        chain_ttls: list[int] = []
        seen = {domain}
        for _ in range(self.max_cname_depth):
            link = cnames.get(domain)
            if link is None:
                break
            target, ttl = link
            if target in seen:
                return 0  # CNAME loop: reject inferred chain
            seen.add(target)
            chain_ttls.append(ttl)
            chain_domains.append(target)
            domain = target
        else:
            if domain in cnames:
                return 0
        pending_bindings: dict[tuple[str, str, str], list[DNSBinding]] = defaultdict(list)
        for ip, record_type, addr_ttl in addresses.get(domain, []):
            ttl = min(chain_ttls + [addr_ttl]) if chain_ttls else addr_ttl
            if ttl <= 0:
                continue
            binding = DNSBinding(
                session_id=observation.session_id,
                client_ip=str(ipaddress.ip_address(observation.client_ip)),
                queried_domain=qname,
                resolved_ip=str(ipaddress.ip_address(ip)),
                domain_candidates=tuple(chain_domains),
                record_types=tuple(["CNAME"] * len(chain_ttls) + [record_type]),
                observed_at=observation.observed_at,
                expires_at=observation.observed_at + ttl,
            )
            key = (binding.session_id, binding.client_ip, binding.resolved_ip)
            pending_bindings[key].append(binding)

        created = 0
        for key, bindings in pending_bindings.items():
            # Refresh this QNAME on each resolved IP while preserving other domains
            # sharing the IP and preserving all A/AAAA answers in this response.
            self._bindings[key] = [b for b in self._bindings.get(key, ())
                                   if b.queried_domain != qname]
            self._bindings[key].extend(bindings)
            created += len(bindings)
            for binding in bindings:
                logger.debug("[DNS][CACHE_INSERT] client=%s domain=%s ip=%s record_types=%s expires_at=%.3f ttl=%s", binding.client_ip, binding.queried_domain, binding.resolved_ip, ",".join(binding.record_types), binding.expires_at, int(binding.expires_at - binding.observed_at))
        if created == 0:
            logger.debug("[DNS][CACHE_NO_BINDING] qname=%s answers=%s reason=no-terminal-address-or-valid-chain", qname, len(observation.answers))
        return created

    def lookup(self, *, session_id: str, client_ip: str, destination_ip: str,
               timestamp: float) -> tuple[DNSCandidate, ...]:
        client = str(ipaddress.ip_address(client_ip))
        destination = str(ipaddress.ip_address(destination_ip))
        key = (session_id, client, destination)
        active = [b for b in self._bindings.get(key, ()) if timestamp < b.expires_at]
        if active:
            self._bindings[key] = active
            logger.debug("[DNS][CACHE_HIT] client=%s ip=%s candidates=%s", client, destination, [(b.queried_domain, b.domain_candidates, b.expires_at) for b in active])
        else:
            self._bindings.pop(key, None)
            logger.debug("[DNS][CACHE_MISS] client=%s ip=%s", client, destination)
        return tuple(DNSCandidate(b.queried_domain, b.resolved_ip, b.expires_at, b.record_types, b.domain_candidates)
                     for b in active)
