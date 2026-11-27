"""DNS-first Application identification for an individual Flow."""
from __future__ import annotations

import logging

from appid.dns.cache import DNSCache
from appid.dns.domain_rules import ApplicationDomainRules
from appid.dns.models import DNSIdentification

logger = logging.getLogger("appid.dns.identifier")


class DNSApplicationIdentifier:
    def __init__(self, cache: DNSCache, rules: ApplicationDomainRules) -> None:
        self.cache = cache
        self.rules = rules

    def identify(self, *, session_id: str, flow_id: str, client_ip: str | None,
                 destination_ip: str, timestamp: float) -> DNSIdentification:
        def unresolved(reason: str) -> DNSIdentification:
            return DNSIdentification(session_id, flow_id, "DNS_UNRESOLVED", None, None,
                                     reason, client_ip, destination_ip)
        if client_ip is None:
            logger.debug("[DNS][IDENTIFY] flow=%s status=UNRESOLVED reason=DNS_CLIENT_UNKNOWN destination=%s", flow_id, destination_ip)
            return unresolved("DNS_CLIENT_UNKNOWN")
        candidates = self.cache.lookup(session_id=session_id, client_ip=client_ip,
                                       destination_ip=destination_ip, timestamp=timestamp)
        if not candidates:
            logger.debug("[DNS][IDENTIFY] flow=%s status=UNRESOLVED reason=DNS_CACHE_MISS client=%s destination=%s", flow_id, client_ip, destination_ip)
            return unresolved("DNS_CACHE_MISS")
        matches: dict[str, set[tuple[str, str]]] = {}
        expiry_by_app: dict[str, float] = {}
        for candidate in candidates:
            for domain in candidate.domain_candidates or (candidate.domain,):
                for rule in self.rules.match(domain):
                    matches.setdefault(rule.application_id, set()).add((domain, rule.rule_id))
                    expiry_by_app[rule.application_id] = min(expiry_by_app.get(rule.application_id, candidate.expires_at), candidate.expires_at)
        if not matches:
            logger.debug("[DNS][IDENTIFY] flow=%s status=UNRESOLVED reason=DNS_DOMAIN_UNMAPPED candidates=%s", flow_id, [(c.domain_candidates, c.resolved_ip) for c in candidates])
            return unresolved("DNS_DOMAIN_UNMAPPED")
        if len(matches) > 1:
            logger.info("[DNS][IDENTIFY] flow=%s status=UNRESOLVED reason=DNS_SHARED_IP_AMBIGUOUS apps=%s domains=%s", flow_id, sorted(matches), [(c.domain_candidates, c.resolved_ip) for c in candidates])
            return unresolved("DNS_SHARED_IP_AMBIGUOUS")
        app_id = next(iter(matches))
        domain_rule_pairs = sorted(matches[app_id])
        logger.info("[DNS][IDENTIFY] flow=%s status=IDENTIFIED app=%s client=%s destination=%s domains=%s rules=%s", flow_id, app_id, client_ip, destination_ip, sorted({domain for domain, _ in domain_rule_pairs}), sorted({rule_id for _, rule_id in domain_rule_pairs}))
        return DNSIdentification(
            session_id, flow_id, "DNS_IDENTIFIED", app_id, "dns", "DNS_CLIENT_IP_DOMAIN_MATCH",
            client_ip, destination_ip,
            tuple(sorted({domain for domain, _ in domain_rule_pairs})),
            tuple(sorted({rule_id for _, rule_id in domain_rule_pairs})),
            expiry_by_app[app_id],
        )
