"""Deterministic DNS rule/cache acceptance scenarios (no live network required)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from appid.dns.cache import DNSCache
from appid.dns.domain_rules import ApplicationDomainRules
from appid.dns.identifier import DNSApplicationIdentifier
from appid.dns.models import DNSAnswerRecord, DNSObservation


def observation(domain: str, ip: str, *, client: str = "192.168.1.18", at: float = 100.0, ttl: int = 60):
    return DNSObservation(
        session_id="acceptance-session", packet_index=1, observed_at=at,
        client_ip=client, resolver_ip="192.168.1.1", transaction_id=1,
        query_name=domain, query_type="A", response_code=0,
        answers=(DNSAnswerRecord(domain, "A", ip, ttl),),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=str(ROOT / "config/dns_mapping.yaml"))
    args = parser.parse_args()
    rules = ApplicationDomainRules.from_yaml(args.config)
    cache = DNSCache()
    identifier = DNSApplicationIdentifier(cache, rules)
    failures: list[str] = []
    total_checks = 0

    def check(name: str, condition: bool, detail: str) -> None:
        nonlocal total_checks
        total_checks += 1
        print(f"[{ 'PASS' if condition else 'FAIL' }] {name}: {detail}")
        if not condition:
            failures.append(name)

    representatives = {
        "chatgpt": "chatgpt.com", "facebook": "facebook.com",
        "tiktok": "tiktok.com", "youtube": "youtube.com", "spotify": "spotify.com",
    }
    for app, domain in representatives.items():
        matched = {r.application_id for r in rules.match("www." + domain)}
        check(f"domain-rule/{app}", matched == {app}, f"{domain} -> {sorted(matched)}")

    # Two names for the same app and client may share one IP and remain identifiable.
    cache.update(observation("chatgpt.com", "203.0.113.10"))
    cache.update(observation("chat.openai.com", "203.0.113.10"))
    same = identifier.identify(session_id="acceptance-session", flow_id="same-app",
        client_ip="192.168.1.18", destination_ip="203.0.113.10", timestamp=110)
    check("shared-ip/same-app", same.application_id == "chatgpt",
          f"status={same.status}, app={same.application_id}, domains={same.matched_domains}")

    # Conflicting app candidates on one IP must never be arbitrarily selected.
    cache.update(observation("facebook.com", "203.0.113.20"))
    cache.update(observation("tiktok.com", "203.0.113.20"))
    mixed = identifier.identify(session_id="acceptance-session", flow_id="mixed-apps",
        client_ip="192.168.1.18", destination_ip="203.0.113.20", timestamp=110)
    check("shared-ip/different-apps", mixed.reason_code == "DNS_SHARED_IP_AMBIGUOUS",
          f"reason={mixed.reason_code}, app={mixed.application_id}")

    # The same IP mapping must not leak to another LAN client.
    other_client = identifier.identify(session_id="acceptance-session", flow_id="other-client",
        client_ip="192.168.1.19", destination_ip="203.0.113.10", timestamp=110)
    check("client-isolation", other_client.reason_code == "DNS_CACHE_MISS",
          f"reason={other_client.reason_code}")

    # Expired bindings must not identify a new Flow.
    expired = identifier.identify(session_id="acceptance-session", flow_id="after-ttl",
        client_ip="192.168.1.18", destination_ip="203.0.113.10", timestamp=160)
    check("ttl-expiry", expired.reason_code == "DNS_CACHE_MISS",
          f"reason={expired.reason_code}")

    print("\n" + "=" * 64)
    print(f"DNS ACCEPTANCE SCENARIOS: {total_checks - len(failures)}/{total_checks} passed")
    if failures:
        print("Failed: " + ", ".join(failures))
        return 1
    print("[PASS] Deterministic DNS acceptance scenarios passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
