#!/usr/bin/env python3
"""Demonstration script for Encrypted Traffic Classification Rule Engine.

This script demonstrates the end-to-end functionality of RuleEngine:
1. Loading configuration and rule sets from YAML.
2. Ingesting DNS queries/responses to build client-to-IP resolution caches.
3. Classifying diverse network flows (SNI matching, CDN domains, ECH fallback,
   Group C shared infrastructure, spoofed domains, exclusions, fast-path caching).
4. Formatting individual classification decisions and printing a summary table.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from rule_engine import RuleEngine


def print_banner() -> None:
    """Print the main banner for the demo script."""
    banner = """
╔══════════════════════════════════════════════════════════╗
║     Encrypted Traffic Classification - Rule Engine      ║
║                    Demo / Example                       ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner.strip())


def print_section(title: str) -> None:
    """Print a section header with clean visual formatting."""
    print(f"\n┌{'─' * 58}┐")
    print(f"│  {title:<56}│")
    print(f"└{'─' * 58}┘")


def print_result(label: str, result: Dict[str, Any]) -> None:
    """Pretty print classification result and gathered layer evidence.

    Args:
        label: Descriptive scenario title.
        result: Classification outcome dictionary from RuleEngine.classify().
    """
    print(f"\n{'=' * 60}")
    print(f"  {label}")
    print(f"{'=' * 60}")
    print(f"  App:        {result['app']}")
    print(f"  Confidence: {result['confidence']:.4f}")
    print(f"  Source:     {result['source']}")
    print(f"  Rule:       {result['matched_rule'] or 'None'}")
    if result.get("evidence"):
        print("  Evidence:")
        for e in result["evidence"]:
            app_str = e.get("app", "unknown")
            conf_str = f"{e.get('confidence', 0.0):.4f}"
            src_str = e.get("source", "unknown")
            details = f" ({e['details']})" if e.get("details") else ""
            conflict = " [CONFLICT]" if e.get("conflict") else ""
            print(f"    - [{src_str}] {app_str} (conf={conf_str}){details}{conflict}")
    print()


def make_flow(
    sni: Optional[str] = None,
    client_ip: str = "192.168.1.100",
    dest_ip: str = "142.250.190.46",
    src_port: int = 54321,
    dst_port: int = 443,
    protocol: str = "tcp",
    timestamp: Optional[float] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Helper to generate a realistic flow_info dictionary with standard defaults."""
    now = time.time() if timestamp is None else timestamp
    flow = {
        "sni": sni,
        "client_ip": client_ip,
        "dest_ip": dest_ip,
        "src_ip": client_ip,
        "dst_ip": dest_ip,
        "src_port": src_port,
        "port": dst_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "transport": protocol,
        "timestamp": now,
    }
    flow.update(kwargs)
    return flow


def print_summary_table(scenarios: List[Dict[str, Any]]) -> None:
    """Print an ASCII summary table for all evaluated classification scenarios."""
    print("\n" + "=" * 90)
    print("  CLASSIFICATION SCENARIO SUMMARY TABLE")
    print("=" * 90)

    header = (
        f"{'#':<3} | {'Scenario':<34} | {'App':<14} | {'Conf':<6} | "
        f"{'Source':<8} | {'Rule':<16}"
    )
    separator = "-" * 90
    print(header)
    print(separator)

    for idx, item in enumerate(scenarios, start=1):
        res = item["result"]
        label = item["label"]
        app = str(res.get("app", "unknown"))
        conf = f"{float(res.get('confidence', 0.0)):.2f}"
        source = str(res.get("source", "none"))
        rule = str(res.get("matched_rule") or "-")
        if len(label) > 34:
            label = label[:31] + "..."
        if len(rule) > 16:
            rule = rule[:13] + "..."

        print(f"{idx:<3} | {label:<34} | {app:<14} | {conf:<6} | {source:<8} | {rule:<16}")

    print(separator)
    print(f"Total Scenarios Evaluated: {len(scenarios)}\n")


def main() -> None:
    """Run all demonstration scenarios."""
    print_banner()

    # --------------------------------------------------------------------------
    # 1. Loading the Rule Engine
    # --------------------------------------------------------------------------
    print_section("1. Loading Rule Engine Configuration")
    rules_file = "rules.yaml"
    print(f"Loading rules configuration from: {rules_file} ...")
    start_load = time.perf_counter()
    engine = RuleEngine(rules_file)
    load_time_ms = (time.perf_counter() - start_load) * 1000
    print(f"Engine successfully initialized in {load_time_ms:.2f} ms")
    print(f" - Domain trie rules loaded")
    print(f" - DNS Cache capacity: {engine.dns_cache._max_entries:,} entries")
    print(f" - Flow Table capacity: {engine.flow_table._max_entries:,} entries")
    print(f" - Settings: min_conf={engine.min_confidence}, cache_threshold={engine.flow_table._cache_threshold}")

    # --------------------------------------------------------------------------
    # 2. Ingesting DNS Responses
    # --------------------------------------------------------------------------
    print_section("2. Ingesting DNS Responses into DnsCache")
    base_time = time.time()

    dns_events = [
        {
            "service": "YouTube",
            "client_ip": "192.168.1.100",
            "query_name": "youtube.com",
            "answers": ["142.250.190.46", "142.250.190.47"],
            "cnames": ["youtube-ui.l.google.com"],
            "ttl": 300.0,
        },
        {
            "service": "TikTok",
            "client_ip": "192.168.1.100",
            "query_name": "tiktok.com",
            "answers": ["104.18.20.30"],
            "cnames": ["tiktok.cdn.cloudflare.net"],
            "ttl": 120.0,
        },
        {
            "service": "ChatGPT",
            "client_ip": "192.168.1.100",
            "query_name": "chatgpt.com",
            "answers": ["104.18.10.20"],
            "cnames": ["chatgpt.cloudflare.com"],
            "ttl": 120.0,
        },
        {
            "service": "Netflix",
            "client_ip": "192.168.1.100",
            "query_name": "nflxvideo.net",
            "answers": ["45.57.20.10"],
            "cnames": ["dualstack.nflxvideo.net"],
            "ttl": 3600.0,
        },
        {
            "service": "Generic Google",
            "client_ip": "192.168.1.100",
            "query_name": "google.com",
            "answers": ["172.217.16.206"],
            "cnames": [],
            "ttl": 300.0,
        },
    ]

    for event in dns_events:
        engine.ingest_dns_response(
            client_ip=event["client_ip"],
            query_name=event["query_name"],
            answers=event["answers"],
            cnames=event["cnames"],
            ttl=event["ttl"],
            timestamp=base_time,
        )
        print(
            f" [DNS INGEST] {event['service']:<15} | Client: {event['client_ip']} "
            f"| Query: {event['query_name']:<15} -> IPs: {event['answers']} "
            f"| CNAMEs: {event['cnames'] or 'None'}"
        )

    # --------------------------------------------------------------------------
    # 3. Classification Scenarios
    # --------------------------------------------------------------------------
    print_section("3. Executing Classification Scenarios")
    results_summary: List[Dict[str, Any]] = []

    # Scenario a: YouTube via SNI (Group B, high confidence)
    flow_a = make_flow(
        sni="www.youtube.com",
        client_ip="192.168.1.100",
        dest_ip="142.250.190.46",
        src_port=50001,
        dst_port=443,
    )
    res_a = engine.classify(flow_a)
    print_result("a. YouTube via SNI (Group B, high confidence)", res_a)
    results_summary.append({"label": "a. YouTube via SNI (Group B)", "result": res_a})

    # Scenario b: YouTube via CDN SNI (Group A, very high confidence)
    flow_b = make_flow(
        sni="rr1.googlevideo.com",
        client_ip="192.168.1.100",
        dest_ip="173.194.55.10",
        src_port=50002,
        dst_port=443,
    )
    res_b = engine.classify(flow_b)
    print_result("b. YouTube via CDN SNI (Group A, very high confidence)", res_b)
    results_summary.append({"label": "b. YouTube via CDN SNI (Group A)", "result": res_b})

    # Scenario c: TikTok via SNI
    flow_c = make_flow(
        sni="tiktok.com",
        client_ip="192.168.1.100",
        dest_ip="104.18.20.30",
        src_port=50003,
        dst_port=443,
    )
    res_c = engine.classify(flow_c)
    print_result("c. TikTok via SNI", res_c)
    results_summary.append({"label": "c. TikTok via SNI", "result": res_c})

    # Scenario d: ChatGPT via SNI
    flow_d = make_flow(
        sni="chatgpt.com",
        client_ip="192.168.1.100",
        dest_ip="104.18.10.20",
        src_port=50004,
        dst_port=443,
    )
    res_d = engine.classify(flow_d)
    print_result("d. ChatGPT via SNI", res_d)
    results_summary.append({"label": "d. ChatGPT via SNI", "result": res_d})

    # Scenario e: Netflix via CDN
    flow_e = make_flow(
        sni="assets.nflxvideo.net",
        client_ip="192.168.1.100",
        dest_ip="45.57.20.10",
        src_port=50005,
        dst_port=443,
    )
    res_e = engine.classify(flow_e)
    print_result("e. Netflix via CDN SNI (Group A)", res_e)
    results_summary.append({"label": "e. Netflix via CDN", "result": res_e})

    # Scenario f: No SNI (ECH) but DNS correlation available
    # Flow without SNI, but client 192.168.1.100 -> dest 142.250.190.46 matched in DNS cache
    flow_f = make_flow(
        sni=None,
        client_ip="192.168.1.100",
        dest_ip="142.250.190.46",
        src_port=50006,
        dst_port=443,
    )
    res_f = engine.classify(flow_f)
    print_result("f. No SNI (ECH) with DNS Correlation to YouTube", res_f)
    results_summary.append({"label": "f. No SNI (ECH) + DNS Correlation", "result": res_f})

    # Scenario g: Group C domain (google.com) - should be low confidence
    flow_g = make_flow(
        sni="google.com",
        client_ip="192.168.1.100",
        dest_ip="172.217.16.206",
        src_port=50007,
        dst_port=443,
    )
    res_g = engine.classify(flow_g)
    print_result("g. Group C Domain (google.com - below min confidence threshold)", res_g)
    results_summary.append({"label": "g. Group C domain (google.com)", "result": res_g})

    # Scenario h: Group C + DNS supplementary evidence
    # Flow with SNI=google.com (Group C), but dest_ip mapped by DNS cache to youtube.com
    flow_h = make_flow(
        sni="google.com",
        client_ip="192.168.1.100",
        dest_ip="142.250.190.46",
        src_port=50008,
        dst_port=443,
    )
    res_h = engine.classify(flow_h)
    print_result("h. Group C SNI + DNS Mapping to YouTube (Conflict Detection)", res_h)
    results_summary.append({"label": "h. Group C + DNS Evidence (Conflict)", "result": res_h})

    # Scenario i: Unknown traffic (no matching rules)
    flow_i = make_flow(
        sni="some-random-site.example.org",
        client_ip="192.168.1.100",
        dest_ip="198.51.100.25",
        src_port=50009,
        dst_port=443,
    )
    res_i = engine.classify(flow_i)
    print_result("i. Unknown Traffic (No Matching Rules)", res_i)
    results_summary.append({"label": "i. Unknown Traffic", "result": res_i})

    # Scenario j: Spoofed domain (security test)
    # Testing boundary matching: youtube.com.evil.com should NOT match youtube.com
    flow_j = make_flow(
        sni="youtube.com.evil.com",
        client_ip="192.168.1.100",
        dest_ip="198.51.100.99",
        src_port=50010,
        dst_port=443,
    )
    res_j = engine.classify(flow_j)
    print_result("j. Spoofed Domain (youtube.com.evil.com - Security Test)", res_j)
    results_summary.append({"label": "j. Spoofed Domain (evil.com suffix)", "result": res_j})

    # Scenario k: Excluded domain
    # Testing domain exclusion: pixel.facebook.com is explicitly excluded from facebook rule
    flow_k = make_flow(
        sni="pixel.facebook.com",
        client_ip="192.168.1.100",
        dest_ip="157.240.22.35",
        src_port=50011,
        dst_port=443,
    )
    res_k = engine.classify(flow_k)
    print_result("k. Excluded Domain (pixel.facebook.com)", res_k)
    results_summary.append({"label": "k. Excluded Domain (Tracking Pixel)", "result": res_k})

    # Scenario l: Fast path demo
    # Re-classifying identical 5-tuple flow should hit FlowTable cache immediately
    flow_l = make_flow(
        sni="chatgpt.com",
        client_ip="192.168.1.100",
        dest_ip="104.18.10.20",
        src_port=50020,
        dst_port=443,
    )
    # 1st classification (slow path)
    t0 = time.perf_counter()
    res_l1 = engine.classify(flow_l)
    t_slow_us = (time.perf_counter() - t0) * 1_000_000

    # 2nd classification (fast path cache hit)
    t1 = time.perf_counter()
    res_l2 = engine.classify(flow_l)
    t_fast_us = (time.perf_counter() - t1) * 1_000_000

    print(f"\n{'=' * 60}")
    print("  l. Fast Path Demo (FlowTable Cache)")
    print(f"{'=' * 60}")
    print(f"  First call  (Cold path): {t_slow_us:.1f} µs -> App: {res_l1['app']} (conf={res_l1['confidence']})")
    print(f"  Second call (Fast path): {t_fast_us:.1f} µs -> App: {res_l2['app']} (conf={res_l2['confidence']})")
    speedup = (t_slow_us / t_fast_us) if t_fast_us > 0 else 1.0
    print(f"  Speedup:    {speedup:.1f}x faster via 5-tuple lookup")
    print()
    results_summary.append({"label": "l. Fast Path Demo (FlowTable Hit)", "result": res_l2})

    # Scenario m: Discord via SNI
    flow_m = make_flow(
        sni="discord.com",
        client_ip="192.168.1.100",
        dest_ip="162.159.135.232",
        src_port=50013,
        dst_port=443,
    )
    res_m = engine.classify(flow_m)
    print_result("m. Discord via SNI (Group B)", res_m)
    results_summary.append({"label": "m. Discord via SNI", "result": res_m})

    # Scenario n: Zalo via SNI
    flow_n = make_flow(
        sni="zaloapp.com",
        client_ip="192.168.1.100",
        dest_ip="49.213.78.20",
        src_port=50014,
        dst_port=443,
    )
    res_n = engine.classify(flow_n)
    print_result("n. Zalo via SNI (Group A)", res_n)
    results_summary.append({"label": "n. Zalo via SNI", "result": res_n})

    # --------------------------------------------------------------------------
    # 4. Summary Table
    # --------------------------------------------------------------------------
    print_summary_table(results_summary)


if __name__ == "__main__":
    main()
