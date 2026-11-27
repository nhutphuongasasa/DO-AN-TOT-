#!/usr/bin/env python3
"""Strict offline acceptance check for the five TCP/SNI probe applications."""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from appid.capture.pcap import replay_pcap
from appid.domain.models import IdentificationMethod, TransportProtocol

EXPECTED = {
    "chatgpt": "chatgpt.com",
    "facebook": "www.facebook.com",
    "tiktok": "www.tiktok.com",
    "youtube": "www.youtube.com",
    "spotify": "open.spotify.com",
}
ACCEPTED_METHODS = {
    IdentificationMethod.SNI,
    IdentificationMethod.HYBRID_DNS_SNI,
}


def validate_traffic_report(path: Path) -> list[str]:
    failures: list[str] = []
    if not path.is_file():
        return [f"traffic report not found: {path}"]
    try:
        with path.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream, delimiter="\t"))
    except (OSError, csv.Error) as exc:
        return [f"cannot read traffic report: {exc}"]

    by_app = {row.get("app", ""): row for row in rows}
    for app, hostname in EXPECTED.items():
        row = by_app.get(app)
        if row is None:
            failures.append(f"{app}: missing traffic-probe report row")
            continue
        if row.get("expected_sni") != hostname:
            failures.append(
                f"{app}: report hostname mismatch; expected {hostname}, "
                f"got {row.get('expected_sni')!r}"
            )
        try:
            curl_exit = int(row.get("curl_exit", "-1"))
            status = int(row.get("http_status", "0"))
        except ValueError:
            failures.append(f"{app}: invalid curl_exit/http_status in report")
            continue
        # A non-2xx HTTP response can still prove that TLS setup completed.
        # The actual AppID pass condition is checked independently from PCAP.
        if curl_exit != 0 or not 100 <= status <= 599:
            failures.append(
                f"{app}: probe did not complete (curl_exit={curl_exit}, HTTP={status})"
            )
    return failures


def validate_replay(result) -> tuple[list[str], dict[str, str]]:
    failures: list[str] = []
    stats = result.stats
    if stats.raw_packets <= 0:
        failures.append("PCAP replay contained zero packets")
    if stats.parsed_packets <= 0:
        failures.append("PCAP replay parsed zero packets")
    if stats.tracked_packets <= 0:
        failures.append("PacketProcessor tracked zero packets")
    if stats.unsupported_packets:
        failures.append(f"unsupported packets={stats.unsupported_packets}")
    if stats.parse_errors:
        failures.append(f"packet parse errors={stats.parse_errors}")

    observed: dict[str, str] = {}
    for flow in result.flows:
        identification = flow.identification_result
        if identification is None:
            continue
        if flow.key.protocol is not TransportProtocol.TCP:
            continue
        if identification.application not in EXPECTED:
            continue
        if identification.method not in ACCEPTED_METHODS:
            continue
        sni_values = {
            item.value.lower().rstrip(".")
            for item in identification.evidence
            if item.source == "tls_sni"
        }
        expected_hostname = EXPECTED[identification.application]
        if expected_hostname in sni_values:
            observed[identification.application] = expected_hostname

    for app, hostname in EXPECTED.items():
        if app not in observed:
            failures.append(
                f"missing accepted TCP AppID flow: {app} ({hostname}) with SNI evidence"
            )
    return failures, observed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--lan-subnet", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    if not args.pcap.is_file() or args.pcap.stat().st_size <= 24:
        print(f"[FAIL] PCAP missing, empty, or header-only: {args.pcap}", file=sys.stderr)
        return 1

    report_failures = validate_traffic_report(args.report)
    try:
        result = replay_pcap(args.pcap, lan_network=args.lan_subnet)
    except Exception as exc:  # Keep CLI failures concise and actionable.
        print(f"[FAIL] PacketProcessor replay failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    replay_failures, observed = validate_replay(result)
    stats = result.stats
    print("\n=== Strict TCP/SNI acceptance ===")
    print(
        f"raw={stats.raw_packets} parsed={stats.parsed_packets} "
        f"tracked={stats.tracked_packets} unsupported={stats.unsupported_packets} "
        f"parse_errors={stats.parse_errors} sni_errors={stats.sni_parse_errors}"
    )
    for app, hostname in EXPECTED.items():
        if app in observed:
            print(f"[PASS] {app:8s} {hostname}")
        else:
            print(f"[FAIL] {app:8s} {hostname}")

    failures = report_failures + replay_failures
    if failures:
        for failure in failures:
            print(f"[FAIL] {failure}", file=sys.stderr)
        print(f"[FAIL] TCP/SNI acceptance failed ({len(failures)} issue(s)).", file=sys.stderr)
        return 1

    print("[PASS] Traffic report, PCAP replay, and all five TCP/SNI AppIDs verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
