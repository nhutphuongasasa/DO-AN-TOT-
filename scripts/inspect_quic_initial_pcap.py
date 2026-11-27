#!/usr/bin/env python3
"""Inspect QUIC v1 Initial packets in a PCAP using the P0.7.3 standalone inspector."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from appid.dns.domain_rules import ApplicationDomainRules
from appid.sni.identifier import SNIApplicationIdentifier
from appid.udp.quic import QUICInitialConnection, QUICParseError, parse_initial_header


def main() -> int:
    parser = argparse.ArgumentParser(description="Decrypt QUIC v1 Initial packets and map visible SNI to AppID rules.")
    parser.add_argument("pcap", type=Path, help="PCAP/PCAPNG captured while generating HTTP/3 traffic")
    parser.add_argument("--config", type=Path, default=Path("config/dns_mapping.yaml"))
    parser.add_argument("--json-out", type=Path, default=Path("quic-pcap-inspection.json"))
    args = parser.parse_args()
    try:
        from scapy.all import IP, UDP, IPv6, rdpcap
    except Exception as exc:
        print(f"ERROR: Scapy is required. Run ./setup_linux.sh first: {exc}")
        return 2
    if not args.pcap.is_file():
        print(f"ERROR: PCAP not found: {args.pcap}")
        return 2

    rules = ApplicationDomainRules.from_yaml(args.config)
    appid = SNIApplicationIdentifier(rules)
    packets = rdpcap(str(args.pcap))
    contexts = {}
    outcomes = []
    initial_count = rejected_count = 0
    for packet in packets:
        if UDP not in packet or (IP not in packet and IPv6 not in packet):
            continue
        ip = packet[IP] if IP in packet else packet[IPv6]
        src = (str(ip.src), int(packet[UDP].sport))
        dst = (str(ip.dst), int(packet[UDP].dport))
        # Canonical endpoint pair groups both directions of a UDP 5-tuple.
        endpoints = tuple(sorted((src, dst)))
        payload = bytes(packet[UDP].payload)
        try:
            header = parse_initial_header(payload)
        except (QUICParseError, ValueError):
            continue
        initial_count += 1
        context = contexts.setdefault(endpoints, QUICInitialConnection())
        result = context.process_datagram(payload)
        if result.status != "DECRYPTED":
            rejected_count += 1
            continue
        if not result.sni:
            continue
        mapped = appid.identify(result.sni)
        row = {
            "src": f"{src[0]}:{src[1]}", "dst": f"{dst[0]}:{dst[1]}",
            "version": result.version, "sender_role": result.sender_role,
            "dcid_hex": result.dcid.hex(), "sni": result.sni,
            "application_id": mapped.application_id,
            "reason_code": mapped.reason_code,
            "rule_ids": list(mapped.rule_ids), "ech_detected": result.ech_detected,
        }
        outcomes.append(row)
        print(f"[SNI] {row['sni']} -> {row['application_id'] or 'UNMAPPED'} "
              f"({row['reason_code']}) {row['src']} -> {row['dst']}")

    # Keep a single record per SNI/application/connection tuple for concise output.
    unique = {}
    for row in outcomes:
        key = (row["src"], row["dst"], row["sni"], row["application_id"])
        unique[key] = row
    report = {
        "pcap": str(args.pcap), "packets_read": len(packets),
        "quic_v1_initial_candidates": initial_count,
        "initial_decrypt_rejected": rejected_count,
        "sni_records": list(unique.values()),
        "unique_sni_count": len(unique),
    }
    args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nQUIC v1 Initial candidates: {initial_count}; decrypt rejected: {rejected_count}; "
          f"SNI records: {len(unique)}")
    print(f"JSON report: {args.json_out}")
    if not unique:
        print("[NO SNI] No decryptable ClientHello SNI was extracted. Check capture timing, "
              "PCAP completeness, QUIC version, ECH, and whether traffic was actually HTTP/3.")
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
