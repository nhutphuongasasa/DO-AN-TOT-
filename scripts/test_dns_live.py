"""Laptop live acceptance test for DNS and TCP/SNI application identification."""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import uuid
from pathlib import Path

from appid.network.interfaces import select_interface
from appid.pipeline.processor import PacketProcessor


def main() -> int:
    parser = argparse.ArgumentParser(description="Test DNS + TCP/SNI AppID on one laptop NIC.")
    parser.add_argument("--config", default="config/network.json")
    parser.add_argument("--interface", help="NIC name; overrides network.mode/interface in config")
    parser.add_argument("--duration", type=int, default=180, help="Capture duration in seconds")
    parser.add_argument("--dns-only", action="store_true", help="Diagnostic DNS-only capture; cannot identify app Flows")
    parser.add_argument("--dns-debug", action="store_true", help="Print detailed DNS query/response/cache/identification diagnostics")
    args = parser.parse_args()
    if args.duration < 1:
        parser.error("--duration must be >= 1")
    logging.basicConfig(level=logging.DEBUG if args.dns_debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s",
                        datefmt="%H:%M:%S")

    try:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        network_config = config.get("network", {})
        if args.interface:
            network_config = {"mode": "manual", "interface": args.interface}
        selected = select_interface(network_config)
    except Exception as exc:
        print(f"[CONFIG ERROR] {exc}", file=sys.stderr)
        return 2

    try:
        from scapy.all import sniff
    except ImportError:
        print("Scapy is missing. Install with: pip install -e '.[dev]'", file=sys.stderr)
        return 2

    processor = PacketProcessor(session_id=str(uuid.uuid4()), lan_network=selected.network)
    seen_result_by_flow: dict[str, tuple[str | None, str | None, str]] = {}
    app_by_flow: dict[str, str] = {}
    seen_flows: set[str] = set()
    identified_by_app: dict[str, int] = {}
    started = time.monotonic()

    print("=" * 72)
    print("HYBRID DNS + TCP/SNI APPLICATION IDENTIFICATION — LAPTOP LIVE TEST")
    print("=" * 72)
    print(f"NIC       : {selected.name}")
    print(f"Local IP  : {selected.address}")
    print(f"LAN       : {selected.network}")
    print(f"Duration  : {args.duration}s")
    print(f"Domain rules : {len(processor.dns_rules.rules)} rules loaded (shared by DNS and SNI)")
    print(f"DNS debug : {'ON' if args.dns_debug else 'OFF (use --dns-debug for packet-level logs)'}")
    print("\nWhile capture runs, use another terminal to run nslookup and curl.")
    print("Example: nslookup chatgpt.com && curl -I https://chatgpt.com")
    print("Repeat for facebook.com, tiktok.com, youtube.com and spotify.com.")
    print("NOTE: DNS-over-HTTPS / DNS-over-TLS may hide DNS packets from this parser.")
    print("-" * 72)

    def handle_packet(raw_packet) -> None:
        flow = processor.process(raw_packet)
        if flow is None:
            return
        seen_flows.add(flow.flow_id)
        result = flow.identification_result
        if result is not None:
            signature = (result.application, result.method.value if result.method else None,
                         result.reason_code)
            if seen_result_by_flow.get(flow.flow_id) != signature:
                seen_result_by_flow[flow.flow_id] = signature
                app_name = result.application or "unknown"
                previous_app = app_by_flow.get(flow.flow_id)
                if previous_app != app_name:
                    if previous_app is not None:
                        identified_by_app[previous_app] -= 1
                        if identified_by_app[previous_app] <= 0:
                            identified_by_app.pop(previous_app, None)
                    app_by_flow[flow.flow_id] = app_name
                    identified_by_app[app_name] = identified_by_app.get(app_name, 0) + 1
                domains = [e.value for e in result.evidence
                           if e.source in ("dns_domain", "tls_sni")]
                print(
                    f"\n[APP IDENTIFIED] app={result.application} method={result.method.value if result.method else '?'} "
                    f"reason={result.reason_code} flow={flow.flow_id} "
                    f"client={flow.client_endpoint.ip if flow.client_endpoint else '?'} "
                    f"server={flow.remote_endpoint.ip if flow.remote_endpoint else '?'} "
                    f"hostnames={','.join(domains) or '(not recorded)'}",
                    flush=True,
                )

    try:
        sniff(
            iface=selected.name,
            filter="port 53" if args.dns_only else None,
            prn=handle_packet,
            store=False,
            timeout=args.duration,
        )
    except KeyboardInterrupt:
        print("\n[STOP] User interrupted capture.")
    except PermissionError:
        print("\n[CAPTURE ERROR] Permission denied. Run with sudo/admin privileges.")
        processor.close()
        return 3
    except Exception as exc:
        print(f"\n[CAPTURE ERROR] {type(exc).__name__}: {exc}", file=sys.stderr)
        processor.close()
        return 3

    processor.close()
    stats = processor.stats
    print("\n" + "=" * 72 + "\nTEST SUMMARY\n" + "=" * 72)
    print(f"Elapsed              : {time.monotonic() - started:.1f}s")
    print(f"Raw packets          : {stats.raw_packets}")
    print(f"Parsed packets       : {stats.parsed_packets}")
    print(f"Tracked packets      : {stats.tracked_packets}")
    print(f"Flows observed       : {len(seen_flows)}")
    print(f"DNS bindings created : {stats.dns_bindings_created}")
    print(f"DNS-identified Flows : {stats.dns_identified_flows}")
    print(f"TCP payload packets  : {stats.tcp_payload_packets}")
    print(f"SNI ClientHellos     : {stats.sni_parsed_client_hellos}")
    print(f"SNI-identified Flows : {stats.sni_identified_flows}")
    print(f"SNI unmapped names   : {stats.sni_unmapped_hostnames}")
    print(f"SNI ECH detections   : {stats.sni_ech_detected}")
    print(f"SNI parse errors     : {stats.sni_parse_errors}")
    print("Identified by app     : " + (", ".join(f"{k}={v}" for k, v in sorted(identified_by_app.items())) or "none"))
    print(f"DNS parser errors    : {stats.dns_processing_errors}")
    if stats.dns_error_types:
        print("DNS error types      : " + ", ".join(
            f"{name}={count}" for name, count in sorted(stats.dns_error_types.items())
        ))
    if processor.dns_parser.diagnostics:
        print("DNS parser diagnostics: " + ", ".join(
            f"{name}={count}" for name, count in sorted(processor.dns_parser.diagnostics.items())
        ))
    print(f"Packet parse errors  : {stats.parse_errors}")
    print(f"Outside LAN          : {stats.outside_lan_packets}")

    expected_apps = {"chatgpt", "facebook", "tiktok", "youtube", "spotify"}
    found_apps = set(identified_by_app)
    missing_apps = sorted(expected_apps - found_apps)
    if expected_apps.issubset(found_apps):
        methods = "DNS only" if args.dns_only else "DNS and/or TCP SNI"
        print(f"\n[PASS] All five target applications were identified using {methods}.")
        return 0
    if stats.dns_identified_flows or stats.sni_identified_flows:
        print("\n[PARTIAL] DNS and/or SNI identified at least one application Flow.")
        print("Not observed in this capture: " + ", ".join(missing_apps))
        print("Generate traffic for each missing app and repeat the test.")
        return 1
    if stats.dns_bindings_created:
        print("\n[PARTIAL] DNS answers were cached, but no application Flow was identified.")
        print("Generate app traffic after the lookup; check destination IP matches DNS answer.")
        return 1
    print("\n[NOT CONFIRMED] No DNS binding was created; this is not a test pass.")
    print("Check NIC, sudo privileges, visible DNS/TLS traffic, and whether the capture started before ClientHello.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
