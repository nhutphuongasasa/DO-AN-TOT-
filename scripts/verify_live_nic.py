"""Linux smoke test: emit a UDP broadcast and prove it reaches FlowTracker.

Run from the repository root with root/capture privileges:
    sudo python scripts/verify_live_nic.py --config config/network.json
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
import uuid
from pathlib import Path

from appid.network.interfaces import SelectedInterface, select_interface
from appid.pipeline.processor import PacketProcessor


def load_selected_interface(config_path: str) -> SelectedInterface:
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    return select_interface(config.get("network", {}))


def run_smoke_test(config_path: str, timeout: float = 5.0) -> dict:
    """Capture a uniquely marked broadcast on the selected NIC and track it."""
    if sys.platform != "linux":
        raise RuntimeError("This real-NIC smoke test is intended for Linux")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise PermissionError("Run with sudo/root so Scapy can capture the NIC")

    from scapy.all import AsyncSniffer, Raw

    selected = load_selected_interface(config_path)
    if selected.network.version != 4:
        raise RuntimeError(
            f"Selected NIC {selected.name!r} has {selected.network}; "
            "this smoke test needs an IPv4 address to send a LAN broadcast"
        )

    session_id = f"nic-smoke-{uuid.uuid4()}"
    processor = PacketProcessor(session_id=session_id, lan_network=selected.network)
    marker = f"APPID-NIC-SMOKE-{uuid.uuid4()}".encode("ascii")
    matched_frames = 0

    def on_packet(raw_packet) -> None:
        nonlocal matched_frames
        if Raw not in raw_packet or marker not in bytes(raw_packet[Raw].load):
            return
        matched_frames += 1
        processor.process(raw_packet)

    sniffer = AsyncSniffer(iface=selected.name, prn=on_packet, store=False)
    sniffer.start()
    try:
        # Give the capture socket time to attach before sending the test frame.
        time.sleep(0.8)
        destination = str(selected.network.broadcast_address)
        source = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            source.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            # Linux-only: bind the sender to the same interface being sniffed.
            if not hasattr(socket, "SO_BINDTODEVICE"):
                raise RuntimeError("SO_BINDTODEVICE is unavailable on this Linux system")
            source.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                selected.name.encode("utf-8") + b"\0",
            )
            source.bind((selected.address, 0))
            source.settimeout(1.0)
            for _ in range(3):
                source.sendto(marker, (destination, 49091))
                time.sleep(0.1)
        finally:
            source.close()

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and processor.stats.tracked_packets == 0:
            time.sleep(0.05)
    finally:
        if sniffer.running:
            sniffer.stop()
        sniffer.join()

    tracked_flows = processor.tracker.flows
    summary = {
        "interface": selected.name,
        "local_address": selected.address,
        "subnet": str(selected.network),
        "session_id": session_id,
        "marker_frames_seen_on_selected_nic": matched_frames,
        "raw_packets_processed": processor.stats.raw_packets,
        "parsed_packets": processor.stats.parsed_packets,
        "tracked_packets": processor.stats.tracked_packets,
        "flow_count": len(tracked_flows),
        "flow_ids": [flow.flow_id for flow in tracked_flows],
        "flow_packet_counts": [len(flow.packets) for flow in tracked_flows],
    }
    processor.close()

    if matched_frames == 0 or processor.stats.tracked_packets == 0 or not tracked_flows:
        raise AssertionError(
            "NIC capture did not deliver the generated packet to FlowTracker. "
            f"Observed summary: {summary}"
        )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify real Linux capture on one NIC and delivery into FlowTracker"
    )
    parser.add_argument("--config", default="config/network.json")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    try:
        result = run_smoke_test(args.config, args.timeout)
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1

    print("[PASS] Real NIC capture reached FlowTracker")
    for key, value in result.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
