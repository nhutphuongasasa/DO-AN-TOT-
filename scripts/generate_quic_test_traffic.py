#!/usr/bin/env python3
"""Generate real HTTP/3 requests using aioquic (no curl dependency).

Only advertises HTTP/3 ALPN and QUIC v1. There is no TCP or HTTP/2 fallback.
A request is counted as transport-successful only after an HTTP/3 response
stream completes over the QUIC connection.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

try:
    from aioquic.asyncio import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import ConnectionTerminated
    from aioquic.quic.packet import QuicProtocolVersion
except ImportError as exc:  # provide a useful setup error, not a traceback
    print("ERROR: missing aioquic dependency. Run ./setup_linux.sh", file=sys.stderr)
    print(f"Details: {exc}", file=sys.stderr)
    raise SystemExit(2)

TARGETS: dict[str, tuple[str, str]] = {
    "chatgpt": ("ChatGPT", "https://chatgpt.com/"),
    "facebook": ("Facebook", "https://www.facebook.com/"),
    "tiktok": ("TikTok", "https://www.tiktok.com/"),
    "youtube": ("YouTube", "https://www.youtube.com/"),
    "spotify": ("Spotify", "https://open.spotify.com/"),
}


class HTTP3ClientProtocol(QuicConnectionProtocol):
    """Minimal HTTP/3 GET client based on aioquic's public asyncio API."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.pending: dict[int, dict[str, Any]] = {}

    async def get(self, url: str, timeout: float) -> dict[str, Any]:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError(f"Only valid HTTPS URLs are supported: {url}")
        authority = parsed.netloc.encode("ascii")
        path = urlunsplit(("", "", parsed.path or "/", parsed.query, "" )).encode("ascii")
        stream_id = self._quic.get_next_available_stream_id()
        future = self._loop.create_future()
        self.pending[stream_id] = {"future": future, "status": None, "bytes": 0}
        self.http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority),
                (b":path", path),
                (b"user-agent", b"Hybrid-AppID-QUIC-Test/1.1"),
                (b"accept", b"text/html,application/xhtml+xml,*/*;q=0.8"),
            ],
            end_stream=True,
        )
        self.transmit()
        return await asyncio.wait_for(future, timeout=timeout)

    def quic_event_received(self, event: Any) -> None:
        for http_event in self.http.handle_event(event):
            stream_id = getattr(http_event, "stream_id", None)
            state = self.pending.get(stream_id)
            if state is None:
                continue
            if isinstance(http_event, HeadersReceived):
                for name, value in http_event.headers:
                    if name == b":status":
                        try:
                            state["status"] = int(value)
                        except ValueError:
                            pass
                if http_event.stream_ended:
                    self._finish(stream_id)
            elif isinstance(http_event, DataReceived):
                state["bytes"] += len(http_event.data)
                if http_event.stream_ended:
                    self._finish(stream_id)
        if isinstance(event, ConnectionTerminated):
            for state in list(self.pending.values()):
                future = state["future"]
                if not future.done():
                    future.set_exception(ConnectionError("QUIC connection terminated"))
            self.pending.clear()

    def _finish(self, stream_id: int) -> None:
        state = self.pending.pop(stream_id, None)
        if state is None:
            return
        future = state["future"]
        if not future.done():
            future.set_result({"http_status": state["status"], "response_bytes": state["bytes"]})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate forced HTTP/3-only requests for the five Hybrid AppID target apps."
    )
    parser.add_argument("--apps", nargs="+", choices=sorted(TARGETS), default=list(TARGETS))
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--pause", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=25.0)
    parser.add_argument("--json-out", type=Path, default=Path("quic-traffic-report.json"))
    return parser.parse_args()


async def run_one(app: str, label: str, base_url: str, round_no: int,
                  timeout: float) -> dict[str, Any]:
    parsed = urlsplit(base_url)
    query = parsed.query
    probe = f"appid_quic_probe={int(time.time() * 1000)}-{round_no}"
    query = f"{query}&{probe}" if query else probe
    url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", query, ""))
    host = parsed.hostname
    assert host is not None
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    # Keep this test aligned with P0.7.3's QUIC v1-only implementation.
    configuration.supported_versions = [QuicProtocolVersion.VERSION_1]
    configuration.verify_mode = ssl.CERT_REQUIRED
    started = time.monotonic()
    try:
        async with connect(
            host, parsed.port or 443, configuration=configuration,
            create_protocol=HTTP3ClientProtocol, wait_connected=True,
        ) as client:
            response = await client.get(url, timeout=timeout)
            client.close()
        return {
            "app": app, "label": label, "url": url, "expected_sni": host,
            "round": round_no, "http3_confirmed": True,
            "http_status": response["http_status"],
            "response_bytes": response["response_bytes"],
            "elapsed_seconds": round(time.monotonic() - started, 3), "error": None,
        }
    except Exception as exc:  # report each target independently
        return {
            "app": app, "label": label, "url": url, "expected_sni": host,
            "round": round_no, "http3_confirmed": False,
            "http_status": None, "response_bytes": 0,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "error": f"{type(exc).__name__}: {exc}"[:1000],
        }


async def async_main(args: argparse.Namespace) -> int:
    report: dict[str, Any] = {
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "client": "aioquic", "quic_version": "v1", "alpn": H3_ALPN,
        "mode": "HTTP/3-only; no TCP or HTTP/2 fallback", "results": [],
    }
    print("=== Hybrid AppID | aioquic HTTP/3 / QUIC v1 traffic generator ===")
    print("Mode: ALPN h3 only; QUIC v1 only; TLS certificate verification enabled")
    print("No curl dependency and no TCP/HTTP2 fallback. SNI must be checked in PCAP.\n")
    for round_no in range(1, args.rounds + 1):
        for index, key in enumerate(args.apps):
            label, base_url = TARGETS[key]
            result = await run_one(key, label, base_url, round_no, args.timeout)
            report["results"].append(result)
            state = "HTTP/3 PASS" if result["http3_confirmed"] else "NO HTTP/3"
            print(f"[{state}] {label:8s} SNI~{result['expected_sni']} "
                  f"status={result['http_status'] or '-'} "
                  f"bytes={result['response_bytes']} time={result['elapsed_seconds']}s")
            if result["error"]:
                print(f"  error: {result['error']}")
            if args.pause and (round_no != args.rounds or index != len(args.apps) - 1):
                await asyncio.sleep(args.pause)
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    report["success_count"] = sum(r["http3_confirmed"] for r in report["results"])
    report["request_count"] = len(report["results"])
    report["all_http3_confirmed"] = report["success_count"] == report["request_count"]
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nHTTP/3 confirmed: {report['success_count']}/{report['request_count']}")
    print(f"Report: {args.json_out}")
    if not report["all_http3_confirmed"]:
        print("[PARTIAL/FAIL] Failed targets are not counted as QUIC traffic.")
        return 1
    print("[PASS] Every request completed over HTTP/3 (QUIC v1).")
    return 0


def main() -> int:
    args = parse_args()
    if args.rounds < 1 or args.pause < 0 or args.timeout <= 0:
        print("ERROR: --rounds must be >=1, --pause >=0 and --timeout >0", file=sys.stderr)
        return 2
    return asyncio.run(async_main(args))


if __name__ == "__main__":
    raise SystemExit(main())
