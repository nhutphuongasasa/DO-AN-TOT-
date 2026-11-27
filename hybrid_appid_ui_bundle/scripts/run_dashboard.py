#!/usr/bin/env python3
"""Serve the static dashboard and finalized AppID JSONL feed."""
from __future__ import annotations

import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "dashboard"
RESULTS = ROOT / "artifacts" / "live-appid-results.jsonl"


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DASHBOARD), **kwargs)

    def do_GET(self):
        if urlparse(self.path).path == "/api/results":
            records = []
            if RESULTS.exists():
                with RESULTS.open(encoding="utf-8") as handle:
                    for line in handle:
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            payload = json.dumps({"results": records}, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/":
            self.path = "/index.html"
        return super().do_GET()


def main():
    host, port = "127.0.0.1", 8765
    print(f"Dashboard: http://{host}:{port}")
    print(f"Reading results from: {RESULTS}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
