#!/usr/bin/env python3
"""Apply the PCAP original-wire-length fix to a Hybrid AppID project.

Run from the p12-work project root with the project's Python environment:
    .venv/bin/python apply_wirelen_fix.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
PARSER = ROOT / "src/appid/packet/parser.py"
MODELS = ROOT / "src/appid/domain/models.py"
TEST = ROOT / "tests/unit/packet/test_parser.py"

old_parser_anchor = '''def parse_packet(raw_packet, *, session_id: str, packet_index: int) -> PacketRecord | None:\n    """Parse supported IPv4/IPv6 TCP/UDP packets; return None if unsupported."""\n'''
new_parser_helper = '''def _packet_length(raw_packet) -> int:\n    """Return original packet length when capture metadata exposes it.\n\n    Offline Scapy PcapReader packets expose the PCAP record's original length\n    as ``wirelen`` even when the saved packet bytes were truncated by snaplen.\n    Live packets may not expose that attribute, so fall back to captured length.\n    """\n    captured_length = len(raw_packet)\n    wire_length = getattr(raw_packet, "wirelen", None)\n    if wire_length is None:\n        return captured_length\n    try:\n        wire_length = int(wire_length)\n    except (TypeError, ValueError):\n        return captured_length\n    return wire_length if wire_length > 0 else captured_length\n\n\ndef parse_packet(raw_packet, *, session_id: str, packet_index: int) -> PacketRecord | None:\n    """Parse supported IPv4/IPv6 TCP/UDP packets; return None if unsupported."""\n'''
old_doc = '''    `packet_length` is the length in bytes of the packet representation\n    provided to the parser. It is not claimed to be the original on-wire\n    length when a capture was truncated.\n'''
new_doc = '''    `packet_length` is the original packet length in bytes when the capture\n    source exposes it (for example, Scapy's PCAP `wirelen`). If that metadata\n    is unavailable, it falls back to the captured packet representation length.\n'''

test_content = '''from appid.packet.parser import _packet_length\n\n\nclass FakeRawPacket:\n    def __init__(self, captured_length, wirelen_marker=...):\n        self.captured_length = captured_length\n        if wirelen_marker is not ...:\n            self.wirelen = wirelen_marker\n\n    def __len__(self):\n        return self.captured_length\n\n\ndef test_packet_length_prefers_original_pcap_wirelen():\n    assert _packet_length(FakeRawPacket(128, 278)) == 278\n\n\ndef test_packet_length_falls_back_when_wirelen_is_missing():\n    assert _packet_length(FakeRawPacket(128)) == 128\n\n\ndef test_packet_length_falls_back_when_wirelen_is_none_or_invalid():\n    assert _packet_length(FakeRawPacket(128, None)) == 128\n    assert _packet_length(FakeRawPacket(128, "not-a-length")) == 128\n\n\ndef test_packet_length_falls_back_for_nonpositive_wirelen():\n    assert _packet_length(FakeRawPacket(128, 0)) == 128\n'''

if not PARSER.is_file() or not MODELS.is_file():
    raise SystemExit("Run this script from the p12-work project root (src/appid/... not found).")

parser_text = PARSER.read_text(encoding="utf-8")
models_text = MODELS.read_text(encoding="utf-8")

if "def _packet_length(raw_packet) -> int:" not in parser_text:
    if parser_text.count(old_parser_anchor) != 1 or parser_text.count("packet_length=len(raw_packet),") != 1:
        raise SystemExit("STOP: parser.py does not match the expected original version; no files changed.")
if new_doc not in models_text and models_text.count(old_doc) != 1:
    raise SystemExit("STOP: models.py does not match the expected original version; no files changed.")

for path in (PARSER, MODELS):
    backup = path.with_name(path.name + ".bak_wirelen")
    if not backup.exists():
        shutil.copy2(path, backup)

if "def _packet_length(raw_packet) -> int:" not in parser_text:
    parser_text = parser_text.replace(old_parser_anchor, new_parser_helper)
    parser_text = parser_text.replace("packet_length=len(raw_packet),", "packet_length=_packet_length(raw_packet),")
    PARSER.write_text(parser_text, encoding="utf-8")

if new_doc not in models_text:
    MODELS.write_text(models_text.replace(old_doc, new_doc), encoding="utf-8")

TEST.parent.mkdir(parents=True, exist_ok=True)
if TEST.exists() and TEST.read_text(encoding="utf-8") != test_content:
    raise SystemExit(f"STOP: {TEST} already exists with different contents; source patch applied, test file left untouched.")
if not TEST.exists():
    TEST.write_text(test_content, encoding="utf-8")

print("PATCH APPLIED: parser now prefers Scapy wirelen; live capture falls back to len(packet).")
print("Backups: parser.py.bak_wirelen, models.py.bak_wirelen")

compile_result = subprocess.run([sys.executable, "-m", "py_compile", str(PARSER)], check=False)
if compile_result.returncode:
    raise SystemExit(compile_result.returncode)

test_result = subprocess.run(
    [sys.executable, "-m", "pytest", "-q", "tests/unit/packet/test_parser.py", "tests/unit/packet/test_models.py"],
    check=False,
)
if test_result.returncode:
    raise SystemExit(test_result.returncode)
