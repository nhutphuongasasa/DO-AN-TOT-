"""Opt-in real-NIC integration test; see docs/testing/live-nic-capture.md."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("APPID_RUN_LIVE_NIC_TEST") != "1",
    reason="set APPID_RUN_LIVE_NIC_TEST=1 and run pytest as root to capture a real NIC",
)


def test_real_linux_nic_packet_reaches_flow_tracker() -> None:
    from scripts.verify_live_nic import run_smoke_test

    root = Path(__file__).resolve().parents[2]
    result = run_smoke_test(str(root / "config" / "network.json"))
    assert result["marker_frames_seen_on_selected_nic"] >= 1
    assert result["tracked_packets"] >= 1
    assert result["flow_count"] >= 1
    assert result["flow_ids"]
