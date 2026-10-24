"""Unit tests for ML feature extraction module (ml/features.py)."""

import time
import numpy as np
import pytest

from capture.flow_tracker import FlowState, FlowTracker
from ml.features import (
    DeviceWindowCollector,
    WindowStats,
    extract_first_pkts_sequence,
    extract_flow_features,
)


def test_window_stats_empty():
    """Verify WindowStats extract returns clean zeros without NaN or division by zero."""
    w = WindowStats()
    feats = w.extract()

    assert isinstance(feats, dict)
    assert len(feats) == 24
    assert feats["n_pkts_total"] == 0.0
    assert feats["bytes_total"] == 0.0
    assert feats["pkt_len_mean"] == 0.0
    assert feats["pkt_len_std"] == 0.0
    assert feats["pkt_len_min"] == 0.0
    assert feats["pkt_len_max"] == 0.0
    assert feats["iat_mean"] == 0.0
    assert feats["iat_std"] == 0.0
    assert feats["iat_min"] == 0.0
    assert feats["iat_max"] == 0.0
    assert feats["fwd_pkt_per_sec"] == 0.0
    assert feats["bwd_pkt_per_sec"] == 0.0
    assert feats["dest_port"] == 0.0
    assert feats["is_udp"] == 0.0
    assert feats["is_tcp"] == 0.0


def test_window_stats_single_packet():
    """Verify single packet edge case where duration=0 and IAT has no prior packet."""
    w = WindowStats()
    w.update(size=1400, direction=1, timestamp=10.0)
    feats = w.extract()

    assert feats["n_pkts_total"] == 1.0
    assert feats["bytes_total"] == 1400.0
    assert feats["n_pkts_fwd"] == 1.0
    assert feats["n_pkts_bwd"] == 0.0
    assert feats["fwd_bwd_pkt_ratio"] == 1.0
    assert feats["pkt_len_mean"] == 1400.0
    assert feats["pkt_len_std"] == 0.0
    assert feats["pkt_len_min"] == 1400.0
    assert feats["pkt_len_max"] == 1400.0
    assert feats["pkt_len_fwd_mean"] == 1400.0
    assert feats["iat_mean"] == 0.0
    assert feats["iat_min"] == 0.0
    assert feats["fwd_pkt_per_sec"] == 0.0
    assert feats["bwd_pkt_per_sec"] == 0.0


def test_window_stats_multi_packet_and_reset():
    """Verify window statistics accumulation and cross-window IAT preservation."""
    w = WindowStats()
    w.update(1400, 1, 1.0)
    w.update(500, -1, 1.005)

    feats = w.extract(dest_port=443, transport="tcp")
    assert feats["n_pkts_total"] == 2.0
    assert feats["bytes_total"] == 1900.0
    assert feats["n_pkts_fwd"] == 1.0
    assert feats["n_pkts_bwd"] == 1.0
    assert feats["pkt_len_mean"] == 950.0
    assert feats["pkt_len_std"] == pytest.approx(450.0, rel=1e-4)
    assert feats["dest_port"] == 443.0
    assert feats["is_tcp"] == 1.0
    assert feats["is_udp"] == 0.0
    assert feats["iat_mean"] == pytest.approx(0.005, rel=1e-4)

    # Reset for next window
    w.reset_for_next_window()
    assert w.n == 0
    assert w.sum_bytes == 0
    assert w.prev_time == 1.005  # Preserved!

    # Next packet at 1.020 should compute IAT against 1.005
    w.update(200, 1, 1.020)
    feats2 = w.extract()
    assert feats2["n_pkts_total"] == 1.0
    assert feats2["iat_mean"] == pytest.approx(0.015, rel=1e-4)
    assert feats2["iat_min"] == pytest.approx(0.015, rel=1e-4)


def test_extract_flow_features():
    """Verify extract_flow_features correctly extracts features from FlowState."""
    flow = FlowState(
        client_ip="192.168.1.50",
        client_port=52341,
        dest_ip="93.184.216.34",
        dest_port=443,
        transport="tcp",
        client_mac="AA:BB:CC:DD:EE:FF",
        timestamp=100.0,
    )
    flow.win.update(1200, 1, 100.0)
    flow.win.update(300, -1, 100.1)

    feats = extract_flow_features(flow, dest_port=443, transport="tcp")
    assert feats["dest_port"] == 443.0
    assert feats["is_tcp"] == 1.0
    assert feats["is_udp"] == 0.0
    assert feats["n_pkts_total"] == 2.0


def test_extract_first_pkts_sequence():
    """Verify early packet sequence normalization, IAT, and zero-padding."""
    flow = FlowState(
        client_ip="192.168.1.50",
        client_port=52341,
        dest_ip="93.184.216.34",
        dest_port=443,
        transport="tcp",
        client_mac="AA:BB:CC:DD:EE:FF",
        timestamp=100.0,
    )

    # Empty flow test
    seq_empty = extract_first_pkts_sequence(flow, n=20)
    assert seq_empty.shape == (20, 2)
    assert np.all(seq_empty == 0.0)

    # Populate 3 packets
    flow.first_pkts.append((1500, 100.0))       # Forward full MTU
    flow.first_pkts.append((-750, 100.050))     # Backward 750 bytes, IAT = 50ms
    flow.first_pkts.append((300, 100.150))      # Forward 300 bytes, IAT = 100ms

    seq = extract_first_pkts_sequence(flow, n=20)
    assert seq.shape == (20, 2)
    assert seq[0, 0] == pytest.approx(1.0, rel=1e-4)        # 1500 / 1500
    assert seq[0, 1] == pytest.approx(0.0, rel=1e-4)        # first packet IAT=0
    assert seq[1, 0] == pytest.approx(-0.5, rel=1e-4)       # -750 / 1500
    assert seq[1, 1] == pytest.approx(np.log1p(50.0), rel=1e-4)
    assert seq[2, 0] == pytest.approx(0.2, rel=1e-4)        # 300 / 1500
    assert seq[2, 1] == pytest.approx(np.log1p(100.0), rel=1e-4)

    # Remaining rows padded with 0
    assert np.all(seq[3:] == 0.0)


def test_device_window_collector():
    """Verify DeviceWindowCollector timeseries matrix and window features."""
    collector = DeviceWindowCollector(max_history_s=60.0)
    mac = "11:22:33:44:55:66"

    # Add packets over 2 seconds
    collector.update(mac, size=1000, direction=1, timestamp=10.0)
    collector.update(mac, size=500, direction=-1, timestamp=10.2)
    collector.update(mac, size=1200, direction=1, timestamp=10.6)
    collector.update(mac, size=800, direction=-1, timestamp=11.1)

    # Timeseries shape (60, 4) for 30s window with 0.5s bins
    ts_mat = collector.get_timeseries(mac, window_s=30.0, bin_s=0.5, current_time=11.5)
    assert ts_mat.shape == (60, 4)
    assert ts_mat.dtype == np.float32

    # Aggregated features
    feats = collector.get_device_window_features(mac, window_s=30.0, current_time=11.5, n_active_flows=2)
    assert feats["total_bytes_up"] == 2200.0
    assert feats["total_bytes_down"] == 1300.0
    assert feats["total_pkts_up"] == 2.0
    assert feats["total_pkts_down"] == 2.0
    assert feats["bytes_down_ratio"] == pytest.approx(1300.0 / (3500.0 + 1.0), rel=1e-4)
    assert feats["n_active_flows"] == 2.0

    # Non-existent MAC
    empty_feats = collector.get_device_window_features("00:00:00:00:00:00")
    assert empty_feats["total_bytes_up"] == 0.0


def test_flow_tracker_ml_integration():
    """Verify FlowTracker updates flow.win and flow.first_pkts on packet ingestion."""
    tracker = FlowTracker()

    flow, is_fwd = tracker.normalize_flow(
        src_ip="192.168.1.10",
        src_port=45000,
        dst_ip="8.8.8.8",
        dst_port=53,
        transport="udp",
        mac="AA:BB:CC:DD:EE:FF",
        timestamp=1000.0,
    )
    assert len(flow.first_pkts) == 0
    assert flow.win.n == 0

    # Update packet 1 (fwd)
    tracker.update_packet(flow, is_forward=True, payload=b"", packet_len=60)
    assert flow.win.n == 1
    assert flow.win.bytes_fwd == 60
    assert len(flow.first_pkts) == 1
    assert flow.first_pkts[0] == (60, 1000.0)

    # Update packet 2 (rev)
    flow, is_fwd2 = tracker.normalize_flow(
        src_ip="8.8.8.8",
        src_port=53,
        dst_ip="192.168.1.10",
        dst_port=45000,
        transport="udp",
        timestamp=1000.025,
    )
    tracker.update_packet(flow, is_forward=False, payload=b"", packet_len=120)
    assert flow.win.n == 2
    assert flow.win.bytes_bwd == 120
    assert len(flow.first_pkts) == 2
    assert flow.first_pkts[1] == (-120, 1000.025)

    # Feed more packets beyond 20 to test cap on first_pkts
    for i in range(25):
        tracker.update_packet(flow, is_forward=True, payload=b"", packet_len=100)

    assert flow.win.n == 27
    assert len(flow.first_pkts) == 20  # Capped at FIRST_PKTS_MAX = 20
