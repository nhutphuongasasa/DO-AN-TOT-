"""Unit tests for ml.dataset_builder and ml.features."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile

import numpy as np
import pandas as pd
import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from ml.features import WindowStats
from ml.dataset_builder import DatasetBuilder, collect_session_files


def test_window_stats_empty():
    stats = WindowStats()
    d = stats.extract()
    assert d["n_pkts_total"] == 0.0
    assert d["bytes_total"] == 0.0
    assert d["pkt_len_mean"] == 0.0
    for k, v in d.items():
        assert not np.isnan(v), f"NaN found in empty stats field {k}"
        assert not np.isinf(v), f"Inf found in empty stats field {k}"


def test_window_stats_single_packet():
    stats = WindowStats()
    stats.update(size=500, direction=1, timestamp=1000.0)
    d = stats.extract(dest_port=443, transport="tcp")
    assert d["n_pkts_total"] == 1.0
    assert d["n_pkts_fwd"] == 1.0
    assert d["n_pkts_bwd"] == 0.0
    assert d["bytes_total"] == 500.0
    assert d["bytes_fwd"] == 500.0
    assert d["bytes_bwd"] == 0.0
    assert d["pkt_len_min"] == 500.0
    assert d["pkt_len_max"] == 500.0
    assert d["pkt_len_mean"] == 500.0
    assert d["pkt_len_std"] == 0.0
    assert d["dest_port"] == 443.0
    assert d["is_tcp"] == 1.0
    assert d["is_udp"] == 0.0


def test_window_stats_bidirectional():
    ts = [100.0, 100.5, 101.0, 102.0]
    sz = [200, 1200, 300, 1400]
    dirs = [1, -1, 1, -1]
    stats = WindowStats()
    for t, s, d_val in zip(ts, sz, dirs):
        stats.update(size=s, direction=d_val, timestamp=t)
    d = stats.extract(dest_port=80, transport="tcp")

    assert d["n_pkts_total"] == 4.0
    assert d["n_pkts_fwd"] == 2.0
    assert d["n_pkts_bwd"] == 2.0
    assert d["bytes_total"] == 3100.0
    assert d["bytes_fwd"] == 500.0
    assert d["bytes_bwd"] == 2600.0
    assert d["pkt_len_min"] == 200.0
    assert d["pkt_len_max"] == 1400.0
    assert d["iat_min"] == 0.5
    assert d["iat_max"] == 1.0


def test_dataset_builder_synthetic_pipeline(tmp_path: Path):
    # Create synthetic PCAP and session JSON
    pcap_path = tmp_path / "capture_test_123.pcap"
    session_path = tmp_path / "session_test_123.json"
    output_dir = tmp_path / "ml_data"

    # Base epoch time
    t0 = 1700000000.0
    trim_s = 15.0

    # Session layout:
    # app1 "youtube": raw [t0, t0 + 100], trimmed [t0 + 15, t0 + 85]
    # cooldown: [t0 + 100, t0 + 130]
    # app2 "zalo": raw [t0 + 130, t0 + 230], trimmed [t0 + 145, t0 + 215]
    session_data = {
        "batch": "test_batch",
        "pcap_file": pcap_path.name,
        "trim_s": trim_s,
        "apps": [
            {
                "app": "youtube",
                "t_start": t0,
                "t_end": t0 + 100.0,
            },
            {
                "app": "zalo",
                "t_start": t0 + 130.0,
                "t_end": t0 + 230.0,
            },
        ],
    }
    session_path.write_text(json.dumps(session_data))

    packets = []

    # 1. Packet in trim zone (t0 + 5s) -> should be IGNORED
    p_trim = Ether(src="aa:bb:cc:dd:ee:01", dst="11:22:33:44:55:66") / \
             IP(src="192.168.4.2", dst="1.2.3.4") / TCP(sport=50000, dport=443) / ("X" * 100)
    p_trim.time = t0 + 5.0
    p_trim.wirelen = 154
    packets.append(p_trim)

    # 2. DNS packet in valid interval -> should be IGNORED (port 53)
    p_dns = Ether(src="aa:bb:cc:dd:ee:01", dst="11:22:33:44:55:66") / \
            IP(src="192.168.4.2", dst="8.8.8.8") / UDP(sport=51234, dport=53) / ("D" * 50)
    p_dns.time = t0 + 20.0
    p_dns.wirelen = 92
    packets.append(p_dns)

    # 3. ICMP packet in valid interval -> should be IGNORED
    p_icmp = Ether(src="aa:bb:cc:dd:ee:01", dst="11:22:33:44:55:66") / \
             IP(src="192.168.4.2", dst="1.2.3.4") / ICMP()
    p_icmp.time = t0 + 21.0
    p_icmp.wirelen = 64
    packets.append(p_icmp)

    # 4. Flow 1 (youtube) - 4 packets (valid, >= 3 packets)
    # Flow key: 192.168.4.2:50001 -> 142.250.1.1:443
    times_f1 = [t0 + 25.0, t0 + 26.0, t0 + 27.0, t0 + 32.0]  # spans 2 windows: [0, 5) and [5, 10)
    for i, t in enumerate(times_f1):
        if i % 2 == 0:
            # Forward (LAN -> WAN)
            p = Ether(src="aa:bb:cc:dd:ee:01", dst="11:22:33:44:55:66") / \
                IP(src="192.168.4.2", dst="142.250.1.1") / TCP(sport=50001, dport=443) / ("A" * 200)
        else:
            # Backward (WAN -> LAN)
            p = Ether(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:01") / \
                IP(src="142.250.1.1", dst="192.168.4.2") / TCP(sport=443, dport=50001) / ("B" * 800)
        p.time = t
        p.wirelen = len(p)
        packets.append(p)

    # 5. Flow 2 (youtube) - Short flow: only 2 packets (< 3 packets) -> should be SKIPPED
    p_short1 = Ether(src="aa:bb:cc:dd:ee:01", dst="11:22:33:44:55:66") / \
               IP(src="192.168.4.2", dst="142.250.1.2") / TCP(sport=50002, dport=443) / ("S" * 50)
    p_short1.time = t0 + 40.0
    p_short1.wirelen = 100
    p_short2 = Ether(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:01") / \
               IP(src="142.250.1.2", dst="192.168.4.2") / TCP(sport=443, dport=50002) / ("S" * 50)
    p_short2.time = t0 + 41.0
    p_short2.wirelen = 100
    packets.extend([p_short1, p_short2])

    # 6. Packet during cooldown (t0 + 115) -> should be IGNORED
    p_cool = Ether(src="aa:bb:cc:dd:ee:01", dst="11:22:33:44:55:66") / \
             IP(src="192.168.4.2", dst="1.2.3.4") / TCP(sport=50003, dport=443) / ("C" * 100)
    p_cool.time = t0 + 115.0
    p_cool.wirelen = 150
    packets.append(p_cool)

    # 7. Flow 3 (zalo) - 3 packets (valid, >= 3 packets)
    times_f3 = [t0 + 150.0, t0 + 151.0, t0 + 152.0]
    for t in times_f3:
        p = Ether(src="aa:bb:cc:dd:ee:02", dst="11:22:33:44:55:66") / \
            IP(src="192.168.4.3", dst="120.72.0.1") / TCP(sport=50005, dport=443) / ("Z" * 300)
        p.time = t
        p.wirelen = 350
        packets.append(p)

    wrpcap(str(pcap_path), packets)

    # Run DatasetBuilder
    builder = DatasetBuilder(
        lan_subnet="192.168.4.0/24",
        window_flow=5.0,
        window_device=30.0,
        output_dir=output_dir,
    )
    success = builder.process_session(session_path)
    assert success is True

    exported = builder.export()
    assert exported["flow_csv"].exists()
    assert exported["device_csv"].exists()
    assert exported["sequences_npz"].exists()
    assert exported["meta_json"].exists()

    # Check Flow CSV
    df_flow = pd.read_csv(exported["flow_csv"])
    assert len(df_flow) > 0
    assert "label" in df_flow.columns
    assert "batch_id" in df_flow.columns
    assert "flow_key" in df_flow.columns
    labels_set = set(df_flow["label"].unique())
    assert "youtube" in labels_set
    assert "zalo" in labels_set

    # Check Device CSV
    df_dev = pd.read_csv(exported["device_csv"])
    assert len(df_dev) > 0
    assert "total_bytes_up" in df_dev.columns
    assert "mac" in df_dev.columns
    assert "n_active_flows" in df_dev.columns

    # Check Sequences NPZ
    npz_data = np.load(exported["sequences_npz"])
    seqs = npz_data["sequences"]
    lbls = npz_data["labels"]
    assert seqs.ndim == 3
    assert seqs.shape[1] == 20
    assert seqs.shape[2] == 2
    assert len(seqs) == len(lbls)
    # 2 valid flows (Flow 1 youtube, Flow 3 zalo), Flow 2 was < 3 packets so skipped
    assert len(seqs) == 2

    # Check Meta JSON
    meta = json.loads(exported["meta_json"].read_text())
    assert "test_batch" in meta["batch_ids"]
    assert "youtube" in meta["class_names"]
    assert "zalo" in meta["class_names"]
    assert meta["total_sequences"] == 2
