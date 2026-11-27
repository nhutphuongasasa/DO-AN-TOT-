"""End-to-end PCAP replay through packet parsing, Flow tracking and Burst output."""
from __future__ import annotations

import pytest

scapy_all = pytest.importorskip("scapy.all")
from scapy.all import IP, TCP, Ether, wrpcap

from appid.capture.pcap import replay_pcap
from appid.domain.models import Direction
from appid.ml.burst_statistics import (
    compute_burst_statistics,
    compute_flow_statistics,
)
from appid.ml.sequence import build_burst_sequence


def _tcp_packet(timestamp: float, *, reverse: bool = False):
    client = "192.168.1.20"
    server = "203.0.113.40"
    packet = Ether() / IP(
        src=server if reverse else client,
        dst=client if reverse else server,
    ) / TCP(
        sport=443 if reverse else 55000,
        dport=55000 if reverse else 443,
        flags="A",
        seq=int(timestamp * 1000),
    )
    packet.time = timestamp
    return packet


def test_real_pcap_replay_produces_bursts_and_exports(tmp_path):
    pcap_path = tmp_path / "bidirectional.pcap"
    wrpcap(str(pcap_path), [
        _tcp_packet(1.0),
        _tcp_packet(1.1),
        _tcp_packet(1.2, reverse=True),
        _tcp_packet(1.3, reverse=True),
        _tcp_packet(2.0),
        _tcp_packet(2.7),
    ])
    jsonl_path = tmp_path / "bursts.jsonl"
    tsv_path = tmp_path / "bursts.tsv"

    result = replay_pcap(
        pcap_path,
        lan_network="192.168.1.0/24",
        session_id="real-pcap-burst",
        burst_jsonl=jsonl_path,
        burst_tsv=tsv_path,
    )

    assert result.stats.raw_packets == 6
    assert result.stats.tracked_packets == 6
    assert result.stats.burst_flows_finalized == 1
    assert result.stats.ml_candidates_admitted == 1
    assert result.stats.bursts_created == 4
    assert [burst.direction for burst in result.bursts] == [
        Direction.FORWARD, Direction.BACKWARD, Direction.FORWARD, Direction.FORWARD
    ]
    assert [burst.packet_count for burst in result.bursts] == [2, 2, 1, 1]
    assert all(burst.flow_id == result.flows[0].flow_id for burst in result.bursts)
    assert all(burst.session_id == "real-pcap-burst" for burst in result.bursts)
    assert len(jsonl_path.read_text(encoding="utf-8").splitlines()) == 4
    assert len(tsv_path.read_text(encoding="utf-8").splitlines()) == 5

    burst_stats = [compute_burst_statistics(burst) for burst in result.bursts]
    flow_stats = compute_flow_statistics(result.bursts)
    sequence = build_burst_sequence(result.bursts)
    assert sum(item.packet_count for item in burst_stats) == 6
    assert flow_stats.packet_count == 6
    assert flow_stats.total_bytes == sum(burst.total_bytes for burst in result.bursts)
    assert sequence.sequence_length == 4
    assert [item.burst_index for item in sequence.bursts] == [0, 1, 2, 3]
