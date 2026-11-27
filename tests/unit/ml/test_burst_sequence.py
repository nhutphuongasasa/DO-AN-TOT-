from dataclasses import replace

import pytest

from appid.domain.models import Direction, PacketRecord, TransportProtocol
from appid.flow.tracker import FlowTracker
from appid.ml.burst import BidirectionalFlowReconstructor, BurstSegmentationPolicy, BurstSegmenter
from appid.ml.sequence import build_burst_sequence


def _make_bursts():
    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    flow = None
    rows = [
        (1.0, "192.168.1.10", "203.0.113.8", 100),
        (1.1, "192.168.1.10", "203.0.113.8", 120),
        (1.2, "203.0.113.8", "192.168.1.10", 80),
    ]
    for index, (timestamp, src, dst, length) in enumerate(rows):
        flow = tracker.add_packet(PacketRecord(
            "sequence-s1", index, timestamp, src, dst,
            51000 if src.startswith("192.") else 443,
            443 if src.startswith("192.") else 51000,
            TransportProtocol.TCP, length,
        ))
    assert flow is not None
    observation = BidirectionalFlowReconstructor().reconstruct(flow)
    return BurstSegmenter.segment(observation, BurstSegmentationPolicy())


def test_sequence_preserves_burst_and_packet_order_and_lineage():
    bursts = _make_bursts()
    sequence = build_burst_sequence(reversed(bursts))
    assert sequence.schema_version == "1.0"
    assert sequence.sequence_length == 2
    assert sequence.session_id == "sequence-s1"
    assert sequence.flow_id == bursts[0].flow_id
    assert [item.burst_index for item in sequence.bursts] == [0, 1]
    assert [item.direction for item in sequence.bursts] == ["FORWARD", "BACKWARD"]
    assert sequence.bursts[0].packet_lengths == (100, 120)
    assert sequence.to_dict()["bursts"][0]["packet_lengths"] == [100, 120]


def test_sequence_rejects_empty_input_and_duplicate_indexes():
    with pytest.raises(ValueError, match="at least one"):
        build_burst_sequence([])
    bursts = _make_bursts()
    with pytest.raises(ValueError, match="duplicate burst_index"):
        build_burst_sequence([bursts[0], bursts[0]])


def test_sequence_rejects_packet_count_mismatch():
    burst = _make_bursts()[0]
    malformed = replace(burst, packet_count=burst.packet_count + 1)
    with pytest.raises(ValueError, match="packet_count"):
        build_burst_sequence([malformed])


def test_sequence_rejects_inconsistent_byte_total():
    burst = _make_bursts()[0]
    malformed = replace(burst, total_bytes=burst.total_bytes + 1)
    with pytest.raises(ValueError, match="total_bytes"):
        build_burst_sequence([malformed])


def test_sequence_rejects_mixed_packet_direction_inside_burst():
    burst = _make_bursts()[0]
    changed_packet = replace(burst.packets[0], direction=Direction.BACKWARD)
    malformed = replace(burst, packets=(changed_packet, *burst.packets[1:]))
    with pytest.raises(ValueError, match="mixed packet directions"):
        build_burst_sequence([malformed])
