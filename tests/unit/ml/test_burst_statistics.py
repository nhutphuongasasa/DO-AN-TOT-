from dataclasses import replace

import pytest

from appid.domain.models import Direction, PacketRecord, TransportProtocol
from appid.flow.tracker import FlowTracker
from appid.ml.burst import (
    BidirectionalFlowReconstructor,
    BurstSegmentationPolicy,
    BurstSegmenter,
)
from appid.ml.burst_statistics import compute_burst_statistics, compute_flow_statistics


def _bursts(records):
    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    flow = None
    for record in records:
        flow = tracker.add_packet(record)
    assert flow is not None
    observation = BidirectionalFlowReconstructor().reconstruct(flow)
    return BurstSegmenter.segment(observation, BurstSegmentationPolicy())


def _packet(index, timestamp, *, reverse=False, length=100):
    client, server = "192.168.1.10", "203.0.113.8"
    return PacketRecord(
        "stats-s1", index, timestamp,
        server if reverse else client, client if reverse else server,
        443 if reverse else 51000, 51000 if reverse else 443,
        TransportProtocol.TCP, length,
    )


def test_burst_statistics_calculate_lengths_iats_and_direction_counts():
    bursts = _bursts([
        _packet(0, 1.0, length=100),
        _packet(1, 1.2, length=200),
    ])
    stats = compute_burst_statistics(bursts[0])
    assert stats.schema_version == "1.0"
    assert stats.packet_count == 2
    assert stats.total_bytes == 300
    assert stats.packet_length_min == 100
    assert stats.packet_length_max == 200
    assert stats.packet_length_mean == pytest.approx(150)
    assert stats.packet_length_median == pytest.approx(150)
    assert stats.packet_length_std_population == pytest.approx(50)
    assert stats.iat_min_seconds == pytest.approx(0.2)
    assert stats.iat_mean_seconds == pytest.approx(0.2)
    assert stats.forward_packet_count == 2
    assert stats.backward_packet_count == 0
    assert stats.unknown_packet_count == 0
    assert stats.forward_bytes == 300


def test_single_packet_burst_has_null_iat_statistics():
    burst = _bursts([_packet(0, 1.0)])[0]
    stats = compute_burst_statistics(burst)
    assert stats.iat_min_seconds is None
    assert stats.iat_max_seconds is None
    assert stats.iat_mean_seconds is None
    assert stats.iat_std_population_seconds is None
    assert stats.packet_length_std_population == 0.0


def test_flow_statistics_aggregate_multiple_direction_bursts():
    bursts = _bursts([
        _packet(0, 1.0, length=100),
        _packet(1, 1.1, length=150),
        _packet(2, 1.2, reverse=True, length=80),
        _packet(3, 1.3, reverse=True, length=90),
    ])
    stats = compute_flow_statistics(bursts)
    assert stats.burst_count == 2
    assert stats.packet_count == 4
    assert stats.total_bytes == 420
    assert stats.forward_burst_count == 1
    assert stats.backward_burst_count == 1
    assert stats.unknown_burst_count == 0
    assert stats.duration_seconds == pytest.approx(0.3)
    assert stats.inter_burst_gap_min_seconds == pytest.approx(0.1)


def test_flow_statistics_reject_mixed_flow_lineage():
    bursts = _bursts([_packet(0, 1.0)])
    other = replace(bursts[0], flow_id="different-flow")
    with pytest.raises(ValueError, match="same session and Flow"):
        compute_flow_statistics([bursts[0], other])


def test_flow_statistics_reject_duplicate_burst_indexes():
    burst = _bursts([_packet(0, 1.0)])[0]
    duplicate = replace(burst, start_ts=2.0, end_ts=2.0,
                        packets=tuple(replace(p, timestamp=2.0) for p in burst.packets))
    with pytest.raises(ValueError, match="duplicate burst_index"):
        compute_flow_statistics([burst, duplicate])


def test_burst_statistics_reject_inconsistent_byte_total():
    burst = _bursts([_packet(0, 1.0, length=100)])[0]
    malformed = replace(burst, total_bytes=999)
    with pytest.raises(ValueError, match="total_bytes"):
        compute_burst_statistics(malformed)


def test_burst_statistics_reject_non_finite_packet_timestamp():
    burst = _bursts([_packet(0, 1.0, length=100)])[0]
    malformed_packet = replace(burst.packets[0], timestamp=float("nan"))
    malformed = replace(burst, packets=(malformed_packet,))
    with pytest.raises(ValueError, match="finite"):
        compute_burst_statistics(malformed)


def test_flow_statistics_reject_negative_inter_burst_gap():
    burst = _bursts([_packet(0, 1.0, length=100)])[0]
    malformed = replace(burst, inter_burst_gap_seconds=-0.1)
    with pytest.raises(ValueError, match="inter-burst gap"):
        compute_flow_statistics([malformed])


def test_unknown_direction_is_preserved_in_packet_statistics():
    burst = _bursts([_packet(0, 1.0, length=123)])[0]
    unknown_packet = replace(burst.packets[0], direction=Direction.UNKNOWN)
    unknown_burst = replace(
        burst, direction=Direction.UNKNOWN, packets=(unknown_packet,)
    )
    stats = compute_burst_statistics(unknown_burst)
    assert stats.direction == "UNKNOWN"
    assert stats.unknown_packet_count == 1
    assert stats.unknown_bytes == 123
    assert stats.forward_packet_count == 0
    assert stats.backward_packet_count == 0


def test_flow_statistics_reject_non_chronological_burst_indexes():
    bursts = _bursts([
        _packet(0, 1.0, length=100),
        _packet(1, 1.1, reverse=True, length=80),
    ])
    earlier_packet = replace(bursts[1].packets[0], timestamp=0.5)
    malformed_second = replace(bursts[1], packets=(earlier_packet,))
    with pytest.raises(ValueError, match="not chronological"):
        compute_flow_statistics([bursts[0], malformed_second])
