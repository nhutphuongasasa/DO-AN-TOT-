from dataclasses import replace

import pytest

from appid.domain.models import Direction, PacketRecord, TransportProtocol
from appid.flow.tracker import FlowTracker
from appid.ml import (
    BidirectionalFlowReconstructor,
    BurstSegmentationPolicy,
    BurstSegmenter,
)


def make_flow(records):
    tracker = FlowTracker(lan_subnets=["192.168.1.0/24"])
    flow = None
    for record in records:
        flow = tracker.add_packet(record)
    assert flow is not None
    return tracker, flow


def packet(index, ts, src, dst, sport, dport, length=100):
    return PacketRecord(
        "burst-s1", index, ts, src, dst, sport, dport,
        TransportProtocol.TCP, length,
    )


def observation_for(records):
    _, flow = make_flow(records)
    return BidirectionalFlowReconstructor().reconstruct(flow), flow


def test_direction_change_always_starts_new_burst_and_preserves_lineage():
    observation, flow = observation_for([
        packet(0, 1.0, "192.168.1.10", "203.0.113.8", 51000, 443, 100),
        packet(1, 1.1, "192.168.1.10", "203.0.113.8", 51000, 443, 120),
        packet(2, 1.2, "203.0.113.8", "192.168.1.10", 443, 51000, 80),
        packet(3, 1.3, "203.0.113.8", "192.168.1.10", 443, 51000, 90),
        packet(4, 1.4, "192.168.1.10", "203.0.113.8", 51000, 443, 110),
    ])
    bursts = BurstSegmenter.segment(observation, BurstSegmentationPolicy())
    assert [b.direction for b in bursts] == [
        Direction.FORWARD, Direction.BACKWARD, Direction.FORWARD
    ]
    assert [b.packet_count for b in bursts] == [2, 2, 1]
    assert all(b.flow_id == flow.flow_id for b in bursts)
    assert all(b.session_id == flow.session_id for b in bursts)
    assert [b.burst_index for b in bursts] == [0, 1, 2]
    assert [b.total_bytes for b in bursts] == [220, 170, 110]


def test_idle_gap_is_additional_boundary_for_same_direction():
    observation, _ = observation_for([
        packet(0, 1.0, "192.168.1.10", "203.0.113.8", 51000, 443),
        packet(1, 1.2, "192.168.1.10", "203.0.113.8", 51000, 443),
        packet(2, 2.0, "192.168.1.10", "203.0.113.8", 51000, 443),
    ])
    bursts = BurstSegmenter.segment(observation, BurstSegmentationPolicy(0.5))
    assert [b.packet_count for b in bursts] == [2, 1]
    assert bursts[1].inter_burst_gap_seconds == pytest.approx(0.8)


def test_idle_gap_equal_to_threshold_does_not_split():
    observation, _ = observation_for([
        packet(0, 1.0, "192.168.1.10", "203.0.113.8", 51000, 443),
        packet(1, 1.5, "192.168.1.10", "203.0.113.8", 51000, 443),
    ])
    bursts = BurstSegmenter.segment(observation, BurstSegmentationPolicy(0.5))
    assert len(bursts) == 1


def test_one_direction_flow_is_retained_as_single_burst():
    observation, _ = observation_for([
        packet(0, 1.0, "192.168.1.10", "203.0.113.8", 51000, 443),
        packet(1, 1.1, "192.168.1.10", "203.0.113.8", 51000, 443),
    ])
    bursts = BurstSegmenter.segment(observation, BurstSegmentationPolicy())
    assert len(bursts) == 1
    assert bursts[0].direction is Direction.FORWARD


def test_reconstruction_does_not_create_a_second_flow_identity():
    tracker, flow = make_flow([
        packet(0, 1.0, "192.168.1.10", "203.0.113.8", 51000, 443),
    ])
    observation = BidirectionalFlowReconstructor().reconstruct(flow)
    assert observation.flow_id == flow.flow_id
    assert observation.session_id == flow.session_id
    assert len(tracker.flows) == 1


def test_empty_observation_returns_no_bursts():
    observation, _ = observation_for([
        packet(0, 1.0, "192.168.1.10", "203.0.113.8", 51000, 443),
    ])
    empty = replace(observation, packets=())
    assert BurstSegmenter.segment(empty, BurstSegmentationPolicy()) == ()


@pytest.mark.parametrize("value", [0, -1, float("inf"), float("nan")])
def test_idle_gap_policy_rejects_invalid_values(value):
    with pytest.raises((TypeError, ValueError)):
        BurstSegmentationPolicy(value)


def test_unknown_direction_packets_are_not_merged_with_known_direction():
    from appid.domain.models import Direction
    from appid.ml.candidate_gate import FlowObservation, PacketObservation

    observation = FlowObservation(
        session_id="unknown-s1",
        flow_id="unknown-s1:flow-000001",
        protocol=TransportProtocol.TCP,
        packets=(
            PacketObservation(0, 1.0, Direction.FORWARD, 10, "192.168.1.10", 1, "203.0.113.8", 2),
            PacketObservation(1, 1.1, Direction.UNKNOWN, 20, "192.168.1.10", 1, "203.0.113.8", 2),
            PacketObservation(2, 1.2, Direction.UNKNOWN, 30, "192.168.1.10", 1, "203.0.113.8", 2),
            PacketObservation(3, 1.3, Direction.BACKWARD, 40, "203.0.113.8", 2, "192.168.1.10", 1),
        ),
        first_seen=1.0,
        last_seen=1.3,
        duration_seconds=0.3,
        direction_coverage=(Direction.FORWARD, Direction.BACKWARD, Direction.UNKNOWN),
        quality_flags=("UNKNOWN_DIRECTION_PRESENT",),
    )
    bursts = BurstSegmenter.segment(observation, BurstSegmentationPolicy())
    assert [burst.direction for burst in bursts] == [
        Direction.FORWARD, Direction.UNKNOWN, Direction.BACKWARD
    ]
    assert [burst.packet_count for burst in bursts] == [1, 2, 1]
