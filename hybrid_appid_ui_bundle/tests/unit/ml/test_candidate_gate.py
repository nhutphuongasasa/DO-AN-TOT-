from dataclasses import FrozenInstanceError, replace

import pytest

from appid.domain.models import (
    Direction,
    IdentificationMethod,
    IdentificationResult,
    IdentificationStatus,
    PacketRecord,
    TransportProtocol,
)
from appid.flow.tracker import FlowTracker
from appid.ml import (
    CandidateReason,
    CandidateState,
    FlowObservationAdapter,
    FlowObservationPolicy,
    MLCandidateGate,
)


def make_flow(*, packets=None, identified=False, lan="192.168.1.0/24"):
    tracker = FlowTracker(lan_subnets=[lan])
    records = packets or [
        PacketRecord("ml-s1", 2, 2.0, "192.168.1.10", "203.0.113.5", 51000, 443,
                     TransportProtocol.TCP, 120),
        PacketRecord("ml-s1", 1, 1.0, "203.0.113.5", "192.168.1.10", 443, 51000,
                     TransportProtocol.TCP, 80),
    ]
    flow = None
    for packet in records:
        flow = tracker.add_packet(packet)
    assert flow is not None
    if identified:
        flow.identification_result = IdentificationResult(
            session_id=flow.session_id,
            flow_id=flow.flow_id,
            status=IdentificationStatus.CLASSIFIED,
            application="example.app",
            method=IdentificationMethod.DNS,
            reason_code="DNS_RULE_MATCH",
        )
    return tracker, flow


@pytest.mark.parametrize("method", [
    IdentificationMethod.DNS,
    IdentificationMethod.SNI,
    IdentificationMethod.HYBRID_DNS_SNI,
])
def test_rule_identified_flow_is_rejected_before_ml(method):
    _, flow = make_flow()
    flow.identification_result = IdentificationResult(
        session_id=flow.session_id,
        flow_id=flow.flow_id,
        status=IdentificationStatus.CLASSIFIED,
        application="example.app",
        method=method,
        reason_code="RULE_MATCH",
    )
    decision = MLCandidateGate().evaluate(flow, policy=FlowObservationPolicy(1, 0.0))
    assert decision.state is CandidateState.REJECTED
    assert decision.reason is CandidateReason.RULE_BASED_IDENTIFICATION_PRESENT
    assert decision.observation is None


def test_missing_policy_stays_pending_without_inventing_thresholds():
    _, flow = make_flow()
    decision = MLCandidateGate().evaluate(flow)
    assert decision.state is CandidateState.PENDING
    assert decision.reason is CandidateReason.OBSERVATION_POLICY_UNCONFIGURED


def test_explicit_policy_admits_and_reuses_existing_flow_identity():
    tracker, flow = make_flow()
    decision = MLCandidateGate().evaluate(flow, policy=FlowObservationPolicy(2, 1.0))
    assert decision.state is CandidateState.ELIGIBLE
    assert decision.reason is CandidateReason.ADMITTED
    assert decision.observation.flow_id == flow.flow_id
    assert decision.observation.session_id == flow.session_id
    assert len(tracker.flows) == 1


def test_adapter_orders_by_capture_timestamp_then_packet_index_and_preserves_direction():
    _, flow = make_flow()
    observation = FlowObservationAdapter.adapt(flow)
    assert [packet.packet_index for packet in observation.packets] == [1, 2]
    assert [packet.direction for packet in observation.packets] == [
        Direction.BACKWARD, Direction.FORWARD
    ]
    assert set(observation.direction_coverage) == {Direction.FORWARD, Direction.BACKWARD}
    assert observation.duration_seconds == 1.0


def test_one_way_flow_is_retained_with_quality_flag_not_rejected():
    _, flow = make_flow(packets=[
        PacketRecord("ml-s1", 0, 5.0, "192.168.1.10", "203.0.113.5", 51000, 443,
                     TransportProtocol.TCP, 100),
    ])
    decision = MLCandidateGate().evaluate(flow, policy=FlowObservationPolicy(1, 0.0))
    assert decision.state is CandidateState.ELIGIBLE
    assert "ONE_WAY_OR_INCOMPLETE_DIRECTION_COVERAGE" in decision.observation.quality_flags


def test_observation_is_deeply_immutable_at_packet_collection_boundary():
    _, flow = make_flow()
    observation = FlowObservationAdapter.adapt(flow)
    with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
        observation.flow_id = "other"
    with pytest.raises(AttributeError):
        observation.packets.append(observation.packets[0])


def test_duplicate_packet_index_remains_pending_until_policy_is_decided():
    _, flow = make_flow(packets=[
        PacketRecord("ml-s1", 0, 1.0, "192.168.1.10", "203.0.113.5", 51000, 443,
                     TransportProtocol.TCP, 100),
        PacketRecord("ml-s1", 0, 2.0, "192.168.1.10", "203.0.113.5", 51000, 443,
                     TransportProtocol.TCP, 100),
    ])
    decision = MLCandidateGate().evaluate(flow, policy=FlowObservationPolicy(1, 0.0))
    assert decision.state is CandidateState.PENDING
    assert decision.reason is CandidateReason.DUPLICATE_PACKET_INDEX_POLICY_UNRESOLVED


def test_non_finite_timestamp_is_rejected_as_invalid_metadata():
    _, flow = make_flow()
    flow.packets[0] = replace(flow.packets[0], timestamp=float("nan"))
    decision = MLCandidateGate().evaluate(flow, policy=FlowObservationPolicy(1, 0.0))
    assert decision.state is CandidateState.REJECTED
    assert decision.reason is CandidateReason.INVALID_PACKET_METADATA


def test_packet_count_and_duration_thresholds_are_explicit_and_pending():
    _, flow = make_flow()
    gate = MLCandidateGate()
    count_decision = gate.evaluate(flow, policy=FlowObservationPolicy(3, 0.0))
    duration_decision = gate.evaluate(flow, policy=FlowObservationPolicy(2, 2.0))
    assert count_decision.reason is CandidateReason.BELOW_MINIMUM_PACKET_COUNT
    assert duration_decision.reason is CandidateReason.BELOW_MINIMUM_DURATION


def test_policy_rejects_invalid_thresholds():
    with pytest.raises(ValueError):
        FlowObservationPolicy(0, 0.0)
    with pytest.raises(ValueError):
        FlowObservationPolicy(1, -0.1)
