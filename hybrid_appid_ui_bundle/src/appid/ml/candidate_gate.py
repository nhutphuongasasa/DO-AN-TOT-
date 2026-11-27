"""ML candidate admission and immutable Flow observation adapter.

This module deliberately does not segment Bursts or execute model inference.
It reuses the canonical FlowState and Flow ID created by FlowTracker.
Minimum observation thresholds are explicit policy inputs; no project default
is invented while those parameters remain undecided.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum

from appid.domain.models import Direction, IdentificationStatus, TransportProtocol
from appid.flow.tracker import FlowState


class DuplicatePacketIndexError(ValueError):
    """Duplicate packet indexes need a future explicit deduplication policy."""


class CandidateState(str, Enum):
    ELIGIBLE = "ELIGIBLE"
    PENDING = "PENDING"
    REJECTED = "REJECTED"


class CandidateReason(str, Enum):
    RULE_BASED_IDENTIFICATION_PRESENT = "RULE_BASED_IDENTIFICATION_PRESENT"
    UNSUPPORTED_TRANSPORT = "UNSUPPORTED_TRANSPORT"
    EMPTY_FLOW = "EMPTY_FLOW"
    CLIENT_ROLE_UNRESOLVED = "CLIENT_ROLE_UNRESOLVED"
    OBSERVATION_POLICY_UNCONFIGURED = "OBSERVATION_POLICY_UNCONFIGURED"
    BELOW_MINIMUM_PACKET_COUNT = "BELOW_MINIMUM_PACKET_COUNT"
    BELOW_MINIMUM_DURATION = "BELOW_MINIMUM_DURATION"
    INVALID_PACKET_METADATA = "INVALID_PACKET_METADATA"
    DUPLICATE_PACKET_INDEX_POLICY_UNRESOLVED = "DUPLICATE_PACKET_INDEX_POLICY_UNRESOLVED"
    ADMITTED = "ADMITTED"


@dataclass(frozen=True, slots=True)
class FlowObservationPolicy:
    """Explicit admission thresholds; callers must choose them deliberately."""

    min_packets: int
    min_duration_seconds: float

    def __post_init__(self) -> None:
        if isinstance(self.min_packets, bool) or not isinstance(self.min_packets, int):
            raise TypeError("min_packets must be an integer")
        if self.min_packets < 1:
            raise ValueError("min_packets must be an integer >= 1")
        if not math.isfinite(self.min_duration_seconds) or self.min_duration_seconds < 0:
            raise ValueError("min_duration_seconds must be finite and >= 0")


@dataclass(frozen=True, slots=True)
class PacketObservation:
    """Payload-free, immutable packet metadata for downstream ML stages."""

    packet_index: int
    timestamp: float
    direction: Direction
    packet_length: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int


@dataclass(frozen=True, slots=True)
class FlowObservation:
    """Immutable snapshot preserving the canonical Flow lineage."""

    session_id: str
    flow_id: str
    protocol: TransportProtocol
    packets: tuple[PacketObservation, ...]
    first_seen: float
    last_seen: float
    duration_seconds: float
    direction_coverage: tuple[Direction, ...]
    quality_flags: tuple[str, ...]

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def total_bytes(self) -> int:
        return sum(packet.packet_length for packet in self.packets)


@dataclass(frozen=True, slots=True)
class CandidateDecision:
    state: CandidateState
    reason: CandidateReason
    observation: FlowObservation | None = None


class FlowObservationAdapter:
    """Create a deterministic immutable snapshot from an existing FlowState."""

    @staticmethod
    def adapt(flow: FlowState) -> FlowObservation:
        if not flow.session_id or not flow.flow_id:
            raise ValueError("Flow identity is incomplete")
        if flow.key.session_id != flow.session_id:
            raise ValueError("Flow key session_id does not match FlowState")
        if flow.key.protocol not in (TransportProtocol.TCP, TransportProtocol.UDP):
            raise ValueError("unsupported transport protocol")
        if not flow.packets:
            raise ValueError("cannot create an observation from an empty Flow")

        ordered = sorted(flow.packets, key=lambda item: (item.timestamp, item.packet_index))
        indexes: set[int] = set()
        snapshots: list[PacketObservation] = []
        directions: set[Direction] = set()
        for item in ordered:
            if (isinstance(item.packet_index, bool) or not isinstance(item.packet_index, int)
                    or item.packet_index < 0):
                raise ValueError("packet_index must be an integer >= 0")
            if item.packet_index in indexes:
                raise DuplicatePacketIndexError("duplicate packet_index in Flow")
            indexes.add(item.packet_index)
            if not math.isfinite(item.timestamp):
                raise ValueError("packet timestamp must be finite")
            if (isinstance(item.packet_length, bool) or not isinstance(item.packet_length, int)
                    or item.packet_length < 0):
                raise ValueError("packet_length must be an integer >= 0")
            if not isinstance(item.direction, Direction):
                raise ValueError("packet direction is invalid")
            if item.src_endpoint.port is None or item.dst_endpoint.port is None:
                raise ValueError("packet endpoint port is missing")
            directions.add(item.direction)
            snapshots.append(PacketObservation(
                packet_index=item.packet_index,
                timestamp=float(item.timestamp),
                direction=item.direction,
                packet_length=item.packet_length,
                src_ip=item.src_endpoint.ip,
                src_port=item.src_endpoint.port,
                dst_ip=item.dst_endpoint.ip,
                dst_port=item.dst_endpoint.port,
            ))

        timestamps = [item.timestamp for item in snapshots]
        first_seen, last_seen = min(timestamps), max(timestamps)
        flags: list[str] = []
        if Direction.FORWARD not in directions or Direction.BACKWARD not in directions:
            flags.append("ONE_WAY_OR_INCOMPLETE_DIRECTION_COVERAGE")
        if Direction.UNKNOWN in directions:
            flags.append("UNKNOWN_DIRECTION_PRESENT")
        if flow.status.value == "ACTIVE":
            flags.append("FLOW_STILL_ACTIVE")
        coverage = tuple(direction for direction in Direction if direction in directions)
        return FlowObservation(
            session_id=flow.session_id,
            flow_id=flow.flow_id,
            protocol=flow.key.protocol,
            packets=tuple(snapshots),
            first_seen=first_seen,
            last_seen=last_seen,
            duration_seconds=max(0.0, last_seen - first_seen),
            direction_coverage=coverage,
            quality_flags=tuple(flags),
        )


class MLCandidateGate:
    """Admit only unresolved DNS/SNI Flows with an explicit observation policy."""

    def __init__(self, adapter: FlowObservationAdapter | None = None) -> None:
        self.adapter = adapter or FlowObservationAdapter()

    def evaluate(self, flow: FlowState, *,
                 policy: FlowObservationPolicy | None = None) -> CandidateDecision:
        result = flow.identification_result
        if result is not None and result.status is IdentificationStatus.CLASSIFIED:
            return CandidateDecision(CandidateState.REJECTED,
                                     CandidateReason.RULE_BASED_IDENTIFICATION_PRESENT)
        if flow.key.protocol not in (TransportProtocol.TCP, TransportProtocol.UDP):
            return CandidateDecision(CandidateState.REJECTED,
                                     CandidateReason.UNSUPPORTED_TRANSPORT)
        if not flow.packets:
            return CandidateDecision(CandidateState.PENDING, CandidateReason.EMPTY_FLOW)
        if flow.client_endpoint is None or flow.remote_endpoint is None:
            return CandidateDecision(CandidateState.PENDING,
                                     CandidateReason.CLIENT_ROLE_UNRESOLVED)
        if policy is None:
            return CandidateDecision(CandidateState.PENDING,
                                     CandidateReason.OBSERVATION_POLICY_UNCONFIGURED)
        try:
            observation = self.adapter.adapt(flow)
        except DuplicatePacketIndexError:
            return CandidateDecision(
                CandidateState.PENDING,
                CandidateReason.DUPLICATE_PACKET_INDEX_POLICY_UNRESOLVED,
            )
        except (TypeError, ValueError, AttributeError):
            return CandidateDecision(CandidateState.REJECTED,
                                     CandidateReason.INVALID_PACKET_METADATA)
        if observation.packet_count < policy.min_packets:
            return CandidateDecision(CandidateState.PENDING,
                                     CandidateReason.BELOW_MINIMUM_PACKET_COUNT)
        if observation.duration_seconds < policy.min_duration_seconds:
            return CandidateDecision(CandidateState.PENDING,
                                     CandidateReason.BELOW_MINIMUM_DURATION)
        return CandidateDecision(CandidateState.ELIGIBLE, CandidateReason.ADMITTED,
                                 observation=observation)
