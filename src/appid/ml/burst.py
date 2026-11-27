"""ML-specific bidirectional Flow reconstruction and Burst segmentation.

This module consumes the canonical FlowState/FlowObservation. It never creates
or changes Flow identity and never inspects packet payloads.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from appid.domain.models import Direction
from appid.flow.tracker import FlowState
from appid.ml.candidate_gate import (
    FlowObservation,
    FlowObservationAdapter,
    PacketObservation,
)


@dataclass(frozen=True, slots=True)
class BurstSegmentationPolicy:
    """Burst boundaries. ``None`` disables the idle-gap boundary explicitly."""

    idle_gap_seconds: float | None = None

    def __post_init__(self) -> None:
        if self.idle_gap_seconds is not None:
            if isinstance(self.idle_gap_seconds, bool):
                raise TypeError("idle_gap_seconds must be a finite number or None")
            if not isinstance(self.idle_gap_seconds, (int, float)):
                raise TypeError("idle_gap_seconds must be a finite number or None")
            if not math.isfinite(self.idle_gap_seconds) or self.idle_gap_seconds <= 0:
                raise ValueError("idle_gap_seconds must be finite and > 0")


@dataclass(frozen=True, slots=True)
class Burst:
    """Immutable packet group within one existing bidirectional Flow."""

    session_id: str
    flow_id: str
    burst_index: int
    direction: Direction
    start_ts: float
    end_ts: float
    duration_seconds: float
    packet_count: int
    total_bytes: int
    packets: tuple[PacketObservation, ...]
    inter_burst_gap_seconds: float | None


class BidirectionalFlowReconstructor:
    """Create a deterministic payload-free observation from FlowTracker state."""

    def __init__(self, adapter: FlowObservationAdapter | None = None) -> None:
        self.adapter = adapter or FlowObservationAdapter()

    def reconstruct(self, flow: FlowState) -> FlowObservation:
        """Reuse FlowTracker identity and client-relative direction unchanged."""
        return self.adapter.adapt(flow)


class BurstSegmenter:
    """Split ordered packets on direction changes and configured idle gaps.

    Direction change is a fixed boundary. A configured idle-gap threshold is an
    additional boundary; no numeric project default is assumed. Consecutive
    UNKNOWN packets form their own run and are never merged into a known run.
    """

    @staticmethod
    def segment(
        observation: FlowObservation,
        policy: BurstSegmentationPolicy,
    ) -> tuple[Burst, ...]:
        if not observation.packets:
            return ()

        packets = observation.packets
        # Observations are normally already ordered by the adapter. Sorting here
        # keeps the public segmenter deterministic for independently-built input.
        ordered = tuple(sorted(packets, key=lambda p: (p.timestamp, p.packet_index)))
        groups: list[list[PacketObservation]] = []
        current: list[PacketObservation] = [ordered[0]]

        for packet in ordered[1:]:
            previous = current[-1]
            gap = packet.timestamp - previous.timestamp
            if gap < 0:
                raise ValueError("packet timestamps must be chronologically ordered")
            direction_changed = packet.direction is not previous.direction
            idle_gap_exceeded = (
                policy.idle_gap_seconds is not None
                and gap > policy.idle_gap_seconds
            )
            if direction_changed or idle_gap_exceeded:
                groups.append(current)
                current = [packet]
            else:
                current.append(packet)
        groups.append(current)

        bursts: list[Burst] = []
        previous_end: float | None = None
        for index, group in enumerate(groups):
            start_ts = group[0].timestamp
            end_ts = group[-1].timestamp
            inter_gap = None if previous_end is None else max(0.0, start_ts - previous_end)
            bursts.append(Burst(
                session_id=observation.session_id,
                flow_id=observation.flow_id,
                burst_index=index,
                direction=group[0].direction,
                start_ts=start_ts,
                end_ts=end_ts,
                duration_seconds=max(0.0, end_ts - start_ts),
                packet_count=len(group),
                total_bytes=sum(packet.packet_length for packet in group),
                packets=tuple(group),
                inter_burst_gap_seconds=inter_gap,
            ))
            previous_end = end_ts
        return tuple(bursts)
