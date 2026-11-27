"""Stable, chronological Burst sequence representation for downstream models."""
from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from itertools import pairwise

from appid.domain.models import Direction
from appid.ml.burst import Burst
from appid.ml.schemas import BURST_SEQUENCE_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class BurstSequenceItem:
    burst_index: int
    direction: str
    start_ts: float
    end_ts: float
    duration_seconds: float
    packet_count: int
    total_bytes: int
    inter_burst_gap_seconds: float | None
    packet_lengths: tuple[int, ...]
    packet_timestamps: tuple[float, ...]

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["packet_lengths"] = list(self.packet_lengths)
        result["packet_timestamps"] = list(self.packet_timestamps)
        return result


@dataclass(frozen=True, slots=True)
class BurstSequence:
    schema_version: str
    session_id: str
    flow_id: str
    sequence_length: int
    bursts: tuple[BurstSequenceItem, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "flow_id": self.flow_id,
            "sequence_length": self.sequence_length,
            "bursts": [burst.to_dict() for burst in self.bursts],
        }


def build_burst_sequence(bursts: Iterable[Burst]) -> BurstSequence:
    """Build a sequence sorted by burst_index; preserve packet direction/order."""
    items = tuple(bursts)
    if not items:
        raise ValueError("at least one Burst is required")
    session_id, flow_id = items[0].session_id, items[0].flow_id
    if any(item.session_id != session_id or item.flow_id != flow_id for item in items):
        raise ValueError("all Bursts must belong to the same session and Flow")
    for item in items:
        if (isinstance(item.burst_index, bool) or not isinstance(item.burst_index, int)
                or item.burst_index < 0):
            raise ValueError("burst_index must be an integer >= 0")
        if not isinstance(item.direction, Direction):
            raise TypeError("Burst direction must be a Direction")
        if item.inter_burst_gap_seconds is not None:
            gap = float(item.inter_burst_gap_seconds)
            if not math.isfinite(gap) or gap < 0:
                raise ValueError("inter-burst gap must be finite and >= 0")
    ordered = tuple(sorted(items, key=lambda item: item.burst_index))
    indexes = [item.burst_index for item in ordered]
    if len(indexes) != len(set(indexes)):
        raise ValueError("duplicate burst_index in Flow")

    sequence_items: list[BurstSequenceItem] = []
    for burst in ordered:
        if not burst.packets:
            raise ValueError("cannot include an empty Burst in a sequence")
        if burst.packet_count != len(burst.packets):
            raise ValueError("Burst packet_count does not match packet observations")
        packets = tuple(sorted(burst.packets, key=lambda p: (p.timestamp, p.packet_index)))
        packet_indexes: set[int] = set()
        for packet in packets:
            if (isinstance(packet.packet_index, bool)
                    or not isinstance(packet.packet_index, int)
                    or packet.packet_index < 0):
                raise ValueError("packet indexes must be integers >= 0")
            if packet.packet_index in packet_indexes:
                raise ValueError("duplicate packet_index in Burst")
            packet_indexes.add(packet.packet_index)
            if (isinstance(packet.packet_length, bool)
                    or not isinstance(packet.packet_length, int)
                    or packet.packet_length < 0):
                raise ValueError("packet lengths must be integers >= 0")
            if not math.isfinite(float(packet.timestamp)):
                raise ValueError("packet timestamp must be finite")
            if not isinstance(packet.direction, Direction):
                raise TypeError("packet direction must be a Direction")
            if packet.direction is not burst.direction:
                raise ValueError("Burst contains mixed packet directions")
        if burst.total_bytes != sum(packet.packet_length for packet in packets):
            raise ValueError("Burst total_bytes does not match packet observations")
        sequence_items.append(BurstSequenceItem(
            burst_index=burst.burst_index,
            direction=burst.direction.value,
            start_ts=float(packets[0].timestamp),
            end_ts=float(packets[-1].timestamp),
            duration_seconds=max(0.0, float(packets[-1].timestamp - packets[0].timestamp)),
            packet_count=len(packets),
            total_bytes=sum(packet.packet_length for packet in packets),
            inter_burst_gap_seconds=burst.inter_burst_gap_seconds,
            packet_lengths=tuple(packet.packet_length for packet in packets),
            packet_timestamps=tuple(float(packet.timestamp) for packet in packets),
        ))
    for previous, current in pairwise(sequence_items):
        if current.start_ts < previous.end_ts:
            raise ValueError("Burst sequence timestamps are not chronological")

    return BurstSequence(
        schema_version=BURST_SEQUENCE_SCHEMA_VERSION,
        session_id=session_id,
        flow_id=flow_id,
        sequence_length=len(sequence_items),
        bursts=tuple(sequence_items),
    )
