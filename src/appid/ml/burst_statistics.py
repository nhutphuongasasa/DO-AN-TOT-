"""Deterministic descriptive statistics for payload-free Burst observations.

Standard deviations use the population definition (ddof=0). Packet IATs are
computed between adjacent packets inside a Burst after chronological ordering.
"""
from __future__ import annotations

import math
import statistics
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from itertools import pairwise

from appid.domain.models import Direction
from appid.ml.burst import Burst
from appid.ml.schemas import (
    BURST_STATISTICS_SCHEMA_VERSION,
    FLOW_STATISTICS_SCHEMA_VERSION,
)


@dataclass(frozen=True, slots=True)
class BurstStatistics:
    schema_version: str
    session_id: str
    flow_id: str
    burst_index: int
    direction: str
    start_ts: float
    end_ts: float
    duration_seconds: float
    packet_count: int
    total_bytes: int
    packet_length_min: int
    packet_length_max: int
    packet_length_mean: float
    packet_length_median: float
    packet_length_std_population: float
    iat_min_seconds: float | None
    iat_max_seconds: float | None
    iat_mean_seconds: float | None
    iat_std_population_seconds: float | None
    forward_packet_count: int
    backward_packet_count: int
    unknown_packet_count: int
    forward_bytes: int
    backward_bytes: int
    unknown_bytes: int
    inter_burst_gap_seconds: float | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class FlowStatistics:
    schema_version: str
    session_id: str
    flow_id: str
    burst_count: int
    packet_count: int
    total_bytes: int
    start_ts: float
    end_ts: float
    duration_seconds: float
    forward_burst_count: int
    backward_burst_count: int
    unknown_burst_count: int
    inter_burst_gap_min_seconds: float | None
    inter_burst_gap_max_seconds: float | None
    inter_burst_gap_mean_seconds: float | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _finite(value: float, name: str) -> None:
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")


def _population_std(values: list[float]) -> float:
    return statistics.pstdev(values) if values else 0.0


def compute_burst_statistics(burst: Burst) -> BurstStatistics:
    """Compute statistics for one non-empty Burst without reading payloads."""
    if not burst.packets:
        raise ValueError("cannot compute statistics for an empty Burst")
    if burst.packet_count != len(burst.packets):
        raise ValueError("Burst packet_count does not match packet observations")

    if isinstance(burst.burst_index, bool) or not isinstance(burst.burst_index, int) or burst.burst_index < 0:
        raise ValueError("burst_index must be an integer >= 0")
    if not isinstance(burst.direction, Direction):
        raise TypeError("Burst direction must be a Direction")
    if burst.inter_burst_gap_seconds is not None:
        _finite(float(burst.inter_burst_gap_seconds), "inter-burst gap")
        if burst.inter_burst_gap_seconds < 0:
            raise ValueError("inter-burst gap must be >= 0")

    packets = sorted(burst.packets, key=lambda item: (item.timestamp, item.packet_index))
    lengths: list[int] = []
    timestamps: list[float] = []
    packet_indexes: set[int] = set()
    for packet in packets:
        if (isinstance(packet.packet_length, bool)
                or not isinstance(packet.packet_length, int)
                or packet.packet_length < 0):
            raise ValueError("packet lengths must be integers >= 0")
        if (isinstance(packet.packet_index, bool)
                or not isinstance(packet.packet_index, int)
                or packet.packet_index < 0):
            raise ValueError("packet indexes must be integers >= 0")
        if packet.packet_index in packet_indexes:
            raise ValueError("duplicate packet_index in Burst")
        packet_indexes.add(packet.packet_index)
        if not isinstance(packet.direction, Direction):
            raise TypeError("packet direction must be a Direction")
        if packet.direction is not burst.direction:
            raise ValueError("Burst contains mixed packet directions")
        timestamp = float(packet.timestamp)
        _finite(timestamp, "packet timestamp")
        lengths.append(packet.packet_length)
        timestamps.append(timestamp)
    if burst.total_bytes != sum(lengths):
        raise ValueError("Burst total_bytes does not match packet observations")

    iats = [right - left for left, right in pairwise(timestamps)]
    direction_packets = {direction: 0 for direction in Direction}
    direction_bytes = {direction: 0 for direction in Direction}
    for packet in packets:
        if not isinstance(packet.direction, Direction):
            raise TypeError("packet direction must be a Direction")
        direction_packets[packet.direction] += 1
        direction_bytes[packet.direction] += packet.packet_length

    return BurstStatistics(
        schema_version=BURST_STATISTICS_SCHEMA_VERSION,
        session_id=burst.session_id,
        flow_id=burst.flow_id,
        burst_index=burst.burst_index,
        direction=burst.direction.value,
        start_ts=float(packets[0].timestamp),
        end_ts=float(packets[-1].timestamp),
        duration_seconds=max(0.0, float(packets[-1].timestamp - packets[0].timestamp)),
        packet_count=len(packets),
        total_bytes=sum(lengths),
        packet_length_min=min(lengths),
        packet_length_max=max(lengths),
        packet_length_mean=statistics.mean(lengths),
        packet_length_median=statistics.median(lengths),
        packet_length_std_population=_population_std([float(v) for v in lengths]),
        iat_min_seconds=min(iats) if iats else None,
        iat_max_seconds=max(iats) if iats else None,
        iat_mean_seconds=statistics.mean(iats) if iats else None,
        iat_std_population_seconds=_population_std(iats) if iats else None,
        forward_packet_count=direction_packets[Direction.FORWARD],
        backward_packet_count=direction_packets[Direction.BACKWARD],
        unknown_packet_count=direction_packets[Direction.UNKNOWN],
        forward_bytes=direction_bytes[Direction.FORWARD],
        backward_bytes=direction_bytes[Direction.BACKWARD],
        unknown_bytes=direction_bytes[Direction.UNKNOWN],
        inter_burst_gap_seconds=burst.inter_burst_gap_seconds,
    )


def compute_flow_statistics(bursts: Iterable[Burst]) -> FlowStatistics:
    """Aggregate an ordered set of Bursts belonging to exactly one Flow."""
    items = tuple(bursts)
    if not items:
        raise ValueError("at least one Burst is required")
    session_id, flow_id = items[0].session_id, items[0].flow_id
    if any(item.session_id != session_id or item.flow_id != flow_id for item in items):
        raise ValueError("all Bursts must belong to the same session and Flow")
    ordered = tuple(sorted(items, key=lambda item: item.burst_index))
    indexes = [item.burst_index for item in ordered]
    if len(indexes) != len(set(indexes)):
        raise ValueError("duplicate burst_index in Flow")
    if any(item.packet_count != len(item.packets) or not item.packets for item in ordered):
        raise ValueError("each Burst must contain packet observations matching packet_count")

    burst_stats = [compute_burst_statistics(item) for item in ordered]
    for previous, current in pairwise(burst_stats):
        if current.start_ts < previous.end_ts:
            raise ValueError("Flow Bursts are not chronological by burst_index")
    gaps = [item.inter_burst_gap_seconds for item in ordered
            if item.inter_burst_gap_seconds is not None]
    start_ts = min(item.start_ts for item in burst_stats)
    end_ts = max(item.end_ts for item in burst_stats)
    return FlowStatistics(
        schema_version=FLOW_STATISTICS_SCHEMA_VERSION,
        session_id=session_id,
        flow_id=flow_id,
        burst_count=len(ordered),
        packet_count=sum(item.packet_count for item in burst_stats),
        total_bytes=sum(item.total_bytes for item in burst_stats),
        start_ts=start_ts,
        end_ts=end_ts,
        duration_seconds=max(0.0, end_ts - start_ts),
        forward_burst_count=sum(item.direction is Direction.FORWARD for item in ordered),
        backward_burst_count=sum(item.direction is Direction.BACKWARD for item in ordered),
        unknown_burst_count=sum(item.direction is Direction.UNKNOWN for item in ordered),
        inter_burst_gap_min_seconds=min(gaps) if gaps else None,
        inter_burst_gap_max_seconds=max(gaps) if gaps else None,
        inter_burst_gap_mean_seconds=statistics.mean(gaps) if gaps else None,
    )
