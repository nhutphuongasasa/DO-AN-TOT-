
"""Aggregate Burst Statistics into the exact 70 CatBoost Flow V2 features."""
from __future__ import annotations

import math
from collections import Counter
from itertools import pairwise

from appid.domain.models import Direction
from appid.ml.burst_statistics import compute_burst_statistics

BURST_FIELDS = (
    "duration_seconds",
    "packet_count",
    "total_bytes",
    "packet_length_min",
    "packet_length_max",
    "packet_length_mean",
    "packet_length_median",
    "packet_length_std_population",
    "iat_min_seconds",
    "iat_max_seconds",
    "iat_mean_seconds",
    "iat_std_population_seconds",
    "inter_burst_gap_seconds",
)

SUMMARY_FIELDS = ("mean", "std", "min", "max")


class OnlineStats:
    """Welford online statistics, matching the training implementation."""

    def __init__(self) -> None:
        self.count = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.minimum = None
        self.maximum = None

    def add(self, value: float | int | None) -> None:
        if value is None:
            return

        value = float(value)
        if not math.isfinite(value):
            return

        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

        if self.minimum is None or value < self.minimum:
            self.minimum = value
        if self.maximum is None or value > self.maximum:
            self.maximum = value

    def summary(self) -> dict[str, float]:
        if self.count == 0:
            nan = float("nan")
            return {"mean": nan, "std": nan, "min": nan, "max": nan}

        return {
            "mean": self.mean,
            "std": math.sqrt(max(0.0, self.m2 / self.count)),
            "min": self.minimum,
            "max": self.maximum,
        }


def build_flow_features(bursts) -> dict[str, float | int]:
    """Build the same 70 features used by train_p1_5_catboost_flow_v2.py."""
    items = tuple(sorted(bursts, key=lambda item: item.burst_index))
    if not items:
        raise ValueError("Cannot build Flow features without Bursts")

    session_id = items[0].session_id
    flow_id = items[0].flow_id

    if any(b.session_id != session_id or b.flow_id != flow_id for b in items):
        raise ValueError("All Bursts must belong to exactly one Flow")

    if len({b.burst_index for b in items}) != len(items):
        raise ValueError("Duplicate burst_index")

    burst_stats = [compute_burst_statistics(burst) for burst in items]

    for previous, current in pairwise(burst_stats):
        if current.start_ts < previous.end_ts:
            raise ValueError("Flow Bursts are not chronological")

    burst_count = len(items)
    packet_count = sum(row.packet_count for row in burst_stats)
    total_bytes = sum(row.total_bytes for row in burst_stats)

    start_ts = min(row.start_ts for row in burst_stats)
    end_ts = max(row.end_ts for row in burst_stats)

    direction_counts = Counter(row.direction for row in burst_stats)

    forward_bytes = sum(row.forward_bytes for row in burst_stats)
    backward_bytes = sum(row.backward_bytes for row in burst_stats)
    unknown_bytes = sum(row.unknown_bytes for row in burst_stats)

    iat_missing = sum(row.iat_mean_seconds is None for row in burst_stats)
    gap_missing = sum(row.inter_burst_gap_seconds is None for row in burst_stats)

    result = {
        "flow_burst_count": burst_count,
        "flow_packet_count": packet_count,
        "flow_total_bytes": total_bytes,
        "flow_duration_seconds": max(0.0, end_ts - start_ts),

        "flow_forward_burst_count": direction_counts[Direction.FORWARD.value],
        "flow_backward_burst_count": direction_counts[Direction.BACKWARD.value],
        "flow_unknown_burst_count": direction_counts[Direction.UNKNOWN.value],

        "flow_forward_burst_ratio": (
            direction_counts[Direction.FORWARD.value] / burst_count
        ),
        "flow_backward_burst_ratio": (
            direction_counts[Direction.BACKWARD.value] / burst_count
        ),
        "flow_unknown_burst_ratio": (
            direction_counts[Direction.UNKNOWN.value] / burst_count
        ),

        "flow_forward_bytes": forward_bytes,
        "flow_backward_bytes": backward_bytes,
        "flow_unknown_bytes": unknown_bytes,

        "flow_forward_byte_ratio": forward_bytes / total_bytes if total_bytes else 0.0,
        "flow_backward_byte_ratio": backward_bytes / total_bytes if total_bytes else 0.0,
        "flow_unknown_byte_ratio": unknown_bytes / total_bytes if total_bytes else 0.0,

        "flow_iat_missing_fraction": iat_missing / burst_count,
        "flow_gap_missing_fraction": gap_missing / burst_count,
    }

    for field in BURST_FIELDS:
        stats = OnlineStats()

        for row in burst_stats:
            stats.add(getattr(row, field))

        for name, value in stats.summary().items():
            result[f"burst_{field}_{name}"] = value

    if len(result) != 70:
        raise RuntimeError(f"Expected 70 features, generated {len(result)}")

    return result
