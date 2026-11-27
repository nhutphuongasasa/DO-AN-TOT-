"""Deterministic, payload-free ML feature extraction and CSV export."""
from __future__ import annotations

import csv
from collections.abc import Iterable, Sequence
from pathlib import Path

from appid.ml.burst import Burst
from appid.ml.burst_statistics import compute_burst_statistics, compute_flow_statistics
from appid.ml.schemas import BURST_STATISTICS_FIELDS, FLOW_STATISTICS_FIELDS


def _write_csv(rows: Iterable[dict[str, object]], fields: Sequence[str], path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=fields,
            extrasaction="raise",
            lineterminator="\n",
        )
        writer.writeheader()
        for row in rows:
            # CSV represents unavailable numeric features as an empty cell.
            writer.writerow({key: "" if row.get(key) is None else row.get(key) for key in fields})
    return destination


def export_burst_features_csv(bursts: Iterable[Burst], path: str | Path) -> Path:
    """Write one validated feature row per Burst, in input order.

    Empty input produces a valid header-only CSV. Packet payloads and endpoint
    identifiers are never exported; the feature schema is explicitly allowlisted.
    """
    rows = [compute_burst_statistics(burst).to_dict() for burst in bursts]
    return _write_csv(rows, BURST_STATISTICS_FIELDS, path)


def export_flow_features_csv(
    flows: Iterable[Iterable[Burst]], path: str | Path
) -> Path:
    """Write one aggregate feature row per Flow (each input item is one Flow).

    Empty input produces a valid header-only CSV. Each Flow is validated by the
    canonical statistics calculator before it is serialized.
    """
    rows = [compute_flow_statistics(flow).to_dict() for flow in flows]
    return _write_csv(rows, FLOW_STATISTICS_FIELDS, path)
