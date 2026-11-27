"""Stable JSONL and TSV serialization for completed Burst records."""
from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from pathlib import Path

from appid.ml.burst import Burst

_FIELDS = (
    "session_id", "flow_id", "burst_index", "direction", "start_ts", "end_ts",
    "duration_seconds", "packet_count", "total_bytes", "inter_burst_gap_seconds",
)


def _row(burst: Burst) -> dict[str, object]:
    return {
        "session_id": burst.session_id,
        "flow_id": burst.flow_id,
        "burst_index": burst.burst_index,
        "direction": burst.direction.value,
        "start_ts": burst.start_ts,
        "end_ts": burst.end_ts,
        "duration_seconds": burst.duration_seconds,
        "packet_count": burst.packet_count,
        "total_bytes": burst.total_bytes,
        "inter_burst_gap_seconds": burst.inter_burst_gap_seconds,
    }


def write_bursts_jsonl(bursts: Iterable[Burst], path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="\n") as stream:
        for burst in bursts:
            stream.write(json.dumps(_row(burst), ensure_ascii=False, separators=(",", ":")))
            stream.write("\n")
    return destination


def write_bursts_tsv(bursts: Iterable[Burst], path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=_FIELDS, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(_row(burst) for burst in bursts)
    return destination
