#!/usr/bin/env python3
"""Export payload-free P1.5 Burst features from paired PCAP/session/label files.

Expected sibling files for capture_batchX_<session-token>.pcap:
  session_batchX_<session-token>.json
  labels_batchX_<session-token>.jsonl

Label events use {session_id, application, event: START|END, timestamp}
with numeric Unix timestamps in the same time base as the PCAP.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

from appid.capture.pcap import replay_pcap
from appid.ml.burst_statistics import compute_burst_statistics
from appid.ml.sequence import build_burst_sequence


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path):
    rows = []
    with path.open(encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
    return rows


def event_time(row):
    value = row.get("epoch", row.get("timestamp", row.get("ts")))
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"label timestamp must be numeric Unix seconds: {row!r}")
    return float(value)


def make_intervals(label_path, expected_session):
    events = read_jsonl(label_path)
    active = {}
    intervals = []
    for row in sorted(events, key=event_time):
        sid = row.get("session_id", expected_session)
        if sid != expected_session:
            raise ValueError(f"{label_path}: session_id mismatch {sid!r}")
        app = str(row.get("application", row.get("app", ""))).strip().lower()
        event = str(row.get("event", "")).strip().upper()
        ts = event_time(row)
        if event == "START":
            if not app or app in active:
                raise ValueError(f"{label_path}: invalid/duplicate START event: {row!r}")
            active[app] = ts
        elif event == "END":
            if app not in active or ts <= active[app]:
                raise ValueError(f"{label_path}: END without valid START: {row!r}")
            intervals.append((active.pop(app), ts, app))
        else:
            raise ValueError(f"{label_path}: unsupported event {event!r}; expected START/END")
    if active:
        raise ValueError(f"{label_path}: missing END for {sorted(active)}")
    return intervals


def label_flow(flow_bursts, intervals):
    start = min(b.start_ts for b in flow_bursts)
    end = max(b.end_ts for b in flow_bursts)
    hits = [(a, b, app) for a, b, app in intervals if start >= a and end <= b]
    return hits[0][2] if len(hits) == 1 else None


def paired_files(captures_dir):
    for pcap in sorted(Path(captures_dir).rglob("*.pcap*")):
        if not pcap.is_file():
            continue
        stem = pcap.stem
        if stem.startswith("capture_"):
            token = stem[len("capture_"):]
        else:
            token = stem
        base = pcap.parent
        session = base / f"session_{token}.json"
        labels = base / f"labels_{token}.jsonl"
        if session.is_file() and labels.is_file():
            yield pcap, session, labels
        else:
            print(f"SKIP missing pair: {pcap.name} (expected {session.name}, {labels.name})", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--captures-dir", default="captures")
    ap.add_argument("--output-dir", default="ml/p1_5_dataset")
    ap.add_argument("--lan-subnet", default=None)
    ap.add_argument("--session-filter", default=None, help="Exact session_id or session filename token")
    ap.add_argument("--application", default=None, help="Optional application filter, e.g. spotify")
    ap.add_argument("--exclude-application", action="append", default=[], help="Application to exclude; can be repeated")
    ap.add_argument("--smallest-first", action="store_true", help="Process smallest matching PCAP first")
    ap.add_argument("--max-pcaps", type=int, default=None, help="Stop after this many matching PCAPs")
    args = ap.parse_args()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    csv_path = out / "burst_statistics.csv"
    jsonl_path = out / "burst_sequences.jsonl"
    manifest_path = out / "dataset_manifest.json"
    csv_rows, sequence_rows, manifest_sessions = [], [], []
    matched = 0
    pairs = list(paired_files(args.captures_dir))
    if args.smallest_first:
        pairs.sort(key=lambda item: item[0].stat().st_size)

    for pcap, session_path, labels_path in pairs:
        meta = read_json(session_path)
        token = pcap.stem.removeprefix("capture_")

        session_id = str(
            meta.get("session_id") or token
        ).strip()

        batch_id = str(
            meta.get("batch_id") or meta.get("batch") or pcap.parent.name
        )
        token = pcap.stem.removeprefix("capture_")
        if args.session_filter and args.session_filter not in (session_id, token):
            continue
        intervals = make_intervals(labels_path, session_id)
        excluded_apps = {x.strip().lower() for x in args.exclude_application}
        if excluded_apps:
            intervals = [x for x in intervals if x[2].lower() not in excluded_apps]
            if not intervals:
                print(f"SKIP excluded application: {session_id}")
                continue
        if args.application:
            intervals = [x for x in intervals if x[2] == args.application.lower()]
            if not intervals:
                continue
        subnet = args.lan_subnet or meta.get("lan_subnet") or meta.get("subnet")
        if not subnet:
            raise ValueError(f"{session_path}: no lan_subnet/subnet; pass --lan-subnet")
        if args.max_pcaps is not None and matched >= args.max_pcaps:
            break
        matched += 1
        print(f"PROCESS {pcap} session={session_id} batch={batch_id} intervals={len(intervals)}")
        result = replay_pcap(
            pcap, lan_network=subnet, session_id=session_id,
        )
        grouped = defaultdict(list)
        for burst in result.bursts:
            grouped[burst.flow_id].append(burst)

        kept_flows = 0
        for flow_id, bursts in sorted(grouped.items()):
            app = label_flow(bursts, intervals)
            if app is None:
                continue
            kept_flows += 1
            for burst in sorted(bursts, key=lambda b: b.burst_index):
                row = compute_burst_statistics(burst).to_dict()
                row["application"] = app
                row["batch_id"] = batch_id
                csv_rows.append(row)
            seq = build_burst_sequence(bursts).to_dict()
            seq["application"] = app
            seq["batch_id"] = batch_id
            # Packet indexes preserve exact traceability back to original PCAP packet order.
            for seq_burst, burst in zip(seq["bursts"], sorted(bursts, key=lambda b: b.burst_index)):
                packets = sorted(burst.packets, key=lambda p: (p.timestamp, p.packet_index))
                seq_burst["packet_indices"] = [p.packet_index for p in packets]
            sequence_rows.append(seq)
        manifest_sessions.append({
            "session_id": session_id, "batch_id": batch_id, "pcap": str(pcap),
            "raw_packets": result.stats.raw_packets,
            "tracked_packets": result.stats.tracked_packets,
            "ml_candidates_admitted": result.stats.ml_candidates_admitted,
            "bursts_created": result.stats.bursts_created,
            "labeled_flows_exported": kept_flows,
        })
        print(f"  raw={result.stats.raw_packets} tracked={result.stats.tracked_packets} "
              f"admitted={result.stats.ml_candidates_admitted} bursts={result.stats.bursts_created} "
              f"labeled_flows={kept_flows}")

    if matched == 0:
        raise SystemExit("No matching capture/session/labels triplets found. Check filenames and filters.")

    fields = list(csv_rows[0]) if csv_rows else [
        "schema_version", "session_id", "flow_id", "burst_index", "direction",
        "start_ts", "end_ts", "duration_seconds", "packet_count", "total_bytes",
        "packet_length_min", "packet_length_max", "packet_length_mean",
        "packet_length_median", "packet_length_std_population", "iat_min_seconds",
        "iat_max_seconds", "iat_mean_seconds", "iat_std_population_seconds",
        "forward_packet_count", "backward_packet_count", "unknown_packet_count",
        "forward_bytes", "backward_bytes", "unknown_bytes", "inter_burst_gap_seconds",
        "application", "batch_id",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(csv_rows)
    with jsonl_path.open("w", encoding="utf-8", newline="\n") as f:
        for row in sequence_rows:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    manifest = {
        "dataset_version": "P1.5-pilot-1",
        "label_policy": "Flow is retained only when its complete observed Burst time span is inside exactly one START/END interval.",
        "csv": csv_path.name, "jsonl": jsonl_path.name,
        "burst_rows": len(csv_rows), "flow_sequences": len(sequence_rows),
        "sessions": manifest_sessions,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"EXPORTED csv_rows={len(csv_rows)} flow_sequences={len(sequence_rows)}")
    print(f"CSV: {csv_path}\nJSONL: {jsonl_path}\nMANIFEST: {manifest_path}")


if __name__ == "__main__":
    main()
