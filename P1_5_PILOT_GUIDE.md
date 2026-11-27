# P1.5 feature extraction — Spotify pilot first

## What this adds
- `export_p1_5_features.py`: replays paired PCAP sessions through the existing `PacketProcessor`, applies the session START/END labels, and exports:
  - `burst_statistics.csv`: one row per Burst, with `application` and `batch_id`.
  - `burst_sequences.jsonl`: one record per Flow sequence; each Burst carries packet lengths, timestamps **and original PCAP packet indexes**.
  - `dataset_manifest.json`: per-session processing counters and export counts.
- `tools/audit_p1_5_dataset.py`: read-only structural cross-check of CSV and JSONL.

## Expected capture layout
Put all files under `captures/`, retaining the pair names, for example:
```
captures/
  batch1/
    capture_batch1_20261116_162528.pcap
    session_batch1_20261116_162528.json
    labels_batch1_20261116_162528.jsonl
  batch2/
    ...
```
The extractor recursively scans folders and pairs the three files by their common suffix. The session JSON must contain `session_id` and `lan_subnet` (or `subnet`); alternatively pass `--lan-subnet`.

Label JSONL events must follow the project spec: `session_id`, `application`, `event` (`START`/`END`), and numeric Unix `timestamp` in the same time base as the PCAP. The flow is labeled only when its complete observed Burst time span falls inside exactly one label interval. Ambiguous, overlapping, or boundary-crossing flows are excluded, not guessed.

## Step 1 — smallest Spotify pilot
From the project root:
```
source .venv/bin/activate
python export_p1_5_features.py \
  --captures-dir captures \
  --output-dir ml/p1_5_spotify_pilot \
  --lan-subnet 192.168.1.0/24 \
  --application spotify \
  --smallest-first --max-pcaps 1
```
Replace the subnet only if your capture uses a different LAN subnet. If it is already in session JSON, omit `--lan-subnet`.

This selects the **smallest PCAP among sessions whose labels contain a Spotify interval**, not simply the smallest PCAP by filename. It will not run if no matching Spotify session/pair exists.

## Step 2 — audit the pilot
```
python tools/audit_p1_5_dataset.py \
  --csv ml/p1_5_spotify_pilot/burst_statistics.csv \
  --jsonl ml/p1_5_spotify_pilot/burst_sequences.jsonl \
  --report ml/p1_5_spotify_pilot/audit_report.json
```
Inspect the manifest, audit report, row/sequence counts, and whether Spotify-labeled Flows were exported. A structurally passing audit does not prove label correctness; compare the selected session ID and START/END interval with your capture notes.

## Step 3 — only after pilot approval
Run once over all paired sessions (both batches):
```
python export_p1_5_features.py \
  --captures-dir captures \
  --output-dir ml/p1_5_dataset \
  --lan-subnet 192.168.1.0/24
```
Then audit the two global files. Do not train until all sessions are accounted for and labels/class mapping are confirmed.

## Important constraints
- Existing project segmentation defaults are retained: minimum 2 packets, minimum duration 0 seconds, Burst idle gap 0.5 seconds.
- DNS/SNI rule-identified Flows are early-exit and are not emitted as ML Burst candidates by this pipeline; this dataset represents unresolved ML-admitted Flows.
- `packet_indices` are added to the JSONL export for PCAP traceability; the existing core sequence schema is otherwise left unchanged.
- Do not combine the pilot output with the full dataset output.
