# Project handover — Hybrid Network AppID

**Snapshot:** 2026-11-27  
**Purpose:** compact entry point for the next AI coding agent. Read this first, then follow the linked source-of-truth documents.

## Project identity

Edge AI application identification from encrypted network traffic. Current labels: `facebook`, `tiktok`, `chatgpt`, `other-web`, `youtube`, `spotify`.

## Current runtime

Live NIC capture and offline PCAP replay share `src/appid/pipeline/processor.py`:

`Capture/PCAP → parse → LAN filter → DNS parser/cache → FlowTracker → DNS identification → TCP SNI → UDP/QUIC Initial SNI → Flow finalization → Candidate Gate → Burst segmentation → 70 Flow features → optional CatBoost Flow V2 → Flow IdentificationResult`.

Rule-based DNS/SNI/QUIC classifications take priority and are excluded from ML. CatBoost is optional and runs only when a model path is supplied.

## ML integration status

Runtime CatBoost is integrated, not deferred:
- `src/appid/ml/catboost_inference.py`
- `src/appid/ml/flow_aggregation.py`
- `src/appid/pipeline/processor.py`
- `src/appid/capture/live.py`
- `src/appid/capture/pcap.py`

Model path: `outputs/p1_5_full_dataset_wirelen_v2/catboost_flow_v2/catboost_flow_v2.cbm`. Owner-provided facts: 70 features, six classes, 1,362 trees, about 19 MB. CatBoost is optional dependency `ml`; install with `pip install -e ".[ml,dev]"`. The model binary is not inside this ZIP.

Owner-supplied live run: 171 raw / 167 parsed / 164 tracked packets; 24 candidates evaluated, 23 admitted, 1 pending; 23 predictions, 0 inference errors; 24 Flows finalized and 108 Bursts. This proves inference executed, not that any prediction was correct.

## Critical output caveat

Live CLI prints Flow state while packets arrive. CatBoost prediction is attached during Flow finalization in `processor.close()`, but the live CLI does not subsequently print or export those final Flow prediction records. `PacketProcessor.tracker.flows` retains Flow objects in memory. PCAP replay returns `ReplayResult.flows` and prints Flow summaries, but neither entrypoint provides a structured Flow prediction CSV/JSON exporter. Burst JSONL/TSV is not Flow prediction export.

## Verified versus open

- Previously supplied tests: `compileall` and `PYTHONPATH="$PWD" pytest -q` → **195 passed, 1 skipped, 1 warning in 1.81s**. Not rerun during ZIP review.
- No ground-truth accuracy evidence for the ML live run.
- No model-enabled PCAP end-to-end result supplied.
- No inference latency, CPU/RAM or resource-soak measurement.
- No confidence threshold/low-confidence UNKNOWN policy; successful inference returns the argmax of six classes.
- TCP Flows have no idle timeout; session close finalizes remaining Flows.
- QUIC support is QUIC v1 Initial decrypt/CRYPTO/SNI, not general HTTP/3 decryption.

## Recommended next work (no source changes were made in this handover)

1. Implement/verify Flow-level prediction export and post-finalization live reporting.
2. Add focused CatBoost inference and 70-feature schema regression tests.
3. Verify a small model-enabled PCAP replay and inspect per-Flow results.
4. Evaluate predictions against labeled ground truth; report per-class metrics and confusion matrix.
5. Decide a confidence/UNKNOWN policy based on validation data.
6. Profile latency, CPU/RAM and long-running Flow lifecycle.

## Documents to read

1. `PROJECT_COMPLETION_ASSESSMENT_2026-11-26.md` — current status, source-based module matrix, test evidence and remaining work.
2. `SOURCE_FLOW_REVIEW_2026-11-26.md` — call path and source-review findings.
3. `spec/01-system-architecture.md` — current runtime architecture and module status.
4. `spec/03-dns-cache-design.md` — DNS parser/cache semantics.
5. `spec/04-flow-tracking.md` — Flow identity/lifecycle.
6. `spec/05-burst-based-approach.md` and `spec/07-feature-engineering.md` — Burst and 70-feature aggregation.
7. `spec/08-model-training-and-evaluation.md` and `spec/09-runtime-classification.md` — CatBoost model and runtime inference.
8. `spec/02-runtime-packet-flow.md` and `spec/10-testing-and-troubleshooting.md` — entrypoints and validation boundary.

## Review constraints

This review changed Markdown only. It did not edit Python, train a model, install dependencies, run tests, run capture, replay PCAPs, or access the Internet.
