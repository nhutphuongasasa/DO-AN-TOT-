# Source flow review — 2026-11-27

## Scope and method

Reviewed the source archive `hybrid-appid-source-review.zip` directly: runtime entrypoints, PacketProcessor call path, packet/Flow/DNS/SNI/UDP-QUIC modules, ML candidate/Burst/aggregation/inference modules, configuration, tests and Markdown docs. No source code was modified. No dependencies were installed; no network capture, PCAP replay, model inference or pytest run was performed during this documentation review.

The ZIP contains 205 archive entries and Markdown documentation, but does not contain an `outputs/` directory or the CatBoost `.cbm` binary. The configured model path therefore refers to an external project artifact not bundled in this archive.

## Verified runtime call path

1. `SingleNICCapture` in `src/appid/capture/live.py` selects one interface and calls `PacketProcessor.process()` for each captured Scapy packet.
2. `replay_pcap()` in `src/appid/capture/pcap.py` reads packets and calls the same `PacketProcessor.process()`.
3. `parse_packet()` creates a `PacketRecord`; PacketProcessor filters packets to the configured LAN network and updates DNS observations/cache.
4. UDP lifecycle maintenance runs before adding the current UDP packet. The packet is added to the canonical FlowTracker.
5. Identification order is DNS → TCP SNI → UDP/QUIC. DNS match returns immediately. If DNS does not classify, TCP SNI is attempted; a resulting classification prevents QUIC handling. UDP/QUIC is attempted only while the Flow remains unresolved.
6. When UDP idle expiry, UDP capacity eviction, or session close finalizes a Flow, `_finalize_flows()` evaluates Candidate Gate once.
7. Classified DNS/SNI/QUIC Flows are rejected by Candidate Gate. Eligible unresolved Flows are reconstructed, segmented into Bursts, and stored in `PacketProcessor.bursts`.
8. If CatBoost was configured, `_classify_flow_with_ml()` calls `build_flow_features()` (70 features), `CatBoostFlowV2.predict()`, and attaches an `IdentificationResult` with method `BURST_FUSION`.

## Important source findings

- **Runtime ML is integrated.** The earlier completion assessment in the ZIP that said ML runtime inference was deferred is stale and contradicted by current `processor.py`, `live.py`, `pcap.py`, `catboost_inference.py`, and `flow_aggregation.py`.
- `PacketProcessor` loads the model only when `ml_model_path` is supplied. CatBoost is an optional dependency group (`ml`).
- `CatBoostFlowV2` reads feature names/classes from the model, requires 70 unique feature names, orders values by model feature name, then uses `predict_proba`.
- A successful prediction is always the argmax class. No minimum confidence threshold or explicit low-confidence UNKNOWN fallback is implemented.
- The 70-feature builder is `build_flow_features()` in `ml/flow_aggregation.py`. `compute_flow_statistics()` in `ml/burst_statistics.py` returns a different descriptive record and must not be documented as the CatBoost feature vector.
- Live CLI prints Flow status during packet processing. ML inference occurs on finalization during `processor.close()`. The live CLI then exports optional Burst JSONL/TSV and prints counters, but does not print or serialize final Flow prediction records.
- PCAP replay returns `ReplayResult.flows` and its CLI prints finalized Flow application/method/reason rows. No Flow prediction CSV/JSON exporter exists.
- Flow results can be inspected in memory from `PacketProcessor.tracker.flows`; `ReplayResult.flows` exposes them after replay.
- Burst JSONL/TSV output is Burst metadata, not Flow-level prediction export.
- No inference-latency, CPU/RAM profiling or resource-soak instrumentation was found in the reviewed runtime.
- TCP Flows do not have an idle timeout in `FlowTracker`; remaining active Flows close at session end. UDP pseudo-Flows have idle expiry and capacity limits.
- QUIC support is specifically QUIC v1 Initial decryption, CRYPTO extraction/reassembly and visible TLS SNI mapping; it is not general QUIC/HTTP3 payload decryption.
- The source tree has no dedicated CatBoost inference test file and no `tests/unit/ml/test_flow_aggregation.py` in this archive. This does not negate the supplied live inference evidence, but it leaves a focused automated regression gap.

## Module status

| Module | Status | Basis |
|---|---|---|
| Capture / parsing | `DONE` | Shared live and PCAP entrypoints; parser tests |
| Flow tracking | `DONE` | Canonical identity/lifecycle implementation and unit tests |
| DNS parser/cache/AppID | `DONE` | Parser/cache/identifier integration and DNS tests |
| TCP SNI | `DONE` | Reassembly/parser/mapping integration and tests, within visible-SNI scope |
| UDP / QUIC | `PARTIAL` | QUIC v1 Initial/SNI path, bounded scope |
| Candidate Gate | `DONE` | Integrated into Flow finalization; unit tests |
| Burst segmentation/statistics | `DONE` | Integrated; unit and PCAP/Burst integration tests |
| Flow feature aggregation | `DONE` | Runtime builder produces and checks 70 features; no dedicated aggregation test module |
| CatBoost loading/inference | `DONE` | Runtime integration; owner-supplied live 23 prediction / 0 error result |
| Live final prediction output | `PARTIAL` | Results attached after finalization but not printed/exported by live CLI |
| PCAP Flow result visibility | `PARTIAL` | Returned/printed, but no structured Flow prediction export |
| Accuracy / ground-truth quality | `NOT VERIFIED` | No ground-truth evidence supplied for this runtime run |
| Latency / CPU / RAM | `NOT VERIFIED` | No profiling evidence or instrumentation found |
| Model-enabled PCAP end-to-end | `NOT VERIFIED` | Path exists; no run result supplied |

## Test and experimental evidence boundary

Owner-supplied automated result:

```bash
python -m compileall -q src/appid
PYTHONPATH="$PWD" pytest -q
# 195 passed, 1 skipped, 1 warning in 1.81s
```

This review did not rerun it. One separate owner-supplied ML live run recorded 171 raw packets, 167 parsed, 164 tracked, 24 candidate evaluations, 23 admitted, 1 pending, 23 predictions, 0 inference errors, 24 finalized Flows and 108 Bursts. This confirms execution only, not correctness.

Older DNS/TCP-SNI live acceptance and mixed TCP+QUIC PCAP acceptance in the repository docs are distinct historical test runs. They are not evidence that the separate ML live run exercised those same recognition paths.

## Handover priorities

1. Add or specify structured Flow-level prediction export and print post-finalization live results.
2. Add focused CatBoost inference and 70-feature schema tests.
3. Run a small deterministic model-enabled PCAP test and inspect `ReplayResult.flows`.
4. Evaluate against ground truth and report class-wise metrics/confusion matrix; keep low model quality visible if confirmed.
5. Define a confidence threshold or calibrated UNKNOWN policy before treating argmax output as operationally trusted.
6. Measure inference latency, CPU/RAM and long-run Flow-state growth; review TCP Flow lifecycle.
7. Keep the model binary and large datasets external to this lightweight source archive, but supply a separate artifact inventory/checksum.

## Validation boundary

The 195-pass result and live counters above are supplied evidence, not commands executed during this review. Source review is static and does not certify model accuracy or deployment readiness.
