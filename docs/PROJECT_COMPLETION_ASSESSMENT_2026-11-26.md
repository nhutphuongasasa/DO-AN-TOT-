# Project status and completion assessment — 2026-11-27

## Executive summary

The ZIP source contains an integrated rule-first runtime and an optional CatBoost Flow V2 inference path. CatBoost is loaded by `PacketProcessor` when `ml_model_path` is supplied; unresolved Flows that pass the candidate gate are segmented into Bursts, aggregated into 70 Flow-level features, and classified. This is not an offline-only ML branch.

The runtime is an Edge AppID prototype for six labels: `facebook`, `tiktok`, `chatgpt`, `other-web`, `youtube`, `spotify`. A successful inference means the model executed, not that the prediction is correct. No accuracy claim is made from the supplied live counters.

## Status at a glance

| Area | Source / evidence | Status |
|---|---|---|
| Packet capture + shared processing | `capture/live.py`, `capture/pcap.py`, `pipeline/processor.py` | DONE |
| Packet parsing + Flow tracking | `packet/parser.py`, `flow/*` | DONE |
| DNS parser/cache/identification | `dns/*`, processor integration | DONE |
| TCP reassembly + TLS ClientHello/SNI | `sni/*`, processor integration | DONE |
| UDP protocol + QUIC v1 Initial/SNI | `udp/*`, `udp/quic/*`, processor integration | PARTIAL |
| Candidate gate + Burst segmentation/statistics | `ml/candidate_gate.py`, `burst.py`, `burst_statistics.py` | DONE |
| CatBoost Flow V2 inference | `ml/catboost_inference.py`, `flow_aggregation.py`, processor integration | DONE |
| Prediction export in live CLI | Live prints pre-finalization Flow state; no final Flow prediction export | PARTIAL |
| Prediction export in PCAP CLI | Prints finalized Flow results to terminal; no Flow CSV/JSON export | PARTIAL |
| End-to-end CatBoost PCAP proof | CLI/integration path exists; no supplied run result with model-enabled PCAP | NOT VERIFIED |
| Accuracy on ground truth | No current ground-truth runtime evaluation result supplied | NOT VERIFIED |
| Inference latency / CPU / RAM | No instrumentation or benchmark evidence | NOT VERIFIED |

## CatBoost Flow V2 — confirmed model record

- Model path: `outputs/p1_5_full_dataset_wirelen_v2/catboost_flow_v2/catboost_flow_v2.cbm`
- Model: CatBoost Flow V2; 70 features; 6 classes; 1,362 trees; approximately 19 MB.
- Class order reported in the project record: `chatgpt`, `facebook`, `other-web`, `spotify`, `tiktok`, `youtube`.
- CatBoost is in optional dependency group `ml`; install with `pip install -e ".[ml,dev]"`.
- The model binary and `outputs/` directory are **not present in this ZIP**. The runtime expects the model file at the path above or another supplied path.
- Inference reads feature names/classes from the loaded model, validates 70 feature names, orders values by model feature order, calls `predict_proba`, and returns the highest-probability class plus confidence/probability map.
- There is no confidence threshold or calibrated UNKNOWN fallback in `_classify_flow_with_ml`: when inference succeeds, it always chooses the maximum-probability class. UNKNOWN is retained when no classification result is attached, e.g. candidate pending/rejected or model unavailable/error.

## Runtime live evidence supplied by project owner

Command:

```bash
sudo -E .venv/bin/python -m appid.capture.live --interface wlp62s0 --ml-model outputs/p1_5_full_dataset_wirelen_v2/catboost_flow_v2/catboost_flow_v2.cbm
```

One run reported:

| Counter | Result |
|---|---:|
| raw packets | 171 |
| parsed packets | 167 |
| tracked packets | 164 |
| outside LAN | 3 |
| unsupported | 4 |
| parse errors | 0 |
| DNS bindings / DNS-identified Flows | 0 / 0 |
| SNI ClientHello / SNI-identified Flows | 12 / 0 |
| SNI unmapped | 12 |
| UDP datagrams | 21 |
| QUIC Initial candidates / decrypted | 0 / 0 |
| ML candidates evaluated | 24 |
| ML candidates admitted / rejected / pending | 23 / 0 / 1 |
| ML predictions / inference errors | 23 / 0 |
| Flows finalized | 24 |
| Bursts created | 108 |

Permitted conclusion: the model loaded, inference ran 23 times, and there were no inference errors in that run. The counters do **not** establish prediction correctness, accuracy, DNS/SNI/QUIC effectiveness, or V1 completion. Live CLI output occurs as packets are processed; final CatBoost predictions are attached during Flow finalization in `processor.close()` and are not subsequently printed as final Flow records by the live CLI.

## Automated test evidence

Previously supplied result for the source/project state described by the owner:

```bash
python -m compileall -q src/appid
PYTHONPATH="$PWD" pytest -q
# 195 passed, 1 skipped, 1 warning in 1.81s
```

This ZIP review did not rerun pytest, install dependencies, or run capture. Treat the above as prior test evidence, not a fresh test run against this archive. The archive includes unit tests for packet parsing, Flow tracking, DNS, SNI, QUIC, candidate gate, Burst/statistics, PacketProcessor and PCAP/live wrappers. No dedicated CatBoost inference test file is present in the ZIP.

Other historical records in the supplied docs (194 passed / 1 skipped, DNS/live and mixed TCP+QUIC acceptance) are retained as historical evidence and must not be merged with the separate 171-packet ML live run.

## Export and observability findings

- Live capture can export completed Burst metadata to optional JSONL/TSV (`--burst-jsonl`, `--burst-tsv`). These are Burst records, not Flow prediction records.
- Live CLI prints Flow state when first observed and when its identification state changes. Since ML inference is called during finalization on `close()`, final ML results may not be reflected in terminal output.
- Final Flow objects and their `identification_result` remain accessible in memory through `PacketProcessor.tracker.flows`; the live CLI does not serialize them.
- PCAP replay returns `ReplayResult.flows` and prints each finalized Flow including application/method/reason. It has no Flow-level CSV/JSON export.
- Prediction metadata includes probability map and feature count, and `confidence` is stored on `IdentificationResult`.
- No inference latency measurement, CPU/RAM sampling, or resource-soak mechanism was found in the reviewed runtime path.

## Module status details

### Packet capture and parsing
**Source files:** `src/appid/capture/live.py`, `src/appid/capture/pcap.py`, `src/appid/packet/parser.py`, `src/appid/pipeline/processor.py`.

**Implemented:** single-NIC Scapy capture; PCAP replay; shared PacketProcessor; parse TCP/UDP packet metadata and filter to configured LAN subnet.

**Integrated:** both live and PCAP call `PacketProcessor.process()`.

**Tested:** tests under `tests/unit/packet/`, `tests/unit/capture/`, and `tests/integration/`; prior suite result above.

**Status:** `DONE`.

**Remaining:** live resource/performance profiling; no claim of packet-loss benchmark.

### Flow tracking
**Source files:** `src/appid/flow/identity.py`, `src/appid/flow/tracker.py`, `src/appid/domain/models.py`.

**Implemented:** canonical bidirectional tuple, client-relative direction, per-session Flow IDs, TCP/UDP tracking, UDP idle expiry and capacity eviction, session close.

**Integrated:** PacketProcessor adds each accepted packet to FlowTracker; finalized Flows feed Candidate Gate.

**Tested:** `tests/unit/flow/`.

**Status:** `DONE`.

**Remaining:** TCP Flows have no idle timeout in the current tracker; they are finalized on session close. Validate long-running TCP lifecycle/resource bounds before deployment.

### DNS
**Source files:** `src/appid/dns/parser.py`, `cache.py`, `identifier.py`, `domain_rules.py`, `models.py`, `config/dns_mapping.yaml`.

**Implemented:** query/response correlation, A/AAAA/CNAME extraction, client-scoped/session-scoped cache, TTL/CNAME chain expiry, ambiguity rejection, domain-rule match.

**Integrated:** DNS observations update on each in-LAN packet; DNS AppID lookup occurs before SNI/QUIC; a successful DNS classification returns early for that Flow.

**Tested:** `tests/unit/dns/`, including `tests/unit/dns/test_pipeline_dns_integration.py`; historical DNS acceptance records in `docs/testing/`.

**Status:** `DONE` for implemented DNS-first path; real-world coverage remains traffic-dependent.

**Remaining:** DNS over encrypted transports is not parsed; shared IP ambiguity intentionally remains unresolved.

### TLS SNI
**Source files:** `src/appid/sni/tcp_reassembly.py`, `tls_parser.py`, `parser.py`, `identifier.py`; integration in `pipeline/processor.py`.

**Implemented:** bounded directional TCP stream reassembly, ClientHello parser, visible SNI and ECH detection, domain mapping.

**Integrated:** runs for unresolved TCP Flows after DNS and before UDP/QUIC path; mapped SNI classifies Flow and exits subsequent processing.

**Tested:** `tests/unit/sni/`, `tests/unit/pipeline/test_sni_integration.py`; historical TCP/SNI live and PCAP evidence.

**Status:** `DONE` within visible ClientHello/SNI scope.

**Remaining:** ECH, absent SNI, mid-stream capture and bounded-reassembly limitations can prevent mapping.

### UDP / QUIC
**Source files:** `src/appid/udp/`, `src/appid/udp/quic/`; integration in `pipeline/processor.py`.

**Implemented:** conservative UDP protocol signatures; QUIC v1 Initial candidate parsing, decryption, CRYPTO reassembly and SNI extraction/mapping.

**Integrated:** only after DNS and TCP SNI leave the Flow unresolved.

**Tested:** `tests/unit/udp/`, `tests/unit/pipeline/test_udp_quic_integration.py`; historical QUIC PCAP/live-probe evidence in docs.

**Status:** `PARTIAL` — QUIC Initial/SNI inspection exists, not general QUIC/HTTP3 decryption or transaction inspection.

**Remaining:** QUIC v2/other versions, post-Initial encrypted payload and broad live traffic coverage are not established by this source/evidence.

### Candidate gate, Burst and statistics
**Source files:** `src/appid/ml/candidate_gate.py`, `burst.py`, `burst_statistics.py`, `schemas.py`, `burst_output.py`.

**Implemented:** immutable FlowObservation, explicit candidate states/reasons, bidirectional Flow reconstruction, direction-change and optional idle-gap segmentation, Burst statistics, JSONL/TSV Burst export.

**Integrated:** `_finalize_flows()` evaluates each Flow once; eligible Flows become Bursts and proceed to ML if configured.

**Tested:** `tests/unit/ml/test_candidate_gate.py`, `test_burst.py`, `test_burst_statistics.py`, `test_burst_sequence.py`, `tests/integration/test_pcap_burst_pipeline.py`.

**Status:** `DONE`.

**Remaining:** pending policy cases and incomplete/one-way Flow quality need operational review; Burst export is not a Flow prediction export.

### Flow-level CatBoost features and inference
**Source files:** `src/appid/ml/flow_aggregation.py`, `catboost_inference.py`; training script `tools/train_p1_5_catboost_flow_v2.py`.

**Implemented:** 70 features: 17 Flow-level count/bytes/duration/direction/missingness values plus 13 Burst statistics × mean/std/min/max. Feature names/order come from model and are validated.

**Integrated:** PacketProcessor loads model once, candidate-gates unresolved Flows, creates Bursts, calls `build_flow_features()`, runs `predict_proba`, and attaches `IdentificationResult` with method `BURST_FUSION`, confidence, probabilities, model and schema metadata.

**Tested:** user-supplied live run: 23 predictions, 0 inference errors. No dedicated CatBoost inference test module exists in this ZIP. Prior automated suite result is not a model-accuracy result.

**Status:** `DONE` for runtime integration; `NOT VERIFIED` for prediction quality and full model-enabled PCAP acceptance.

**Remaining:** add/perform ground-truth evaluation, explicit confidence/UNKNOWN policy, model-enabled PCAP acceptance, final Flow prediction export, latency and resource profiling. Do not train a new model as part of this handover.

## V1 completion boundary

The project is not accurately described as “ML not integrated.” The code and supplied live run establish integration and actual inference. V1 is nevertheless not fully validated: prediction quality, final live prediction visibility/export, model-enabled PCAP end-to-end evidence, latency and CPU/RAM remain open.
