# 09 — Runtime Application Identification

## 1. Mục đích

Mô tả runtime thực tế trong source snapshot 2026-11-27. Phân biệt CatBoost Flow V2 đã tích hợp với các nhánh 1D-CNN/Late Fusion chưa được gọi trong runtime.

## 2. Runtime path hiện được triển khai

```text
Live NIC hoặc PCAP
  → PacketProcessor.process(raw_packet)
  → parse_packet() + LAN subnet filter
  → DNS Parser / DNS Cache update
  → UDP expiry (nếu packet UDP)
  → FlowTracker.add_packet()
  → DNS Application Identifier (early exit nếu match)
  → TCP: TCP reassembly → TLS ClientHello → SNI mapping
    UDP: UDP protocol identification → QUIC v1 Initial decrypt
         → CRYPTO reassembly → TLS ClientHello → SNI mapping
  → Flow lifecycle finalization
       → MLCandidateGate
       → FlowObservation / reconstruction
       → Burst segmentation
       → build_flow_features() (70 Flow features)
       → CatBoostFlowV2.predict_proba() (nếu model configured)
       → FlowState.identification_result
```

Live NIC và PCAP replay đều dùng cùng `PacketProcessor`. UDP pseudo-Flows có idle expiry/capacity eviction; TCP Flows hiện được finalize khi session đóng. Candidate/Burst pipeline và CatBoost inference được gọi trong `_finalize_flows()`.

## 3. DNS/SNI precedence

- DNS observations update trước Flow identification.
- DNS Identifier được gọi đầu tiên; DNS match attach result và return sớm.
- Nếu DNS unresolved, TCP SNI được thử với TCP; UDP/QUIC Initial SNI được thử với UDP.
- Nếu SNI đã classify Flow, QUIC/ML không được chạy cho Flow đó.
- Candidate Gate từ chối Flow đã có `IdentificationStatus.CLASSIFIED`; chỉ Flow unresolved mới có thể vào ML.
- DNS, SNI, QUIC rule matches ưu tiên hơn CatBoost.

## 4. CatBoost runtime boundary

Đã triển khai:
- `PacketProcessor` nhận `ml_model_path` và load `CatBoostFlowV2` một lần.
- Candidate Gate chạy khi Flow finalized.
- Eligible Flow được tái dựng, chia Burst và chuyển qua `build_flow_features()` tạo đúng 70 feature.
- CatBoost loader lấy feature names/classes từ model, validate 70 feature names, sắp xếp theo model order và gọi `predict_proba`.
- Prediction được gắn vào `FlowState.identification_result` với method `BURST_FUSION`, confidence, probability map, feature count và schema metadata.
- Owner-supplied live run: 23 predictions, 0 inference errors.

Chưa được gọi trong runtime:
- PyTorch 1D-CNN inference.
- Late Fusion / stacking.

Giới hạn:
- Inference thành công luôn trả class argmax; không có confidence threshold hoặc calibrated UNKNOWN fallback.
- Prediction execution không chứng minh correctness.
- Live CLI không in Flow prediction sau `processor.close()`.
- PCAP replay trả Flow objects và in Flow summary nhưng không có structured Flow CSV/JSON export.
- No inference latency, CPU/RAM instrumentation found.

## 5. Source map

| Stage | Source |
|---|---|
| Live capture | `src/appid/capture/live.py` — `SingleNICCapture` |
| PCAP replay | `src/appid/capture/pcap.py` — `replay_pcap()` |
| Packet parsing | `src/appid/packet/parser.py` — `parse_packet()` |
| Shared runtime pipeline | `src/appid/pipeline/processor.py` — `PacketProcessor.process()` |
| Flow identity/lifecycle | `src/appid/flow/identity.py`, `src/appid/flow/tracker.py` |
| DNS | `src/appid/dns/` |
| TCP/TLS SNI | `src/appid/sni/` |
| UDP/QUIC | `src/appid/udp/` |
| Evidence precedence | `src/appid/appid/evidence_engine.py` |
| Candidate/Burst pipeline | `src/appid/ml/` |

## 6. Runtime outputs and limits

- Flow identification is stored in `FlowState.identification_result`, including
  method, reason code, evidence and metadata.
- Live capture prints a Flow when first observed and again when its reported
  identification state changes; `--verbose` prints every packet.
- Completed Burst records are exported only when output paths are supplied.
- DNS/TCP-SNI live acceptance, QUIC PCAP evidence and mixed TCP+QUIC PCAP replay
  are separate acceptance scopes; do not merge their counters into one run.
- QUIC support is limited to the implemented QUIC v1 Initial path. It does not
  imply HTTP/3 request completion, QUIC v2, 0-RTT/1-RTT decryption or ECH inner
  hostname recovery.

## 7. Validation evidence snapshot

As recorded in `README.md` and `docs/PROJECT_COMPLETION_ASSESSMENT_2026-11-26.md`:

- `./start.sh --no-setup`: 194 passed, 1 skipped; the skipped test is opt-in
  live-NIC integration requiring root.
- DNS deterministic acceptance: 9/9.
- 2026-11-26 live DNS + TCP/SNI: 180 seconds; five target applications observed
  through DNS and/or TCP SNI; DNS, packet and SNI parse error counters were zero.
- Mixed TCP + QUIC PCAP replay: 5,899 packets parsed/tracked with zero parse
  errors; this is PCAP evidence, not a live QUIC soak result.

These are recorded user-run results, not a claim that this documentation review
reran live capture or the full suite.

## 8. Target architecture versus current scope

The current runtime invokes CatBoost Flow V2 only. The 1D-CNN and Late Fusion
branches remain target/offline experiment scope and are not called by
`PacketProcessor`. Do not describe CatBoost runtime inference as deferred.

## Current runtime implementation — 2026-11-27

### Module name: DNS/SNI/QUIC + CatBoost runtime classification

**Source files**
- `src/appid/pipeline/processor.py`
- `src/appid/ml/candidate_gate.py`
- `src/appid/ml/burst.py`
- `src/appid/ml/flow_aggregation.py`
- `src/appid/ml/catboost_inference.py`

**Implemented**
The actual order is DNS → TCP SNI → UDP/QUIC SNI, followed at Flow finalization by Candidate Gate → Burst segmentation → 70-feature Flow aggregation → CatBoost (only when configured). DNS match returns early. SNI match prevents subsequent QUIC processing for that packet and the classified Flow is excluded from ML. Candidate Gate rejects any `IdentificationStatus.CLASSIFIED` Flow. CatBoost returns argmax class and probability; successful inference attaches `BURST_FUSION`.

**Integrated**
Both live capture and PCAP replay instantiate the same PacketProcessor and can pass `--ml-model`.

**Tested**
Source unit/integration tests cover rule-based integration, gate, Burst, PCAP and live wrappers. Owner supplied one real live CatBoost run with 23 predictions and zero inference errors. This is not an accuracy result.

**Status**
`DONE` for ML runtime integration; `PARTIAL` for output/observability and full acceptance.

**Remaining**
Live final predictions are not printed after close; PCAP prints final Flow summaries but has no structured Flow result export. No confidence cutoff or explicit low-confidence UNKNOWN mapping exists. Ground-truth metrics, model-enabled PCAP run, latency and resource profiling remain `NOT VERIFIED`.
