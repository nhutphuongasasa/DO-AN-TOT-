# 01 — Kiến trúc hệ thống

## Target architecture versus implemented runtime

The design below includes optional 1D-CNN and Late Fusion target branches. They are not invoked by the current runtime. The implemented runtime is DNS → SNI/QUIC → Candidate Gate → Burst → 70-feature Flow aggregation → optional CatBoost Flow V2.

```text
Packet Capture
  → Packet Parsing & Flow Tracking
  → DNS Parser + DNS Cache
  → DNS Identification
      ├─ DNS_IDENTIFIED → Application (early exit)
      └─ DNS_UNRESOLVED
          ├─ TCP → TLS ClientHello / SNI
          │    ├─ SNI_IDENTIFIED → Application (early exit)
          │    └─ SNI_UNRESOLVED
          └─ UDP → UDP Protocol / QUIC v1 Initial → CRYPTO / SNI
               ├─ SNI_IDENTIFIED → Application (early exit)
               └─ unresolved
                    → Flow finalization
                    → ML Candidate Gate
                    → FlowObservation / reconstruction
                    → Burst Segmentation
                    → 70 Flow-level features
                    → optional CatBoost Flow V2
                    → Flow IdentificationResult

Target-only branches: Burst Sequence → 1D-CNN and Late Fusion / Stacking.
```

ML Candidate Selection is an admission gate, not a classifier. Model inference happens only after reconstruction, Burst segmentation, and feature validation.

**Flow Tracker boundary:** current FlowTracker already groups both directions under one Flow ID and retains client-relative direction and packet metadata. Future ML Reconstruction reuses this FlowState to validate/normalize an ML observation; it must not create a second Flow ID, regroup the tuple, or reassemble/decrypt application payload.

See [`../architecture/decision-ml-flow-order.md`](../architecture/decision-ml-flow-order.md) for the accepted decision and P1.0 scope.


## 1. Flow runtime chuẩn

Thứ tự dưới đây là chuẩn kiến trúc. Không hoán đổi DNS và SNI.

```text
1. Network Packet Capture
   Live interface hoặc PCAP
             |
             v
2. Packet Parsing & Flow Tracking
   Headers, timestamp, direction, 5-tuple / Flow ID, packet sequence
             |
             v
3. DNS Parser + DNS Cache
   Parse DNS Response; cache cập nhật liên tục
   Client ↔ QNAME/CNAME ↔ A/AAAA ↔ TTL/expiry
             |
             v
4. DNS-based Application Identification — FIRST
   Lookup client + destination IP + TTL; match Application Domain Rules
       | DNS_IDENTIFIED            | DNS_UNRESOLVED
       v                           v
   Return Application       5. TLS Parser + SNI Mapping — SECOND
   Stop; skip ML                   | SNI_IDENTIFIED       | SNI_UNRESOLVED
                                   v                      v
                              Return Application    6. ML Candidate Gate
                                                     ELIGIBLE / PENDING / REJECTED
                                                            |
                                                            v
                                              7. Immutable Flow Observation
                                                 (reuse existing Flow ID)
                                                            |
                                                            v
                                              8. Burst Segmentation
                                                   /          \
                                                  v            v
                                      Branch A: Statistics  Branch B: Sequence
                                           CatBoost              1D-CNN
                                                  \            /
                                                   v          v
                                              9. Late Fusion /
                                                 Stacking
                                                     |
                                                     v
                                         10. Application Classification
                                           Application label / UNKNOWN
```

**Diễn giải:** Candidate Gate chỉ nhận Flow chưa được DNS/SNI/QUIC nhận diện. Observation Adapter tái sử dụng Flow ID hiện có và tạo snapshot bất biến; không tự phân đoạn Burst hoặc gọi model. Burst Segmentation và CatBoost Flow V2 đã được nối vào finalization path; 1D-CNN và Fusion vẫn là target-only branches. Sơ đồ không có nhánh ML chạy song song với DNS/SNI.

## 2. Bảng chuyển trạng thái

| Giai đoạn | Điều kiện | Hành động tiếp theo |
|---|---|---|
| DNS identification | Mapping hợp lệ, domain đã xác minh, không ambiguous | `DNS_IDENTIFIED`; trả Application; dừng |
| DNS identification | Không có evidence hoặc evidence ambiguous | `DNS_UNRESOLVED`; gọi TLS/SNI |
| SNI identification | SNI hợp lệ và mapping đã xác minh | `SNI_IDENTIFIED`; trả Application; dừng |
| SNI identification | Không có SNI hoặc mapping chưa xác minh | `SNI_UNRESOLVED`; gọi ML Candidate Gate |
| ML Candidate Gate | DNS/SNI unresolved và explicit observation policy đạt điều kiện | `ELIGIBLE`; tạo immutable Flow observation |
| ML Candidate Gate | Chưa đủ observation hoặc policy chưa cấu hình | `PENDING`; chờ thêm dữ liệu/chính sách |
| ML Candidate Gate | DNS/SNI đã nhận diện hoặc metadata không hợp lệ | `REJECTED`; không gọi ML |
| Burst ML | Candidate `ELIGIBLE`, observation hợp lệ và đủ feature | Reconstruction → Segmentation → hai model |
| Application classification | Fusion đủ độ tin cậy | Trả application label |
| Application classification | Thiếu dữ liệu, model lỗi hoặc confidence dưới threshold | Trả `UNKNOWN` |

## 3. Module và trách nhiệm

| Module | Trách nhiệm | Không làm |
|---|---|---|
| Packet Capture | Cung cấp packet và timestamp | Không nhận diện app |
| Packet Parser | Parse header/protocol | Không quyết định app |
| Flow Tracker | Gom packet, xác định direction và Flow ID | Không chạy classifier |
| DNS Parser | Parse DNS response, question, RCODE, A/AAAA/CNAME | Không lưu cache dài hạn; không map app |
| DNS Cache | Cập nhật liên tục; lưu client/domain/IP/CNAME/TTL và nhiều candidate | Không tự kết luận Application; không dùng IP làm cache key duy nhất |
| DNS Identifier | Lookup theo client + destination IP + timestamp; match verified Domain Rules; resolve ambiguity | Không parse packet; không gọi SNI/ML |
| TLS/SNI Parser | Trích xuất ClientHello/SNI | Không tự map app nếu chưa qua mapping rules |
| SNI Identifier | Map SNI sang application | Không gọi ML |
| Bidirectional Reconstruction | Tạo chuỗi packet hai chiều theo Flow | Không thay đổi packet payload |
| Burst Segmenter | Chia packet sequence thành Burst | Không dự đoán app |
| CatBoost Branch | Dự đoán từ Burst Statistics | Không xử lý PCAP trực tiếp |
| 1D-CNN Branch | Dự đoán từ Burst Sequence | Không xử lý PCAP trực tiếp |
| Late Fusion | Hợp nhất output hai nhánh | Không tự tạo feature |
| Application Classifier | Áp dụng threshold/reject policy và trả kết quả | Không thay đổi evidence gốc |

## 4. Offline và runtime

Offline preparation tạo dataset và model artifacts. Runtime nhận packet, áp dụng cùng feature contract và nạp model artifacts đã huấn luyện. Dataset builder và runtime phải dùng cùng định nghĩa Flow/Burst/features.

## 5. Quy tắc nghiệp vụ

- BR-01: DNS luôn được đánh giá trước SNI.
- BR-02: SNI chỉ được đánh giá sau DNS unresolved.
- BR-03: ML chỉ nhận Flow unresolved sau cả DNS và SNI.
- BR-04: DNS/SNI identified kết thúc đường nhận diện của Flow.
- BR-05: Hai ML branch nhận dữ liệu được tạo từ cùng Flow/Burst observation.
- BR-06: Late Fusion chỉ chạy khi output của các branch đáp ứng input contract.
- BR-07: Kết quả cuối có thể là `UNKNOWN`.

## 6. Open decisions

Các thông số sau chưa được xác định trong sơ đồ và không được tự đặt:
- DNS/SNI confidence hoặc điều kiện mapping cụ thể ngoài tài liệu DNS.
- Runtime minimum observation timing (số packet/thời gian trước lần đánh giá Flow đầu tiên).
- Burst idle-gap threshold và cách xử lý đổi direction.
- Chiều dài sequence, padding/truncation và tensor shape cho 1D-CNN.
- CatBoost feature schema chính thức.
- Fusion algorithm, calibration và threshold.
- Thời điểm phát prediction: sau N packet, T giây hay khi Flow đóng.

## 7. Tiêu chí nghiệm thu

- [ ] Test chứng minh DNS được gọi trước SNI.
- [ ] Test chứng minh DNS identified không gọi SNI/ML.
- [ ] Test chứng minh SNI identified không gọi ML.
- [ ] Test unresolved cả hai mới gọi Burst ML.
- [ ] Test hai nhánh và fusion có thể truy vết theo cùng Flow ID.
- [ ] Test trả `UNKNOWN` khi thiếu input hoặc confidence không đạt.


## 8. UDP / QUIC evidence extension — historical P0.7.3 and current P0.7.4

The standalone P0.7.3 QUIC v1 Initial inspector was integrated in P0.7.4.
Current `PacketProcessor` sends UDP payloads through `UDPAnalyzer`, QUIC v1
Initial decryption, CRYPTO reassembly and TLS ClientHello/SNI mapping. QUIC
connection/CID state is distinct from the UDP pseudo-Flow lifecycle. This path
is shared by live capture and PCAP replay. See
`docs/architecture/p0.7.4-hybrid-tcp-udp-pipeline.md`.

## Current source-of-truth snapshot — 2026-11-27

### Runtime call path verified in source

`capture.live.SingleNICCapture._handle_packet()` and `capture.pcap.replay_pcap()` both call `PacketProcessor.process()`. PacketProcessor parses the packet, applies the selected LAN filter, updates DNS parser/cache state, expires UDP Flows when applicable, tracks the packet, then applies the rule-first order:

1. DNS identification; a DNS match returns immediately.
2. TCP ClientHello/SNI for unresolved TCP Flows.
3. UDP protocol analysis / QUIC Initial SNI for still-unresolved Flows.
4. On Flow finalization, Candidate Gate → FlowObservation → Burst segmentation → Flow-level feature aggregation → CatBoost inference, if a model was configured and the Flow was admitted.

A classified DNS/SNI/QUIC Flow is rejected by Candidate Gate and is not sent to ML. `compute_flow_statistics()` is a descriptive summary API and is not the CatBoost Flow V2 feature builder.

### Module contract/status

- **Packet capture/parsing** — Source: `capture/live.py`, `capture/pcap.py`, `packet/parser.py`, `pipeline/processor.py`. Implemented: single-NIC capture and PCAP replay share PacketProcessor. Integrated: yes. Tested: capture/parser unit tests and prior full-suite evidence. Status: `DONE`. Remaining: performance/resource profiling.
- **Flow tracking** — Source: `flow/identity.py`, `flow/tracker.py`, `domain/models.py`. Implemented: canonical bidirectional Flow identity, client-relative direction, UDP expiry/capacity, session close. Integrated: yes. Tested: `tests/unit/flow/`. Status: `DONE`. Remaining: TCP Flows do not idle-expire; session close finalizes them.
- **DNS** — Source: `dns/parser.py`, `cache.py`, `identifier.py`, `domain_rules.py`, `config/dns_mapping.yaml`. Implemented: correlated DNS responses, A/AAAA/CNAME, scoped TTL cache and domain mapping. Integrated: before SNI/QUIC, with early return on match. Tested: `tests/unit/dns/` and prior DNS acceptance records. Status: `DONE`. Remaining: encrypted DNS and shared-IP ambiguity.
- **TLS SNI** — Source: `sni/tcp_reassembly.py`, `tls_parser.py`, `identifier.py`. Implemented: bounded TCP reassembly and visible ClientHello/SNI mapping. Integrated: after DNS, only for unresolved TCP Flows. Tested: SNI unit/integration tests and historical live/PCAP evidence. Status: `DONE` within visible-SNI scope. Remaining: ECH/no-SNI/mid-stream visibility limits.
- **UDP/QUIC** — Source: `udp/analyzer.py`, `udp/protocol_identifier.py`, `udp/quic/*`. Implemented: UDP signatures and QUIC v1 Initial decrypt/CRYPTO/SNI. Integrated: after DNS/TCP SNI. Tested: QUIC unit/integration tests and historical PCAP/probe evidence. Status: `PARTIAL`. Remaining: no claim of general QUIC/HTTP3 decryption or comprehensive live coverage.
- **Candidate/Burst** — Source: `ml/candidate_gate.py`, `burst.py`, `burst_statistics.py`. Implemented: gate, immutable observation, reconstruction, direction/idle-gap segmentation, per-Burst statistics. Integrated: finalization path. Tested: `tests/unit/ml/` and PCAP Burst integration. Status: `DONE`.
- **CatBoost** — Source: `ml/flow_aggregation.py`, `ml/catboost_inference.py`, `pipeline/processor.py`. Implemented: 70 Flow features and ordered `predict_proba` inference. Integrated: after eligible Flow Burst creation when `ml_model_path` is configured. Tested: supplied live run 23 predictions / 0 inference errors; no dedicated CatBoost inference test file in this archive. Status: `DONE` for integration, `NOT VERIFIED` for quality. Remaining: ground-truth metrics, model-enabled PCAP evidence, final Flow export and profiling.

For current limitations and the complete test/evidence boundary see `../PROJECT_COMPLETION_ASSESSMENT_2026-11-26.md`.
