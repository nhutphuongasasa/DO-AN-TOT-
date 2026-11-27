# 05 — Burst-based ML Classification

## 1. Mục đích

Burst-based ML là nhánh fallback cuối cùng khi DNS và SNI đều không nhận diện được application. Nhánh này học hành vi traffic từ chuỗi packet hai chiều, không đọc payload.

## 2. Phạm vi

**Làm**
- Bidirectional Flow Reconstruction.
- Burst Segmentation.
- Branch A: Burst Statistics → CatBoost.
- Branch B: Burst Sequence → 1D-CNN.
- Late Fusion / Stacking.
- Application label hoặc `UNKNOWN`.

**Không làm**
- Không chạy nếu DNS hoặc SNI đã identified.
- Không tự parse PCAP.
- Không thay đổi Flow ID hoặc evidence DNS/SNI.
- Không tự quyết định ngưỡng khi chưa có thí nghiệm.

## 3. Phụ thuộc

- Input từ Flow Tracker: Flow ID, packet timestamps, lengths và direction.
- DNS/SNI Identification phải trả unresolved trước khi ML branch được gọi.
- Feature schema từ `07-feature-engineering.md`.
- Training/evaluation contract từ `08-model-training-and-evaluation.md`.

## 4. Luồng xử lý

1. Nhận Flow có `DNS_UNRESOLVED` và `SNI_UNRESOLVED`.
2. Bidirectional Flow Reconstruction sắp xếp packet sequence theo Flow, giữ forward/backward direction.
3. Burst Segmentation chia packet sequence thành Burst: direction change luôn tạo boundary; idle-gap vượt ngưỡng được cấu hình cũng tạo boundary. Không hard-code numeric idle-gap default.
4. Tạo Burst Statistics cho Branch A.
5. Tạo Burst Sequence cho Branch B.
6. Chạy CatBoost và 1D-CNN trên cùng observation/Flow.
7. Late Fusion / Stacking hợp nhất hai model outputs.
8. Application Classification áp dụng confidence/reject policy.
9. Trả application label hoặc `UNKNOWN`.

## 5. Input / Output

**Input packet record tối thiểu**
- `flow_id`
- `timestamp`
- `direction`
- `packet_length`

**Burst record logic**
- `burst_id`, `flow_id`, `start_ts`, `end_ts`
- `direction`
- `packet_count`, `total_bytes`
- ordered packet lengths/timestamps
- `burst_index`, `inter_burst_gap` nếu định nghĩa

**Output**
- Branch A: CatBoost class scores/probabilities.
- Branch B: 1D-CNN class scores/probabilities.
- Fusion: final class scores.
- Classifier: application hoặc `UNKNOWN`.

Tensor shape, feature order và exact output schema phải được chốt trong feature/model contract trước khi code.

## 6. Quy tắc nghiệp vụ

- BR-01: ML chỉ nhận Flow unresolved bởi DNS và SNI.
- BR-02: Reconstruction phải giữ Flow ID và hai chiều.
- BR-03: Burst chỉ chứa packet thuộc cùng Flow.
- BR-04: Packet sequence phải có thứ tự thời gian xác định.
- BR-11: Direction change (FORWARD/BACKWARD/UNKNOWN) luôn bắt đầu Burst mới; các packet UNKNOWN liên tiếp có thể nằm cùng một Burst UNKNOWN.
- BR-12: Idle-gap là boundary bổ sung khi caller cấu hình ngưỡng; `None` tắt boundary này, không ngầm áp dụng numeric default.
- BR-05: Cùng observation phải tạo input tương ứng cho cả hai branch.
- BR-06: Branch A sử dụng Burst Statistics với CatBoost.
- BR-07: Branch B sử dụng Burst Sequence với 1D-CNN.
- BR-08: Hai branch được hợp nhất bằng Late Fusion / Stacking.
- BR-09: Không tự giả định fusion là average, voting hay meta-learner; thuật toán phải được chốt.
- BR-10: Insufficient data hoặc confidence dưới threshold trả `UNKNOWN`.

## 7. Lỗi và trường hợp biên

| Tình huống | Hành vi |
|---|---|
| Flow chỉ có một chiều | Reconstruction vẫn tạo sequence; thiếu direction được biểu diễn rõ |
| Flow quá ít packet | Không tạo prediction; trả insufficient-data/UNKNOWN |
| Timestamp không hữu hạn | Observation adapter từ chối metadata không hợp lệ |
| Timestamp trùng | Deterministic tie-break bằng packet_index |
| Burst không có packet | Không gọi model |
| Một model artifact thiếu | Fusion không giả vờ có đủ hai output; áp dụng policy fallback đã cấu hình hoặc UNKNOWN |
| Model schema mismatch | Không inference; báo model/schema incompatibility |
| Hai model dự đoán khác nhau | Ghi conflict; fusion policy xử lý rõ ràng |

## 8. File/hàm chính

- `ml/train_flow.py`, `ml/train_device.py`, `ml/predictor.py`: tồn tại trong snapshot, nhưng tài liệu cũ mô tả baseline Flow/Device; không mặc định đây là CatBoost/1D-CNN branch.
- `appid.ml.burst`: Bidirectional Flow Reconstruction adapter và Burst Segmentation đã triển khai trong P1.1.
- CatBoost/1D-CNN runtime paths: chưa triển khai.
- Coding Agent phải kiểm tra source và tái sử dụng implementation phù hợp trước khi thêm file.

## 9. Tiêu chí nghiệm thu

- [ ] Flow DNS/SNI identified không vào ML.
- [ ] Flow unresolved được reconstruction hai chiều.
- [ ] Burst không trộn packet từ Flow khác.
- [ ] Branch A nhận đúng Burst Statistics.
- [ ] Branch B nhận đúng Burst Sequence.
- [ ] Hai branch output có cùng class ordering.
- [ ] Fusion được kiểm thử với output thật từ hai branch.
- [ ] Thiếu dữ liệu/schema/model không tạo nhãn giả.

## 10. Ví dụ

Flow chưa được DNS hoặc SNI nhận diện được chuyển vào ML. Packet sequence của Flow được tái tạo hai chiều, chia thành Burst. CatBoost dự đoán từ thống kê Burst; 1D-CNN dự đoán từ chuỗi Burst. Late Fusion hợp nhất hai kết quả và trả `youtube` hoặc `UNKNOWN` tùy policy đã cấu hình.

## Runtime ordering and admission gate

Only Flow unresolved by both DNS and SNI can enter **ML Candidate Selection**. Candidate selection is an admission gate, not a classifier. Eligible candidates are then passed to ML-specific Bidirectional Flow Reconstruction, Burst Segmentation, and feature extraction. Only after those stages do CatBoost and 1D-CNN run.

The ML reconstruction adapter reuses the FlowTracker's existing Flow ID and client-relative direction; it does not create a duplicate Flow identity. Both branches must consume the same Flow observation and Burst lineage (`session_id → flow_id → burst_index`).

Minimum observation requirements, Burst idle-gap threshold, direction-change boundary behavior, and duplicate handling remain OPEN. Do not invent defaults before recording a decision in `14-implementation-parameters.md`.

## P1.3 — Burst statistics and sequence schema

Schema versions are explicitly recorded as `1.0` for Burst statistics, Flow
statistics and Burst sequences. All timestamps and durations are seconds;
packet lengths and byte totals use the packet lengths supplied by the parser
(bytes), not application payload lengths. No payload is inspected.

### Burst statistics

`compute_burst_statistics()` produces packet count/bytes, packet-length
minimum/maximum/mean/median/population-standard-deviation, within-Burst
inter-arrival-time minimum/maximum/mean/population-standard-deviation, and
packet/byte counts split into FORWARD, BACKWARD and UNKNOWN. Population
standard deviation uses `ddof=0`. For a one-packet Burst, IAT statistics are
`null` because no adjacent-packet interval exists. Packet-length standard
deviation is `0.0` for a one-packet Burst.

### Flow statistics

`compute_flow_statistics()` aggregates a non-empty set of Bursts with the same
`session_id` and `flow_id`. It rejects duplicate burst indexes and mixed Flow
lineage. Flow duration spans the earliest Burst start to the latest Burst end.
Inter-Burst gap summaries ignore the first Burst's null gap and any other null
values; if no gap is available, the summaries are `null`.

### Burst sequence

`build_burst_sequence()` orders by `burst_index`, preserves each Burst's
chronological packet order, and emits per-Burst direction, duration, packet
count, bytes, inter-Burst gap, packet lengths and timestamps. It rejects empty
input, mixed Flow lineage and duplicate Burst indexes. It does not pad or
truncate sequences; model-specific tensor sizing belongs to a later model
contract and must be chosen using training data.

### Direction semantics

Direction statistics count packet directions independently of the Burst's
representative direction. UNKNOWN remains a first-class category and is never
folded into FORWARD or BACKWARD. These statistics describe the observations;
they are not application labels or training targets.

## Current source implementation — 2026-11-27

### Module name: Candidate gate and Burst segmentation

**Source files**
- `src/appid/ml/candidate_gate.py`
- `src/appid/ml/burst.py`
- `src/appid/ml/burst_statistics.py`
- `src/appid/ml/burst_output.py`
- Integration: `src/appid/pipeline/processor.py`

**Implemented**
Candidate Gate rejects already-classified Flows and unsupported transport; leaves empty/incomplete/under-policy observations pending or invalid metadata rejected. Default runtime policy is at least 2 packets and 0 seconds minimum duration. `FlowObservationAdapter` creates immutable, payload-free packet metadata. Burst segmentation sorts by timestamp/index and splits at every direction change; optional idle-gap boundary defaults to 0.5 seconds in PacketProcessor. Consecutive UNKNOWN packets remain separate from known direction runs. Burst statistics include packet lengths, IAT, directional counts/bytes and inter-Burst gap.

**Integrated**
`_finalize_flows()` evaluates each Flow once. Only eligible unresolved Flows are reconstructed and segmented. If CatBoost is configured, those Bursts are passed to Flow-level feature aggregation and inference.

**Tested**
`tests/unit/ml/test_candidate_gate.py`, `test_burst.py`, `test_burst_statistics.py`, `test_burst_sequence.py`; `tests/integration/test_pcap_burst_pipeline.py`.

**Status**
`DONE`.

**Remaining**
Burst JSONL/TSV output contains Burst metadata, not final Flow prediction records. `compute_flow_statistics()` is not the CatBoost V2 feature aggregation function.
