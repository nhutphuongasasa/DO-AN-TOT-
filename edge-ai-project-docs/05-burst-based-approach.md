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
3. Burst Segmentation chia packet sequence thành Burst theo boundary rule đã cấu hình.
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
| Timestamp thiếu hoặc trùng | Áp dụng deterministic ordering policy; ghi lỗi dữ liệu |
| Burst không có packet | Không gọi model |
| Một model artifact thiếu | Fusion không giả vờ có đủ hai output; áp dụng policy fallback đã cấu hình hoặc UNKNOWN |
| Model schema mismatch | Không inference; báo model/schema incompatibility |
| Hai model dự đoán khác nhau | Ghi conflict; fusion policy xử lý rõ ràng |

## 8. File/hàm chính

- `ml/train_flow.py`, `ml/train_device.py`, `ml/predictor.py`: tồn tại trong snapshot, nhưng tài liệu cũ mô tả baseline Flow/Device; không mặc định đây là CatBoost/1D-CNN branch.
- Burst reconstruction/segmenter và CatBoost/1D-CNN runtime paths: chưa xác định được từ snapshot.
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
