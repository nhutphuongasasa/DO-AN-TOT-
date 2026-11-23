# 07 — Feature Engineering

## 1. Mục đích

Định nghĩa input contract cho CatBoost và 1D-CNN. Feature extraction phải giống nhau giữa offline training và runtime inference.

## 2. Phạm vi

- Branch A: thống kê theo Burst.
- Branch B: chuỗi Burst có thứ tự.
- Chuẩn hóa class order, missing values và schema version.

Không tự thêm feature chưa có định nghĩa hoặc thay đổi feature order mà không version bump.

## 3. Phụ thuộc

- Input packet sequence từ Bidirectional Flow Reconstruction.
- Burst records từ Burst Segmentation.
- Output được tiêu thụ bởi CatBoost và 1D-CNN.
- Training/evaluation theo `08-model-training-and-evaluation.md`.

## 4. Luồng xử lý

1. Nhận packet records đã gắn Flow ID và direction.
2. Tái tạo thứ tự hai chiều.
3. Phân đoạn Burst theo boundary config.
4. Tính Burst Statistics cho CatBoost.
5. Encode Burst Sequence cho 1D-CNN.
6. Áp dụng missing-value, padding/truncation và scaling policy đã chốt.
7. Kiểm tra schema version và feature order trước inference.

## 5. Input / Output

**Burst Statistics — feature candidates**
- `burst_count`
- `packet_count`
- `bytes_total`
- `duration`
- `iat_mean`, `iat_std`
- packet length statistics
- direction distribution
- inter-burst time statistics

Các trường này được suy ra từ nhãn Branch A trong sơ đồ; danh sách cột và công thức chính thức cần được khóa trước training.

**Burst Sequence — input logic**
- ordered Burst records
- burst direction
- burst duration
- inter-burst time
- packet direction/size sequence nếu được chọn trong sequence schema

Tensor dimensions và maximum sequence length hiện chưa được cung cấp.

## 6. Quy tắc nghiệp vụ

- BR-01: Feature chỉ dùng thông tin đã quan sát tại thời điểm dự đoán.
- BR-02: Offline và runtime dùng chung implementation/schema.
- BR-03: CatBoost input là Burst Statistics.
- BR-04: 1D-CNN input là Burst Sequence.
- BR-05: Cả hai branch dùng cùng label mapping/class order.
- BR-06: Feature order được version hóa.
- BR-07: Không đưa label, session name hoặc future metadata vào model features.
- BR-08: Không tự đặt sequence length, padding hoặc normalization khi chưa có quyết định.

## 7. Lỗi và trường hợp biên

| Tình huống | Hành vi |
|---|---|
| Flow không có Burst | Không tạo sample |
| Burst chỉ có một packet | IAT fields theo missing-value policy |
| Duration bằng 0 | Không chia cho 0 |
| Thiếu direction | Đánh dấu missing/unknown theo schema |
| Sequence dài hơn giới hạn | Áp dụng truncation policy đã chốt |
| Sequence ngắn hơn giới hạn | Áp dụng padding policy đã chốt |
| Schema mismatch | Dừng inference và báo lỗi |

## 8. File/hàm chính

- `ml/features.py`: README cũ mô tả Flow features 24 cột; giữ riêng làm baseline nếu còn được dùng.
- Burst feature extractor và sequence encoder: chưa xác định path trong snapshot.
- `ml/tests/test_features.py`: có trong snapshot; kiểm tra nội dung trước khi mở rộng.

## 9. Tiêu chí nghiệm thu

- [ ] Feature schema có version.
- [ ] Mỗi feature có tên, kiểu, đơn vị và công thức.
- [ ] Cùng input tạo cùng output offline/runtime.
- [ ] CatBoost nhận đúng vector Burst Statistics.
- [ ] 1D-CNN nhận tensor đúng shape đã khóa.
- [ ] Missing value và padding được test.

## 10. Ví dụ

Một Flow có ba Burst. Extractor tạo một vector thống kê tổng hợp cho CatBoost và một chuỗi ba Burst theo đúng thứ tự cho 1D-CNN. Hai input giữ cùng `flow_id` và label.


## 11. Contract liên module

- Giữ `session_id`, `flow_id` và `burst_index` khi áp dụng.
- Branch A nhận Burst Statistics; Branch B nhận Burst Sequence.
- Hai branch dùng chung class mapping/order.
- Tensor layout/sequence dimensions chưa được giả định; xem `14-implementation-parameters.md`.
- Interfaces: `13-module-contracts.md`.
