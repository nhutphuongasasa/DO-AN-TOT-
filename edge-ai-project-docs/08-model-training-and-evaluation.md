# 08 — Huấn luyện và đánh giá mô hình

## 1. Mục đích

Huấn luyện và đánh giá CatBoost, 1D-CNN và Late Fusion / Stacking trên dataset Burst đã version hóa.

## 2. Phạm vi

- Train Branch A CatBoost từ Burst Statistics.
- Train Branch B 1D-CNN từ Burst Sequence.
- Train/fit fusion stage bằng validation data.
- Đánh giá application classification và reject/unknown policy.

Flow/Device LightGBM scripts hiện có được xem là baseline cũ, không tự đổi tên thành CatBoost/1D-CNN.

## 3. Phụ thuộc

- Dataset từ `06-data-collection-and-labeling.md`.
- Feature contract từ `07-feature-engineering.md`.
- Class mapping và split metadata.
- Model artifacts được runtime loader sử dụng.

## 4. Luồng xử lý

1. Khóa dataset version và label mapping.
2. Tạo group split theo session/batch.
3. Train CatBoost với Branch A features.
4. Train 1D-CNN với Branch B sequence.
5. Lấy output dự đoán trên validation split.
6. Fit Late Fusion / Stacking theo thuật toán đã chọn.
7. Tune confidence/reject threshold chỉ trên validation.
8. Đánh giá một lần trên test holdout.
9. Lưu models, calibrators, configs và reports.

## 5. Input / Output

| Thành phần | Input | Output |
|---|---|---|
| CatBoost | Burst Statistics + label | CatBoost artifact + class scores |
| 1D-CNN | Burst Sequence + label | CNN artifact + class scores |
| Fusion | Validation outputs từ hai model | Fusion artifact/config |
| Evaluation | Test labels và final predictions | Metrics, confusion matrix, per-class report |

## 6. Quy tắc nghiệp vụ

- BR-01: Mọi Burst của cùng Flow nằm cùng split.
- BR-02: Ưu tiên group split theo session/batch.
- BR-03: Không fit fusion hoặc calibration trên test set.
- BR-04: Hai model dùng cùng class order.
- BR-05: Báo cáo Macro F1, weighted F1, per-class precision/recall/F1 và confusion matrix.
- BR-06: Báo cáo unknown/reject rate nếu có reject policy.
- BR-07: Lưu dataset hash, schema version, seed, split IDs và model config.
- BR-08: Không tuyên bố Burst tốt hơn baseline chỉ từ một lần chạy.
- BR-09: Không coi confidence là xác suất đáng tin cậy nếu chưa calibration/evaluation.

## 7. Lỗi và trường hợp biên

| Tình huống | Hành vi |
|---|---|
| Class thiếu sample | Báo rõ; không che bằng accuracy tổng |
| Split leakage | Hủy kết quả và tạo split lại |
| Model class order khác | Không chạy fusion |
| Model artifact thiếu | Đánh dấu run không hoàn chỉnh |
| Fusion overfit | Chỉ chọn cấu hình trên validation; test giữ độc lập |
| Test metrics dao động | Báo theo split/session; không chọn test để tune |

## 8. File/hàm chính

- `ml/train_flow.py`, `ml/train_device.py`, `ml/evaluate.py`, `ml/predictor.py`: có trong snapshot; README cũ mô tả baseline Flow/Device.
- `ml/models/flow/label_encoder.json`: classes `chatgpt`, `facebook`, `other-web`, `spotify`, `tiktok`, `youtube`.
- `ml/data/meta.json`: snapshot ghi `total_flow_windows=25263`, `total_device_windows=736`, `total_sequences=3460`; `window_flow_seconds=5.0`, `window_device_seconds=30.0`.
- CatBoost/1D-CNN/Fusion training scripts: chưa được xác nhận trong snapshot.

## 9. Tiêu chí nghiệm thu

- [ ] Hai model train từ đúng feature branch.
- [ ] Class order giống nhau.
- [ ] Fusion train chỉ trên validation predictions.
- [ ] Test set không tham gia tuning.
- [ ] Có per-class metrics và confusion matrix.
- [ ] Artifacts có model version và feature schema version.
- [ ] Training run tái lập được từ config và seed.

## 10. Ví dụ

Một training run tạo CatBoost artifact, 1D-CNN artifact và fusion artifact. Runtime nạp cả ba artifacts có cùng class mapping/schema; nếu một artifact thiếu hoặc không tương thích, prediction không được coi là hợp lệ.


## 11. Framework và contract

- Framework cho 1D-CNN: **PyTorch**.
- Tensor layout, sequence length, feature/channel order, padding, truncation và normalization vẫn là OPEN; xem `14-implementation-parameters.md`.
- Interface module: `13-module-contracts.md`.
