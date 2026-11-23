# 08 – Huấn luyện và đánh giá mô hình

## 1. Baseline hiện tại

README mô tả:
- LightGBM per-flow (`ml/train_flow.py`);
- LightGBM per-device (`ml/train_device.py`);
- LOSO cross-validation;
- isotonic calibration;
- evaluation report, confusion matrix và F1 per class.

Kết quả trao đổi gần đây: Macro F1 baseline khoảng 53%, chưa đạt kỳ vọng. Khi ghi vào báo cáo, phải trích đúng file kết quả và cấu hình lần chạy; không dùng một con số tách khỏi ngữ cảnh.

## 2. Vì sao accuracy chưa đủ?

Dataset có thể mất cân bằng. Accuracy cao vẫn có thể che giấu việc mô hình không nhận diện được một số app. Nên báo cáo:
- Macro F1;
- weighted F1;
- precision/recall/F1 từng lớp;
- confusion matrix;
- số mẫu mỗi lớp;
- unknown/reject rate nếu có;
- latency và RAM khi inference.

## 3. Chia tập dữ liệu

Không random split từng row nếu các row đến từ cùng flow hoặc cùng session.

Ưu tiên:
- group theo session/batch;
- giữ mọi window/burst của một flow trong cùng split;
- validation dùng để chọn threshold/hyperparameter;
- test giữ độc lập đến cuối.

Nếu dùng LOSO, cần đủ số session độc lập để mỗi fold có ý nghĩa. Một session duy nhất cho app không đủ để chứng minh generalization.

## 4. So sánh công bằng

So sánh Flow-only, Burst-only và Flow+Burst phải dùng:
- cùng danh sách session;
- cùng label policy;
- cùng group split;
- cùng metric;
- cùng quy tắc loại sample;
- ghi rõ seed và config.

Không tối ưu Burst trên test set.

## 5. Calibration và confidence

Calibration không tự làm mô hình phân loại đúng hơn; nó điều chỉnh mức confidence dự đoán. Cần đánh giá calibration trên validation độc lập và tránh fit calibration trên test.

Không dùng confidence như xác suất đáng tin cậy nếu chưa kiểm tra calibration.

## 6. Ablation study

Các câu hỏi cần trả lời:
- Bỏ `dest_port` thì kết quả đổi thế nào?
- Chỉ dùng packet size/time có đủ không?
- Thêm DNS/TLS metadata có cải thiện không?
- Burst features có bổ sung tín hiệu so với Flow không?
- Model có phụ thuộc quá nhiều vào một session hoặc một thiết bị không?

## 7. Artifact cần lưu cho mỗi lần train

- dataset version/hash;
- label mapping;
- feature schema version;
- train/validation/test session IDs;
- model config và random seed;
- model artifact;
- metrics JSON;
- confusion matrix;
- per-class report;
- calibration artifact;
- ngày chạy và commit hash.

## 8. Điều kiện kết luận

Không kết luận “Burst tốt hơn” chỉ vì một lần chạy có F1 cao hơn. Cần kết quả ổn định qua nhiều split/session và xem cả per-class, latency, tài nguyên.
