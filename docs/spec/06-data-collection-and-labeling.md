# 06 — Thu thập dữ liệu và gán nhãn

## 1. Mục đích

Tạo PCAP và label session để huấn luyện, validation và test hai nhánh Burst ML. Dataset phải giữ quan hệ session → Flow → Burst để tránh leakage.

## 2. Phạm vi

- Thu PCAP từ thiết bị thử nghiệm.
- Ghi session metadata và app activity timeline.
- Gán nhãn theo khoảng START/END hoặc event timeline.
- Kiểm tra chất lượng và chia split theo session.

Không gán label dựa trên dự đoán của model.

## 3. Phụ thuộc

- Capture source và packet pipeline.
- Flow Tracking để gắn packet vào Flow.
- Burst Segmentation để tạo Burst samples.
- Training pipeline trong `08-model-training-and-evaluation.md`.

## 4. Luồng xử lý

1. Tạo session ID.
2. Ghi thiết bị, OS, interface, subnet, điều kiện mạng và app version nếu biết.
3. Bắt đầu capture trước khi mở app.
4. Ghi START khi bắt đầu hành vi thử nghiệm.
5. Thực hiện hành vi đại diện của app.
6. Ghi END khi dừng hành vi.
7. Dừng capture và lưu PCAP.
8. Kiểm tra PCAP, timestamps và labels.
9. Build Flow/Burst dataset; giữ `session_id` và `flow_id`.
10. Chia train/validation/test theo session hoặc batch.

## 5. Input / Output

| Dữ liệu | Trường |
|---|---|
| PCAP | Packet records và timestamp |
| Label event | `session_id`, `application`, `event`, `timestamp` |
| Session metadata | `session_id`, `batch_id`, device, OS, interface, subnet, network conditions |
| Dataset row | `session_id`, `flow_id`, `burst_id` nếu là Burst sample, label, feature values |

README cũ đề cập `tools/capture_session.py` tạo PCAP, labels JSONL và session JSON; cần kiểm tra format thực tế trước khi thay đổi.

## 6. Quy tắc nghiệp vụ

- BR-01: Mỗi lần thu thập có `session_id` riêng.
- BR-02: Capture bắt đầu trước thao tác app.
- BR-03: Mọi Flow/Burst sample phải giữ nguồn session.
- BR-04: Tất cả Burst của cùng Flow nằm cùng split.
- BR-05: Ưu tiên group split theo session/batch.
- BR-06: Flow cắt qua biên START/END phải theo label policy; không tự gán nếu không chắc.
- BR-07: Không dùng test set để chọn threshold hoặc hyperparameter.
- BR-08: Nhiều Flow từ một PCAP không được tính là nhiều session độc lập.

## 7. Lỗi và trường hợp biên

| Tình huống | Hành vi |
|---|---|
| PCAP rỗng/hỏng | Loại session và ghi lý do |
| Label timestamp sai | Không build sample liên quan |
| Flow cắt qua START/END | Áp dụng policy đã định nghĩa hoặc loại sample |
| Nhiều app chạy đồng thời | Ghi overlap; không ép label đơn |
| Traffic nền/update | Gán lớp nền chỉ khi định nghĩa label rõ |
| Một app chỉ có một session | Không tuyên bố generalization cho app đó |

## 8. File/hàm chính

- `tools/capture_session.py`: được README cũ nhắc đến; xác minh có trong repository trước khi dùng.
- `test_ml_dataset_builder.py`: có trong snapshot.
- `ml/data/meta.json`: lưu batch IDs, class names và số lượng sample trong snapshot.

## 9. Tiêu chí nghiệm thu

- [ ] PCAP đọc được và có packet.
- [ ] Timestamp và label cùng time basis.
- [ ] Session metadata đầy đủ trường đã biết.
- [ ] Không có sample thiếu session/Flow linkage.
- [ ] Split không chia Burst của cùng Flow qua nhiều tập.
- [ ] Dataset version/hash được lưu.

## 10. Ví dụ

Một session ghi nhận thao tác xem YouTube từ START đến END. Dataset builder gắn packet vào Flow, tạo Burst và giữ cùng `session_id`/`flow_id` cho mọi sample phát sinh.
