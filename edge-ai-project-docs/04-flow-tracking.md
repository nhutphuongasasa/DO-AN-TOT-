# 04 — Packet Parsing, Flow Tracking và Bidirectional Flow

## 1. Mục đích

Flow Tracker gom packet thành Flow logic, giữ packet sequence và direction để DNS/SNI enrichment cũng như Burst ML sử dụng.

## 2. Phạm vi

**Làm:** canonical Flow key, Flow ID, client/remote endpoint, direction, timestamp, packet sequence và lifecycle.

**Không làm:** không quyết định application; không tự phân đoạn Burst; không chạy model.

## 3. Phụ thuộc

- Nhận ParsedPacket từ Packet Parsing.
- Cung cấp Flow và packet sequence cho DNS/SNI identification và ML branch.
- Bidirectional Flow Reconstruction ở bước 7 dùng packet sequence hai chiều đã gắn Flow ID.

## 4. Luồng xử lý

1. Nhận ParsedPacket.
2. Xác định LAN/client endpoint theo cấu hình mạng.
3. Tạo canonical key không phụ thuộc chiều packet.
4. Tìm hoặc tạo FlowState.
5. Gán direction `forward` hoặc `backward`.
6. Cập nhật packet count, bytes, timestamp và packet sequence.
7. Gắn DNS/TLS metadata khi parser cung cấp.
8. Đóng Flow theo lifecycle/timeout đã cấu hình.
9. Giữ Flow record đủ lâu để downstream consumer hoàn tất.

## 5. Input / Output

**5-tuple**

`(src_ip, src_port, dst_ip, dst_port, protocol)`

**Flow output logic**
- `flow_id`
- `canonical_5tuple`
- `client_endpoint`
- `remote_endpoint`
- `first_seen`, `last_seen`
- `packets_forward`, `packets_backward`
- `bytes_forward`, `bytes_backward`
- ordered packet metadata: timestamp, direction, packet length

Ví dụ hai chiều:
- `10.0.0.5:51000 → 142.1.1.1:443 TCP`: forward.
- `142.1.1.1:443 → 10.0.0.5:51000 TCP`: backward.

## 6. Quy tắc nghiệp vụ

- BR-01: Hai chiều của cùng kết nối thuộc một Flow.
- BR-02: Direction được xác định tương đối với client/LAN endpoint, không dựa đơn thuần vào packet đầu tiên.
- BR-03: Flow ID ổn định trong một capture session.
- BR-04: Packet order được giữ theo timestamp capture; packet out-of-order phải được xử lý có quy tắc.
- BR-05: Idle timeout hiện được tài liệu cũ ghi là `120s`; phải xác minh với runtime config trước khi coi là giá trị chuẩn.
- BR-06: Tuple reuse sau khi Flow đóng không được trộn vào Flow cũ.
- BR-07: Feature window 5 giây (nếu còn dùng) không đồng nghĩa Flow idle timeout.
- BR-08: ML chỉ nhận Flow sau khi DNS và SNI đều unresolved.

## 7. Lỗi và trường hợp biên

| Tình huống | Hành vi |
|---|---|
| Server packet đến trước | Xác định endpoint bằng LAN/subnet config |
| Capture bắt đầu giữa Flow | Tạo Flow partial; không giả định thấy SYN |
| Out-of-order packet | Giữ timestamp; reconstruction xử lý theo policy |
| Duplicate packet | Không tự loại nếu chưa có duplicate policy |
| Timeout | Finalize Flow và giữ output cho consumer |
| Tuple reuse | Tạo Flow ID mới |
| Nhiều client tới cùng server | Tạo Flow riêng theo endpoint tuple |

## 8. File/hàm chính

- Runtime Flow Tracker path: cần tìm trong source repository; không có đường dẫn implementation được xác nhận trong snapshot.
- `ml/features.py`: README cũ mô tả Flow feature extraction tại đây; kiểm tra source trước khi thay contract.
- Không tạo module mới nếu Flow Tracker hiện hữu đã đáp ứng contract.

## 9. Tiêu chí nghiệm thu

- [ ] Hai chiều cùng connection có cùng Flow ID.
- [ ] Direction forward/backward đúng với client endpoint.
- [ ] Server-first capture không đảo direction.
- [ ] Tuple reuse tạo Flow ID mới.
- [ ] Flow không mất trước khi Burst pipeline đọc xong.
- [ ] Replay PCAP cho cùng cấu hình tạo Flow grouping ổn định.

## 10. Ví dụ

Một TCP connection có packet client→server và server→client. Flow Tracker gom cả hai vào cùng Flow ID, đánh dấu từng packet direction và chuyển packet sequence sang bước Bidirectional Flow Reconstruction.
