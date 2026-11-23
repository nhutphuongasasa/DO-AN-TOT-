# 02 — Network Packet Capture và Packet Parsing

## 1. Mục đích

Nhận packet từ live interface hoặc PCAP, parse metadata cần thiết và chuyển packet vào Flow Tracking. Cả hai nguồn phải dùng chung packet-processing path.

## 2. Phạm vi

**Làm**
- Live capture và offline PCAP replay.
- Giữ timestamp gốc của packet.
- Parse Ethernet/IP/TCP/UDP header cần cho Flow.
- Nhận diện DNS và TLS/QUIC packet để chuyển parser tương ứng.

**Không làm**
- Không tự nhận diện application.
- Không tự tạo DNS/SNI mapping.
- Không tính CatBoost/1D-CNN prediction.

## 3. Phụ thuộc

- Scapy được khai báo trong `requirements.txt`.
- Packet Capture gọi Packet Parser.
- Packet Parser chuyển packet metadata sang Flow Tracker và protocol parsers.

## 4. Luồng xử lý

1. Chọn nguồn: live interface hoặc PCAP.
2. Nhận packet và giữ capture timestamp.
3. Kiểm tra packet có Ethernet/IP và TCP/UDP hay không.
4. Parse địa chỉ, port, protocol, packet length và transport metadata.
5. Chuyển DNS packet sang DNS Parser.
6. Chuyển packet vào Flow Tracker để gán Flow ID và direction.
7. Chuyển TLS/QUIC candidate packet sang parser tương ứng khi cần.
8. Không để lỗi parser phụ làm dừng capture/Flow tracking.

## 5. Input / Output

| Object | Trường tối thiểu |
|---|---|
| Input packet | Raw packet + capture timestamp |
| ParsedPacket | `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `packet_length`, `transport_flags` |
| Output | ParsedPacket hoặc trạng thái `UNSUPPORTED` / `PARSE_ERROR` |

Tên class và kiểu Python chính thức phải khớp implementation; bảng trên là contract logic.

## 6. Quy tắc nghiệp vụ

- BR-01: Live capture và PCAP replay dùng chung parser/processing path.
- BR-02: Không thay timestamp capture bằng thời điểm parser xử lý.
- BR-03: Packet không hỗ trợ không được đưa vào Flow như packet hợp lệ.
- BR-04: DNS/TLS parser failure không được làm mất packet khỏi Flow statistics nếu header transport vẫn hợp lệ.
- BR-05: Không lưu payload nhạy cảm vào log.

## 7. Lỗi và trường hợp biên

| Tình huống | Hành vi |
|---|---|
| Packet thiếu IP/TCP/UDP | Bỏ qua khỏi flow pipeline; ghi counter nếu cần |
| Packet malformed | Đánh dấu parse error; tiếp tục capture |
| PCAP rỗng | Báo input rỗng; không tạo prediction |
| Interface không tồn tại/không có quyền | Dừng capture và trả lỗi cấu hình rõ ràng |
| TLS ClientHello chia nhiều TCP segment | Chuyển đủ stream data cho TLS reassembly/parser |
| DNS parser lỗi | Flow tracking vẫn tiếp tục |

## 8. File/hàm chính

- `requirements.txt`: khai báo dependency Scapy.
- Runtime capture/parser path: **chưa xác định được đường dẫn source trong snapshot tài liệu**; Coding Agent phải tìm entrypoint hiện hữu trước khi tạo file mới.
- Không tạo thêm `capture/main.py` hoặc class mới nếu repository đã có implementation tương đương.

## 9. Tiêu chí nghiệm thu

- [ ] Cùng PCAP chạy hai lần cho cùng số packet parse được.
- [ ] Timestamp output khớp timestamp trong PCAP.
- [ ] Packet TCP/UDP được parse đúng 5-tuple.
- [ ] Packet lỗi parser không làm dừng xử lý các packet sau.
- [ ] Live và PCAP path gọi cùng packet-processing function.

## 10. Ví dụ

Một packet TCP từ `192.168.1.10:51000` đến `142.1.1.1:443` được parse thành metadata gồm source/destination IP, port, protocol TCP, timestamp và packet length; sau đó chuyển sang Flow Tracker.
