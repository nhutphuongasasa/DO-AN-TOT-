# 02 – Luồng xử lý packet khi chạy

## 1. Nguồn packet

Hai chế độ được README mô tả:

- `LiveSource`: Scapy sniff từ interface, BPF filter mặc định `tcp or udp`.
- `PcapSource`: đọc PCAP để replay offline.

Cả hai nên đưa packet vào cùng một hàm xử lý lõi để giảm khác biệt giữa test offline và live.

## 2. Trình tự xử lý đề xuất

1. Nhận packet và giữ timestamp gốc.
2. Kiểm tra lớp Ethernet/IP và loại packet hỗ trợ.
3. Xác định LAN endpoint, client IP và MAC nếu quan sát được.
4. Nếu là DNS, parse response và cập nhật DNS cache.
5. Chuẩn hóa 5-tuple và xác định hướng packet.
6. Cập nhật FlowState và thống kê.
7. Nếu packet thuộc TLS/QUIC handshake và chưa inspect, thử trích xuất metadata.
8. Gửi metadata và trạng thái flow sang Rule Engine.
9. Nếu Rule Engine chưa đủ tin cậy, chỉ gọi ML khi cửa sổ dữ liệu đủ điều kiện.
10. Tổng hợp theo thiết bị và ghi log.

## 3. Packet không parse được

Không parse được DNS/TLS/QUIC không đồng nghĩa packet hoặc flow bị lỗi. Ví dụ:
- DoH/DoT làm DNS query không quan sát được ở port 53.
- ECH có thể che SNI.
- QUIC Initial có thể không giải mã được do thiếu packet, version hoặc lỗi parser.
- TCP ClientHello có thể bị chia segment và cần reassembly.

Trong các trường hợp này, pipeline vẫn phải cập nhật flow statistics và có thể dùng ML nếu đủ dữ liệu.

## 4. TCP và QUIC metadata

### TLS over TCP
Cần reassemble TCP stream trước khi parse ClientHello. Không giả định toàn bộ ClientHello nằm trong một packet đầu tiên.

### QUIC over UDP
QUIC Initial có thể chứa TLS ClientHello được bảo vệ ở tầng QUIC. Parser chỉ nên trả metadata khi giải mã và parse thành công. Nếu thất bại, trả trạng thái không có metadata, không làm hỏng flow.

## 5. Quan sát và log

Mỗi kết quả phân loại nên lưu tối thiểu:
- timestamp;
- device/client identifier;
- flow key hoặc flow ID;
- protocol và port;
- SNI/ALPN/fingerprint nếu có;
- rule result và ML result (nếu đã chạy);
- final app, confidence, source;
- lý do `unknown` hoặc thiếu dữ liệu.

Không ghi payload nhạy cảm. Log phải đủ để điều tra nhưng không lưu nội dung người dùng.
