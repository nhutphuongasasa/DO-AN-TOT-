# 00 – Tổng quan dự án

## 1. Bài toán

Các ứng dụng hiện đại thường truyền dữ liệu qua TLS/HTTPS hoặc QUIC. Payload được mã hóa nên hệ thống không thể dựa vào nội dung ứng dụng để phân loại. Bài toán của đồ án là suy luận ứng dụng từ các dấu hiệu quan sát được bên ngoài payload.

## 2. Mục tiêu

- Thu thập traffic của các thiết bị trong mạng LAN.
- Nhận diện metadata có thể quan sát: DNS, TLS ClientHello, QUIC Initial, giao thức, port.
- Gom packet thành flow và trích xuất đặc trưng thống kê.
- Nghiên cứu mô hình ML để phân loại ứng dụng khi luật không đủ thông tin.
- Tổng hợp kết quả theo thiết bị và hiển thị trên dashboard.
- Đánh giá khả năng hoạt động trên Edge với tài nguyên hạn chế.

## 3. Ngoài phạm vi

- Không giải mã HTTPS payload hoặc đọc nội dung tin nhắn/video.
- Không cam kết nhận diện chính xác mọi ứng dụng trong mọi mạng.
- Không coi IP, port hoặc ASN đơn lẻ là định danh ứng dụng.
- Không khẳng định có thể nhận diện ứng dụng khi traffic hoàn toàn không có tín hiệu phân biệt.

## 4. Đầu vào và đầu ra

| Loại | Nội dung |
|---|---|
| Đầu vào capture | Ethernet/IP/TCP/UDP packets từ NIC hoặc PCAP |
| Metadata | DNS query/response, SNI, ALPN, JA3/JA4 nếu parse được |
| Nhãn training | Ứng dụng đang được chủ động sử dụng trong từng khoảng thời gian |
| Flow output | 5-tuple, thống kê packet/byte/time/direction |
| Burst output | Chuỗi nhóm packet liên tiếp theo quy tắc burst được định nghĩa |
| Kết quả | App dự đoán, confidence, nguồn quyết định, thiết bị, thời gian |

## 5. Đối tượng phân loại

Các nhãn được README cũ đề cập gồm YouTube, Spotify, Zalo, Google Meet, ChatGPT và các lớp nền như other-idle, other-web, other-update. Danh sách nhãn cuối cùng phải được chốt dựa trên dữ liệu thực tế, không nên giữ lớp chưa có mẫu.

## 6. Hai cấp độ phân loại

- **Flow-level:** dự đoán ứng dụng cho một flow hoặc một cửa sổ quan sát của flow.
- **Device-level:** tổng hợp nhiều flow thuộc cùng thiết bị trong một khoảng thời gian.

Không được nhầm hai bài toán này: một thiết bị có thể đồng thời chạy nhiều ứng dụng.

## 7. Tiêu chí thành công

- Dataset có nhãn đáng tin cậy, nhiều phiên độc lập cho mỗi lớp.
- Flow tracking không trộn lẫn kết nối hoặc hướng truyền.
- Feature offline và runtime giống nhau.
- Kết quả được đánh giá trên session chưa xuất hiện trong training.
- Có báo cáo per-class, confusion matrix, Macro F1 và kiểm tra độ trễ/tài nguyên.
- Hệ thống trả về `unknown` khi không đủ bằng chứng thay vì ép đoán.
