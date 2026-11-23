# 12 – Thuật ngữ và quyết định kỹ thuật

## 1. Thuật ngữ

| Thuật ngữ | Ý nghĩa |
|---|---|
| PCAP | File lưu các packet đã capture |
| Packet | Một đơn vị gói tin mạng |
| Flow | Nhóm packet thuộc cùng kết nối logic |
| 5-tuple | Source IP/port, destination IP/port, protocol |
| Direction | Chiều truyền tương đối với client LAN |
| IAT | Inter-Arrival Time, khoảng cách thời gian giữa packet |
| SNI | Server Name Indication trong TLS ClientHello |
| ALPN | Application-Layer Protocol Negotiation |
| ECH | Encrypted ClientHello, có thể che thông tin ClientHello như SNI |
| JA3/JA4 | TLS client fingerprint |
| QUIC Initial | Gói QUIC ban đầu có thể mang TLS ClientHello được bảo vệ ở tầng QUIC |
| DNS cache | Lưu quan sát DNS trong thời gian TTL |
| CDN | Mạng phân phối nội dung, thường dùng chung IP cho nhiều domain |
| Flow feature | Đặc trưng thống kê của flow/window |
| Burst | Nhóm packet liên tiếp theo một quy tắc thời gian/hướng |
| Session | Một lần thu thập thí nghiệm có metadata và nhãn |
| Data leakage | Thông tin từ train lọt sang validation/test |
| Macro F1 | Trung bình F1 các lớp với trọng số bằng nhau |
| Calibration | Điều chỉnh confidence dự đoán cho phù hợp hơn với tần suất đúng thực tế |

## 2. Quyết định kỹ thuật cần giữ

### D1 – Giữ Flow baseline
Không xóa Flow-based khi nghiên cứu Burst. Baseline là mốc để chứng minh Burst có cải thiện thật hay không.

### D2 – DNS là evidence phụ
Một IP có thể dùng chung cho nhiều domain. Không ánh xạ cứng một IP thành một app/domain duy nhất.

### D3 – Unknown là kết quả hợp lệ
Khi evidence không đủ hoặc xung đột không giải quyết được, hệ thống nên trả `unknown` thay vì đoán.

### D4 – Không leakage giữa các split
Mọi burst của cùng flow phải nằm cùng split; ưu tiên group theo session.

### D5 – Offline/runtime dùng chung feature contract
Không duy trì hai bộ công thức độc lập cho dataset và inference.

### D6 – Không khẳng định chức năng khi chưa test
README, sơ đồ và roadmap cần phân biệt implementation, integration và validation.

## 3. Các câu hỏi còn phải chốt

- Burst được phân đoạn theo idle gap bao nhiêu? Có tách direction không?
- Một sample Burst đại diện cho burst, flow hay chuỗi burst?
- Dự đoán ở thời điểm nào: sau N packet, sau T giây hay khi flow đóng?
- 5-second Flow window là fixed/sliding/flow-relative?
- Rule Engine và ML conflict được giải quyết theo policy nào?
- Device dashboard biểu diễn nhiều app đồng thời ra sao?
- Danh sách nhãn cuối cùng và quy trình tạo nhãn là gì?

Các câu hỏi này cần được quyết định bằng thí nghiệm và kiểm tra code, không tự điền bằng giả định.
