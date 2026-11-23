# 04 – Flow Tracking

## 1. Mục đích

Flow Tracker gom nhiều packet thành một kết nối logic để thống kê và phân loại. README mô tả flow theo 5-tuple:

`(src_ip, src_port, dst_ip, dst_port, protocol)`

Trong thực tế cần chuẩn hóa hai chiều để packet đi và về được gom vào cùng một FlowState.

## 2. Khóa flow hai chiều

Ví dụ:
- Client → Server: `10.0.0.5:51000 -> 142.1.1.1:443 TCP`
- Server → Client: `142.1.1.1:443 -> 10.0.0.5:51000 TCP`

Hai packet direction trên phải thuộc cùng một flow, nhưng vẫn giữ thông tin chiều forward/backward.

Cần xác định client/LAN endpoint một cách nhất quán. Không chỉ dựa vào packet đầu tiên đến vì PCAP có thể bắt đầu giữa phiên hoặc thấy server packet trước.

## 3. Thông tin cần giữ trong FlowState

- flow ID ổn định trong phiên capture;
- 5-tuple canonical;
- client IP/port và remote IP/port;
- protocol;
- thời điểm packet đầu/cuối;
- packet count và byte count mỗi chiều;
- packet length statistics;
- inter-arrival time statistics;
- TCP flags/state nếu cần;
- metadata DNS/TLS/QUIC;
- trạng thái inspect/parser;
- nhãn/dataset metadata chỉ ở offline path.

## 4. Timeout và tuple reuse

README mô tả `idle_timeout = 120s`. Cần kiểm tra:
- Flow không có packet trong thời gian timeout được đóng đúng cách.
- Khi đóng flow, final statistics được giữ để prediction/export.
- Kết nối mới dùng lại cùng 5-tuple không được trộn vào flow cũ.
- Cleanup không xóa flow trước khi consumer hoàn tất.
- Memory usage có giới hạn khi nhiều flow hoạt động.

`idle_timeout` là thời gian sống của flow state; nó không đồng nghĩa cửa sổ feature 5 giây.

## 5. Phân biệt Flow và Window

Một flow có thể tồn tại lâu hơn nhiều cửa sổ quan sát. Cần định nghĩa rõ:
- 5-second window là fixed, sliding hay chỉ là một lần tổng hợp?
- Feature được tính từ đầu flow hay từ phần packet trong window?
- Mỗi window tạo một sample riêng hay chỉ cập nhật thống kê hiện tại?
- Flow đóng thì có xuất sample cuối cùng không?

Không được trộn lẫn các định nghĩa này giữa dataset builder và live pipeline.

## 6. Test bắt buộc

- TCP và UDP.
- Packet hai chiều.
- Server packet xuất hiện trước.
- Capture bắt đầu giữa flow.
- Packet duplicate hoặc out-of-order.
- Idle timeout.
- Tuple reuse sau timeout.
- Nhiều client cùng remote IP.
- Replay cùng PCAP hai lần cho cùng kết quả flow/features (trong cùng cấu hình).

## 7. Điều kiện để chuyển sang Burst

Burst extraction phải nhận packet sequence đã được Flow Tracker xác định flow và direction. Không được tạo burst từ các packet đã bị mất thứ tự hoặc trộn flow.
