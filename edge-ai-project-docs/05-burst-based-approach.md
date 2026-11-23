# 05 – Hướng Burst-based Traffic Classification

## 1. Vì sao nghiên cứu Burst?

Flow-based baseline hiện dùng thống kê tổng hợp của flow/window. Cách này có thể làm mất cấu trúc thời gian và chuỗi hành vi: upload ngắn, download dài, các đợt truyền dữ liệu, khoảng nghỉ giữa các đợt.

Burst-based thử biểu diễn traffic thành các nhóm packet gần nhau về thời gian và có thể cùng hướng, sau đó học từ:
- kích thước và số lượng packet trong burst;
- tổng byte;
- thời lượng burst;
- hướng upload/download;
- khoảng cách giữa các burst;
- thứ tự và mẫu xen kẽ giữa hai hướng.

Burst-based là **hướng thí nghiệm**, không phải kết luận rằng mô hình này chắc chắn tốt hơn Flow-based.

## 2. Không thay baseline ngay

Giữ ít nhất ba nhánh để so sánh:

1. **Flow-only:** baseline hiện tại.
2. **Burst-only:** chỉ dùng đặc trưng burst/chuỗi burst.
3. **Flow + Burst:** kết hợp hai nhóm đặc trưng.

So sánh trên cùng dataset, cùng session split, cùng nhãn, cùng metric và cùng quy tắc loại bỏ dữ liệu.

## 3. Định nghĩa Burst phải được cố định

Burst là một nhóm packet trong cùng flow được gom theo quy tắc thời gian/hướng. Cần thử nghiệm và chọn ngưỡng bằng validation, không chọn theo test set.

Một định nghĩa ban đầu có thể là:
- packet thuộc cùng flow;
- cùng direction trong một burst;
- packet kế tiếp cách packet trước không quá ngưỡng idle gap `T`;
- nếu direction đổi hoặc gap vượt `T`, kết thúc burst và mở burst mới.

Đây chỉ là định nghĩa khởi đầu. Có thể nghiên cứu thêm burst hai chiều hoặc burst theo idle gap mà không tách direction, nhưng phải ghi rõ và so sánh.

## 4. Cấu trúc dữ liệu đề xuất

Mỗi burst cần liên kết về:
- `session_id`;
- `flow_id`;
- `burst_id`;
- `start_ts`, `end_ts`;
- `direction`;
- `packet_count`;
- `total_bytes`;
- thống kê packet length;
- IAT trong burst;
- gap từ burst trước;
- thứ tự burst trong flow.

Không bỏ `flow_id`/`session_id`, vì đây là chìa khóa chống data leakage và truy vết lỗi.

## 5. Feature ứng viên

| Nhóm | Feature ví dụ |
|---|---|
| Quy mô | packet_count, total_bytes |
| Kích thước | mean/std/min/max packet length |
| Thời gian | duration, intra-burst IAT mean/std |
| Hướng | upload/download, direction transition |
| Liên burst | inter_burst_gap, previous_burst_direction |
| Chuỗi | burst order, rolling statistics trên N burst gần nhất |

Chỉ thêm feature có định nghĩa rõ và có thể tính giống nhau offline/runtime.

## 6. Cách đưa Burst vào ML

Có hai hướng:
- **Tabular burst samples:** mỗi burst là một sample, có thể thử LightGBM. Cần quy định dự đoán burst đại diện cho app nào và cách tổng hợp nhiều burst thành flow prediction.
- **Sequence model:** một flow là chuỗi burst có thứ tự, dùng mô hình chuỗi nếu lượng dữ liệu đủ. Không nên nhảy sang deep learning khi dataset còn ít.

Bước đầu nên ưu tiên pipeline đơn giản, đo được, dễ debug.

## 7. Tránh leakage

Tất cả burst thuộc cùng một flow phải nằm trong cùng một split. Tốt hơn nữa, chia theo session/batch độc lập để test khả năng tổng quát hóa.

Không được random split từng burst nếu cùng một flow xuất hiện ở cả train và test.

## 8. Thí nghiệm cần thực hiện

| Thí nghiệm | Câu hỏi |
|---|---|
| Flow-only | Baseline hiện tại đạt mức nào? |
| Burst-only | Burst có tín hiệu phân biệt không? |
| Flow + Burst | Burst có bổ sung thông tin không? |
| Nhiều ngưỡng gap | Kết quả nhạy với T ra sao? |
| Early vs late observation | Cần quan sát bao lâu mới dự đoán được? |
| Per-class | App nào cải thiện, app nào giảm? |
| Runtime cost | CPU, RAM, latency trên Edge ra sao? |

## 9. Điều kiện chấp nhận Burst

Chỉ chuyển Burst thành hướng chính khi:
- tăng Macro F1 hoặc cải thiện lớp yếu một cách ổn định trên session độc lập;
- không làm tăng false positive quá mức;
- latency và RAM phù hợp Edge;
- feature extraction có thể chạy giống nhau offline/runtime;
- kết quả lặp lại được.

Nếu Burst không vượt baseline, giữ Flow-only hoặc dùng Burst như feature bổ sung.
