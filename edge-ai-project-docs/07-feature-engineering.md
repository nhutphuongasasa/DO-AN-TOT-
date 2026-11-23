# 07 – Feature Engineering

## 1. Nguyên tắc

Feature phải:
- có định nghĩa toán học và đơn vị;
- chỉ dùng thông tin có sẵn tại thời điểm dự đoán;
- không chứa trực tiếp label hoặc thông tin tương lai;
- được tính nhất quán offline và runtime;
- có schema version và thứ tự cột cố định.

## 2. Flow feature baseline

README hiện mô tả 24 feature từ `WindowStats` trong `ml/features.py`:

| # | Feature | Đơn vị / ý nghĩa |
|---:|---|---|
| 1 | `n_pkts_total` | Tổng packet |
| 2 | `bytes_total` | Tổng byte |
| 3 | `n_pkts_fwd` | Packet forward/upload |
| 4 | `n_pkts_bwd` | Packet backward/download |
| 5 | `fwd_bwd_pkt_ratio` | Tỷ lệ packet hai chiều |
| 6 | `pkt_len_mean` | Kích thước packet trung bình |
| 7 | `pkt_len_std` | Độ lệch chuẩn packet length |
| 8 | `pkt_len_min` | Packet nhỏ nhất |
| 9 | `pkt_len_max` | Packet lớn nhất |
| 10 | `pkt_len_fwd_mean` | Packet forward trung bình |
| 11 | `bytes_fwd` | Byte forward |
| 12 | `bytes_bwd` | Byte backward |
| 13 | `bytes_ratio` | Tỷ lệ byte backward/forward |
| 14 | `iat_mean` | IAT trung bình, giây |
| 15 | `iat_std` | Độ lệch chuẩn IAT |
| 16 | `iat_max` | IAT lớn nhất |
| 17 | `iat_min` | IAT nhỏ nhất |
| 18 | `fwd_pkt_per_sec` | Packet forward mỗi giây |
| 19 | `bwd_pkt_per_sec` | Packet backward mỗi giây |
| 20 | `dest_port` | Destination port |
| 21 | `is_udp` | Cờ UDP |
| 22 | `is_tcp` | Cờ TCP |
| 23 | `bytes_down_ratio` | Byte backward / tổng byte |
| 24 | `bytes_up_ratio` | Byte forward / tổng byte |

Bảng trên phản ánh README, không xác nhận rằng mọi phép tính trong code đã đúng. Cần kiểm tra xử lý chia cho 0, empty flow, packet direction và window semantics.

## 3. Định nghĩa hướng

`forward` và `backward` phải nhất quán:
- forward: LAN client → remote server;
- backward: remote server → LAN client.

Không xác định direction chỉ bằng thứ tự packet đầu tiên.

## 4. Window semantics

README nói WindowStats là mỗi flow 5 giây nhưng chưa đủ rõ:
- 5 giây tính từ packet đầu flow?
- fixed interval theo clock?
- sliding window?
- sample tạo định kỳ hay chỉ khi flow kết thúc?

Phải chốt một định nghĩa và dùng chung cho dataset builder/runtime. `idle_timeout=120s` là một khái niệm khác.

## 5. Burst feature schema

Xem [05-burst-based-approach.md](05-burst-based-approach.md). Burst schema cần version riêng, không âm thầm thay đổi 24 Flow features.

## 6. Offline/runtime parity

Khuyến nghị tổ chức code theo hướng dùng chung:
- `flow_features.py`: hàm tính Flow features dùng chung;
- `burst_features.py`: hàm tính Burst features dùng chung;
- `feature_schema.py`: tên, thứ tự, kiểu, version và missing-value policy;
- dataset builder và predictor cùng gọi các hàm này.

Tên file trên là đề xuất tổ chức, không khẳng định repo hiện đã có.

## 7. Kiểm thử parity

Cho cùng một PCAP và cùng thời điểm quan sát:
1. chạy offline extraction;
2. replay qua runtime;
3. so sánh feature vector theo flow/window;
4. kiểm tra sai số số thực trong tolerance đã định;
5. kiểm tra feature order và missing values.

Không train bằng một định nghĩa feature rồi inference bằng định nghĩa khác.
