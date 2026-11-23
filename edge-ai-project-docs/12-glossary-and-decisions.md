# 12 — Glossary và Architecture Decisions

## 1. Thuật ngữ

| Thuật ngữ | Ý nghĩa |
|---|---|
| Packet | Gói tin mạng |
| PCAP | File lưu packet capture |
| Flow | Nhóm packet thuộc cùng kết nối logic |
| 5-tuple | Source IP/port, destination IP/port, protocol |
| Flow ID | Định danh Flow trong capture/session |
| Direction | Chiều packet so với client/LAN endpoint |
| DNS Cache | Cache DNS observation có TTL |
| DNS Identified | DNS evidence đủ điều kiện map application |
| DNS Unresolved | DNS không đủ điều kiện; chuyển sang SNI |
| SNI | Server Name Indication trong TLS ClientHello |
| SNI Identified | SNI map được application |
| SNI Unresolved | SNI không đủ điều kiện; chuyển sang ML |
| Burst | Nhóm packet liên tiếp theo segmentation rule |
| Burst Statistics | Feature thống kê của Burst |
| Burst Sequence | Chuỗi Burst có thứ tự |
| CatBoost | Model Branch A trong sơ đồ |
| 1D-CNN | Model Branch B trong sơ đồ |
| Late Fusion / Stacking | Giai đoạn hợp nhất output hai branch |
| UNKNOWN | Không đủ evidence/confidence để trả application |
| Session | Một lần thu thập có PCAP và metadata |
| Data leakage | Dữ liệu cùng nguồn lọt qua train/test split |

## 2. Quyết định kiến trúc bắt buộc

### D1 — DNS trước SNI
DNS-based Application Identification là phương án đầu tiên. SNI chỉ được gọi khi DNS unresolved.

### D2 — SNI trước ML
TLS SNI Mapping là phương án thứ hai. ML chỉ được gọi khi SNI unresolved.

### D3 — Early exit
Flow được DNS hoặc SNI identified phải trả Application và bỏ qua ML.

### D4 — Hai nhánh ML
Branch A dùng Burst Statistics + CatBoost. Branch B dùng Burst Sequence + 1D-CNN.

### D5 — Late Fusion
Output hai branch được hợp nhất ở Late Fusion / Stacking trước Application Classification.

### D6 — UNKNOWN hợp lệ
Thiếu evidence, input, model hoặc confidence thì trả `UNKNOWN`; không ép nhãn.

### D7 — Shared IP không phải định danh
Một IP có thể phục vụ nhiều domain/application. DNS lookup phải giữ ambiguity.

### D8 — Offline/runtime parity
Dataset builder và runtime dùng chung Flow/Burst/feature contract.

### D9 — Giữ metadata lineage
Mọi Burst và prediction phải truy ngược được về `flow_id` và `session_id` khi có.

## 3. Open decisions — không tự giả định

| ID | Cần quyết định | Vì sao cần |
|---|---|---|
| O-01 | DNS mapping confidence/ambiguity policy | Quyết định DNS_IDENTIFIED |
| O-02 | SNI domain mapping rules | Quyết định SNI_IDENTIFIED |
| O-03 | Burst idle-gap threshold | Xác định Burst boundary |
| O-04 | Có tách Burst khi direction đổi không | Ảnh hưởng segmentation |
| O-05 | CatBoost feature list/order | Khóa model input |
| O-06 | 1D-CNN tensor shape/sequence length | Khóa model input |
| O-07 | Padding/truncation/normalization | Đảm bảo inference hợp lệ |
| O-08 | Late Fusion hay Stacking cụ thể | Xác định training/inference |
| O-09 | Confidence threshold và calibration | Xác định UNKNOWN |
| O-10 | Thời điểm phát prediction | Xác định minimum observation |
| O-11 | Final output schema | Đồng bộ module và dashboard |
| O-12 | Runtime source paths/entrypoint | Tránh tạo file trùng chức năng |

## 4. Quy tắc cho Coding Agent

1. Đọc `README.md`, sau đó `01-system-architecture.md`.
2. Giữ nguyên thứ tự DNS → SNI → ML.
3. Tìm implementation hiện có trước khi tạo file mới.
4. Không đổi Flow/Device LightGBM baseline thành CatBoost/1D-CNN nếu chưa có code tương ứng.
5. Không tự điền Open Decisions bằng giá trị phỏng đoán.
6. Khi cần giả định để triển khai, ghi rõ trong PR/code comment và cập nhật tài liệu.
7. Thêm test chứng minh nhánh DNS/SNI early exit và ML fallback.
