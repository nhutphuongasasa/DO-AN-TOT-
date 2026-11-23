# 11 – Roadmap và quản lý trạng thái

## 1. Trạng thái theo bằng chứng hiện có

| Hạng mục | Trạng thái theo README / trao đổi | Việc cần xác minh |
|---|---|---|
| Packet capture live/offline | README mô tả đã có code | Test interface và replay |
| DNS/TLS/QUIC parser | README mô tả đã có | Kiểm tra code và edge cases |
| Flow Tracker | README mô tả đã có | Hai chiều, timeout, tuple reuse |
| Rule Engine | README mô tả đã có | Rule precedence và ambiguity |
| Dataset Builder | Có code theo README | Label boundary, leakage |
| Flow features 24 cột | Có code theo README | Công thức và parity |
| LightGBM baseline | Có script; kết quả chưa tốt | Tái lập metric |
| Burst-based | Đang nghiên cứu | Thiết kế, implement, benchmark |
| DNS cache hardening | Cần audit | Multi-domain/IP, TTL, client scope |
| ML runtime integration | README ghi kế hoạch | Xác minh pipeline call path |
| Dashboard | Có Rich terminal theo README | Kiểm tra output và trạng thái thực |

## 2. Thứ tự ưu tiên

### P0 – Đảm bảo dữ liệu đầu vào đúng
- Audit DNS parser/cache.
- Audit Flow Tracker và direction.
- Kiểm tra session labels, flow grouping và split leakage.

### P1 – Khóa feature contract
- Chốt Flow window semantics.
- Viết test offline/runtime parity.
- Version hóa feature schema.

### P2 – Làm baseline đáng tin cậy
- Tái lập Flow LightGBM.
- Báo cáo per-class và session split.
- Phân tích lỗi lớp yếu, label noise và feature leakage.

### P3 – Thử nghiệm Burst
- Định nghĩa burst boundary.
- Xây extractor độc lập.
- Tạo Burst dataset với flow/session IDs.
- So sánh Flow-only, Burst-only, Flow+Burst.

### P4 – Tích hợp runtime
- Chốt state machine và minimum observation.
- Tích hợp predictor sau khi schema ổn định.
- Kiểm soát conflict, unknown và log evidence.

### P5 – Hoàn thiện đồ án
- Replay end-to-end.
- Đo latency/RAM trên Edge.
- Cập nhật README, sơ đồ, báo cáo và demo.

## 3. Definition of Done

Một hạng mục chỉ được đánh dấu hoàn thành khi:
- code tồn tại;
- test liên quan pass;
- có dữ liệu/log chứng minh;
- có hướng dẫn chạy;
- trạng thái tài liệu khớp implementation.

## 4. Nhật ký thay đổi

Nên ghi mỗi quyết định quan trọng theo mẫu:
- Ngày:
- Vấn đề:
- Quyết định:
- Lý do:
- Phương án đã loại:
- File/code bị ảnh hưởng:
- Test cần chạy:
- Kết quả:
