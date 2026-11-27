# 00 — Tổng quan dự án

## 1. Mục đích

Hybrid Application Identification nhận diện ứng dụng tương ứng với Flow mạng bằng bằng chứng giao thức và hành vi traffic. Hệ thống không giải mã payload HTTPS và không đọc nội dung ứng dụng.

## 2. Bài toán

Traffic ứng dụng thường được mã hóa. IP hoặc port riêng lẻ không đủ để xác định ứng dụng, đặc biệt khi nhiều domain dùng chung CDN/IP. Dự án kết hợp ba tầng bằng chứng theo thứ tự cố định: DNS, TLS SNI và Burst-based ML.

## 3. Đối tượng sử dụng

- Người phát triển hệ thống cần triển khai và kiểm thử pipeline.
- Người vận hành/nghiên cứu mạng cần xem ứng dụng được nhận diện và evidence tương ứng.

## 4. Phạm vi

**Trong phạm vi**
- Capture packet từ NIC hoặc PCAP.
- Parse packet và theo dõi Flow.
- DNS Response parsing, DNS Cache và DNS domain mapping.
- TLS ClientHello parsing và SNI mapping.
- Bidirectional Flow Reconstruction và Burst Segmentation.
- CatBoost, 1D-CNN và Late Fusion / Stacking.
- Kết quả application hoặc `UNKNOWN`.

**Ngoài phạm vi**
- Giải mã payload HTTPS.
- Khẳng định nhận diện được mọi ứng dụng trong mọi điều kiện.
- Kết luận ứng dụng chỉ từ một IP/port nếu evidence không đủ.
- Coi DNS Cache là ánh xạ IP → application một-một.

## 5. Input / Output

| Loại | Dữ liệu |
|---|---|
| Input | Ethernet/IP/TCP/UDP packet từ NIC hoặc PCAP |
| Protocol evidence | DNS Response, domain, IP, TTL, TLS ClientHello, SNI |
| Flow data | 5-tuple, timestamp, direction, packet length, packet sequence |
| ML input A | Burst Statistics |
| ML input B | Burst Sequence |
| Output | Flow identifier, application label hoặc `UNKNOWN`, identification method, evidence và confidence khi có |

Runtime result hiện được lưu trong `FlowState.identification_result` (application/status/method/evidence/confidence/metadata). Live CLI chưa xuất Flow prediction sau finalize; PCAP trả Flow objects và in summary, chưa có structured Flow CSV/JSON exporter.

## 6. Quy tắc kiến trúc

- BR-01: DNS identification phải chạy trước SNI identification.
- BR-02: SNI identification chỉ chạy khi DNS trả `DNS_UNRESOLVED`.
- BR-03: ML chỉ chạy khi DNS và SNI đều unresolved.
- BR-04: Flow đã identified bằng DNS hoặc SNI không được gửi vào ML classification.
- BR-05: ML sử dụng hai nhánh CatBoost và 1D-CNN.
- BR-06: Kết quả hai nhánh ML được hợp nhất bằng Late Fusion / Stacking.
- BR-07: Không đủ độ tin cậy thì trả `UNKNOWN`.

## 7. Giới hạn đã biết

- DoH/DoT, VPN hoặc DNS cache ở endpoint có thể khiến DNS Response không xuất hiện trong capture.
- ECH có thể che SNI.
- TCP ClientHello có thể bị chia qua nhiều segment.
- Một IP có thể phục vụ nhiều domain.
- Sơ đồ xác định kiến trúc mục tiêu; không chứng minh mọi module đã có code.

## 8. Tiêu chí nghiệm thu

- [ ] README và architecture mô tả cùng một thứ tự DNS → SNI → ML.
- [ ] Mỗi kết quả phân loại có thể truy ngược Flow và evidence.
- [ ] Có trạng thái `UNKNOWN`.
- [ ] Tài liệu phân biệt rõ phần implemented, tested, designed và open.

> **Implementation status (snapshot 2026-11-27):** Live capture and PCAP replay share `PacketProcessor`. DNS, TCP/TLS SNI, UDP protocol analysis and QUIC v1 Initial/SNI are integrated. Candidate Gate, Flow observation, Burst segmentation/statistics and CatBoost Flow V2 inference are also integrated. CatBoost runtime is optional and requires `--ml-model`; its model binary is external to this source ZIP. A supplied live run produced 23 predictions with zero inference errors, which proves inference execution but not correctness. The current runtime does not invoke the 1D-CNN or Late Fusion branch. Final live Flow predictions are not printed/exported after shutdown finalization; accuracy, model-enabled PCAP acceptance, latency and CPU/RAM remain open.
