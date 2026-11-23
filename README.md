# Edge AI – Tài liệu tổng thể dự án

> Bộ tài liệu này mô tả đồ án phân loại ứng dụng qua lưu lượng mạng mã hóa. Đọc file này trước, sau đó đi theo các tài liệu được liên kết bên dưới.

## 1. Dự án làm gì?

Dự án xây dựng một hệ thống chạy tại thiết bị Edge (laptop hoặc Raspberry Pi) để nhận biết ứng dụng đang tạo traffic trên từng thiết bị trong mạng LAN. Hệ thống không giải mã nội dung HTTPS; thay vào đó sử dụng metadata và đặc trưng hành vi gói tin như kích thước, thời gian đến, hướng truyền, giao thức, thông tin TLS/QUIC có thể quan sát được và mô hình học máy.

Ví dụ đầu ra mong muốn: thiết bị A đang sử dụng YouTube, thiết bị B đang sử dụng Spotify, kèm độ tin cậy và nguồn bằng chứng.

## 2. Tình trạng cần hiểu đúng

Tài liệu được viết lại dựa trên README dự án và các quyết định kỹ thuật đã trao đổi. Đây là **tài liệu thiết kế và quản lý dự án**, không phải xác nhận rằng mọi chức năng đã được kiểm thử trong mã nguồn.

- Đã có mã nguồn cho các thành phần capture, parsing, flow tracking, Rule Engine, xây dựng dataset và huấn luyện LightGBM theo README.
- README cũ ghi đã thu thập YouTube khoảng 237 MB / 30 phút; các ứng dụng khác còn thiếu trong roadmap.
- Baseline LightGBM hiện cho kết quả chưa tốt (Macro F1 khoảng 53% theo kết quả đã trao đổi). Con số này cần được gắn với đúng lần chạy, dataset và cấu hình khi đưa vào báo cáo chính thức.
- Hướng Burst-based đang được nghiên cứu để cải thiện biểu diễn hành vi traffic. **Chưa được xem là đã triển khai hoặc chứng minh tốt hơn Flow-based.**
- Tích hợp ML vào pipeline runtime, chất lượng dữ liệu và độ tin cậy DNS/Flow cần được xác minh bằng code và test.

## 3. Bản đồ tài liệu

| File | Nội dung |
|---|---|
| [00-project-overview.md](edge-ai-project-docs/00-project-overview.md) | Mục tiêu, phạm vi, đầu vào/đầu ra, giới hạn |
| [01-system-architecture.md](edge-ai-project-docs/01-system-architecture.md) | Kiến trúc tổng thể và các module |
| [02-runtime-packet-flow.md](edge-ai-project-docs/02-runtime-packet-flow.md) | Đường đi của packet khi chạy live/offline |
| [03-dns-cache-design.md](edge-ai-project-docs/03-dns-cache-design.md) | DNS parser, cache IP-domain, rủi ro CDN/DoH |
| [04-flow-tracking.md](edge-ai-project-docs/04-flow-tracking.md) | 5-tuple, hướng flow, timeout, trạng thái |
| [05-burst-based-approach.md](edge-ai-project-docs/05-burst-based-approach.md) | Hướng Burst-based, cách định nghĩa và trích xuất |
| [06-data-collection-and-labeling.md](edge-ai-project-docs/06-data-collection-and-labeling.md) | Thu PCAP, nhãn, kiểm soát nhiễu và leakage |
| [07-feature-engineering.md](edge-ai-project-docs/07-feature-engineering.md) | Flow features, Burst features và feature parity |
| [08-model-training-and-evaluation.md](edge-ai-project-docs/08-model-training-and-evaluation.md) | Baseline, so sánh mô hình, chia tập và metrics |
| [09-runtime-classification.md](edge-ai-project-docs/09-runtime-classification.md) | Rule Engine + ML, quyết định và trạng thái phân loại |
| [10-testing-and-troubleshooting.md](edge-ai-project-docs/10-testing-and-troubleshooting.md) | Test quan trọng, replay, xử lý lỗi |
| [11-roadmap-and-status.md](edge-ai-project-docs/11-roadmap-and-status.md) | Trạng thái, thứ tự công việc và tiêu chí hoàn thành |
| [12-glossary-and-decisions.md](edge-ai-project-docs/12-glossary-and-decisions.md) | Thuật ngữ và quyết định kỹ thuật |

## 4. Luồng hoạt động trong một trang

![Luồng hoạt động hệ thống](images/Screenshot_23-11-2026_14734_.jpeg)

## 5. Nguyên tắc đọc tài liệu

1. Phân biệt **đã có trong README**, **đang kiểm chứng**, và **đề xuất thiết kế**.
2. Không kết luận một lỗi tồn tại chỉ từ README; phải kiểm tra code và test.
3. Không thay Flow baseline bằng Burst trước khi có thí nghiệm so sánh công bằng.
4. Không xem DNS IP-domain là ánh xạ một-một hoặc bằng chứng chắc chắn về ứng dụng.
5. Không đưa kết quả ML lên báo cáo nếu chưa ghi rõ dataset, split, seed, model và metric.
