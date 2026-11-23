# 01 – Kiến trúc hệ thống

## 1. Kiến trúc chia thành hai mặt phẳng

### A. Offline preparation / training

```text
capture_session.py
       |
       v
PCAP + labels + session metadata
       |
       v
dataset_builder.py
       |
       +--> Flow feature table
       |
       +--> Burst feature table (đang nghiên cứu)
       |
       v
train / validation / test theo session
       |
       v
model + calibration + evaluation report
```

### B. Runtime

```text
NIC hoặc PCAP
    |
Packet Source
    |
Capture Pipeline
    +--> DNS parser ------> DNS cache
    +--> TLS parser ------> SNI / ALPN / JA3 / JA4
    +--> QUIC parser -----> ClientHello metadata nếu giải mã được
    |
Flow Tracker
    |
Rule Engine
    |
ML inference nếu cần và đủ dữ liệu
    |
Device Aggregator
    |
Dashboard / JSONL / report
```

## 2. Thành phần và trách nhiệm

| Thành phần | Trách nhiệm |
|---|---|
| `capture/main.py` | CLI, khởi tạo chế độ live/offline |
| `capture/packet_source.py` | Đọc packet từ NIC hoặc PCAP |
| `capture/pipeline.py` | Điều phối xử lý packet |
| `capture/flow_tracker.py` | Gom packet theo 5-tuple, cập nhật trạng thái flow |
| `capture/parsers/dns_parser.py` | Đọc DNS response và thông tin record |
| `capture/parsers/tls_parser.py` | Phân tích TLS ClientHello |
| `capture/parsers/quic_parser.py` | Giải mã QUIC Initial để thử lấy ClientHello |
| `rule_engine.py` | Phân loại theo luật và metadata |
| `rules.yaml` | Domain/fingerprint/port/IP rules |
| `ml/dataset_builder.py` | PCAP + labels thành dataset |
| `ml/features.py` | Tính Flow features theo README |
| `ml/train_flow.py` | Huấn luyện Flow LightGBM baseline |
| `ml/predictor.py` | Inference API |
| `capture/device_registry.py` | Theo dõi MAC/IP thiết bị LAN |
| `capture/outputs.py` | Dashboard, JSONL, report |
| `tools/capture_session.py` | Thu PCAP và nhãn phiên |

## 3. Ranh giới trách nhiệm

- Parser chỉ trích xuất dữ liệu giao thức; không tự quyết định app.
- Flow Tracker quản lý kết nối và thống kê; không tự gán nhãn ứng dụng.
- DNS cache cung cấp một tín hiệu hỗ trợ; không phải nguồn sự thật tuyệt đối.
- Rule Engine quyết định từ bằng chứng luật.
- ML nhận feature vector đã được chuẩn hóa theo schema; không tự đọc PCAP trong runtime.
- Device Aggregator tổng hợp kết quả flow; không thay đổi dự đoán gốc mà không lưu dấu nguồn.

## 4. Luồng dữ liệu cần giữ nhất quán

Mỗi packet hợp lệ nên đi qua một đường xử lý có thể truy vết:
1. Capture timestamp và packet metadata.
2. Xác định packet thuộc LAN/device nào.
3. Cập nhật DNS hoặc TLS/QUIC metadata nếu có.
4. Xác định flow key và hướng.
5. Cập nhật thống kê flow/window.
6. Đánh giá Rule Engine.
7. Nếu cần, kiểm tra đủ dữ liệu rồi gọi ML.
8. Ghi kết quả cùng evidence/source và cập nhật thiết bị.

## 5. Trạng thái tích hợp

README cũ có sơ đồ mô tả Rule Engine → LightGBM → Dashboard, nhưng phần chi tiết ghi ML integration là kế hoạch. Vì vậy, không được coi sơ đồ là bằng chứng tích hợp đã hoàn tất. Cần kiểm tra `pipeline.py`, `predictor.py` và đường gọi thực tế trước khi đánh dấu hoàn thành.
