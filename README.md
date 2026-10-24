# Edge AI — Phân Loại Ứng Dụng Qua Lưu Lượng Mã Hóa

> **Đồ án Tốt nghiệp**  
> **Nhóm:** Trần Văn Danh · Lê Nhựt Phương  
> **Đề tài:** Xây dựng hệ thống Edge AI phân loại các ứng dụng thông qua lưu lượng mạng mã hóa

---

## 📌 Tổng quan

Hệ thống phân loại lưu lượng mạng mã hóa (TLS 1.3 / QUIC) **mà không cần giải mã payload** — chạy trực tiếp trên thiết bị biên (Raspberry Pi / Laptop).

Khi triển khai, hệ thống có thể chỉ ra:
- Máy nào trên mạng LAN đang dùng **YouTube**, **Spotify**, **ChatGPT**, **Zalo**, **Meet**...
- Độ tin cậy của mỗi phán đoán

### Ứng dụng phân loại được
| Ứng dụng | Nhãn |
|----------|------|
| YouTube | `youtube` |
| Spotify | `spotify` |
| Google Meet | `meet` |
| Zalo | `zalo` |
| ChatGPT | `chatgpt` |
| Nền (idle) | `other-idle` |
| Duyệt web | `other-web` |
| Cập nhật app | `other-update` |

---

## 🏗️ Kiến trúc hệ thống

```
Packets (PCAP / Live)
        │
        ▼
┌───────────────────────────────────────────┐
│           Rule Engine (5 lớp)             │
│  Layer 1: SNI / Domain matching           │
│  Layer 2: DNS correlation cache           │
│  Layer 3: JA3 / JA4 TLS fingerprint       │
│  Layer 4: Port / Protocol mapping         │
│  Layer 5: IP / ASN lookup                 │
└──────────────────┬────────────────────────┘
          conf ≥ 0.7 │        conf < 0.7
                    │              │
                    │     ┌────────▼──────────┐
                    │     │  ML Fallback       │
                    │     │  LightGBM per-flow │
                    │     │  F1 = 0.995        │
                    │     └────────────────────┘
                    │              │
                    └──────┬───────┘
                           ▼
              DeviceActivityAggregator
              (vote theo bytes, 30s window)
                           │
                           ▼
                     Dashboard / UI
              "PC 192.168.1.5 → YouTube (0.97)"
```

---

## 📂 Cấu trúc thư mục

```
.
├── rule_engine.py          # Rule Engine đa lớp (SNI/DNS/JA3/JA4/Port/ASN)
├── rules.yaml              # Bộ quy tắc phân loại (domain, fingerprint, port, IP)
├── example.py              # Demo script cho Rule Engine
├── requirements.txt        # Python dependencies
│
├── ml/                     # Module AI/ML
│   ├── dataset_builder.py  # PCAP → CSV dataset
│   ├── features.py         # Trích xuất đặc trưng (WindowStats, DeviceWindowCollector)
│   ├── gen_synthetic.py    # Sinh dữ liệu tổng hợp cho training
│   ├── train_flow.py       # Huấn luyện LightGBM per-flow (5s window)
│   ├── train_device.py     # Huấn luyện LightGBM per-device (30s window)
│   ├── train_ts.py         # Huấn luyện 1D-CNN/LSTM (time-series)
│   ├── predictor.py        # Inference engine (FlowPredictor, DeviceWindowPredictor)
│   ├── evaluate.py         # Sinh báo cáo, biểu đồ đánh giá
│   ├── data/               # Dataset (CSV, NPZ, metadata)
│   ├── models/             # Trained models (LightGBM .txt, label encoders)
│   └── results/            # Biểu đồ, confusion matrix, HTML report
│
└── tools/
    ├── capture_session.py  # Thu thập traffic trên Raspberry Pi
    └── PI_SETUP.md         # Hướng dẫn cài đặt Raspberry Pi
```

---

## ⚙️ Cài đặt

### Yêu cầu hệ thống
- Python 3.9+
- Linux (Raspberry Pi OS / Ubuntu)
- `sudo` để sniff packets live

### Cài thư viện

```bash
# Tạo virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Cài dependencies cơ bản
pip install -r requirements.txt

# Cài thêm cho ML training
pip install lightgbm scikit-learn pandas matplotlib seaborn

# Cài thêm cho CNN/LSTM (tuỳ chọn)
pip install torch onnx onnxruntime
```

---

## 🚀 Hướng dẫn sử dụng

### 1. Demo Rule Engine

```bash
python3 example.py
```

### 2. Thu thập traffic (trên Raspberry Pi)

```bash
sudo python3 tools/capture_session.py --batch batch1 --iface wlan0 --dur 30
```

### 3. Xây dựng dataset từ PCAP

```bash
python3 -m ml.dataset_builder --sessions captures/batch1/ --out ml/data/
```

### 4. Sinh dữ liệu tổng hợp (không cần Pi)

```bash
python3 -m ml.gen_synthetic --out-dir captures/ --batches 5
```

### 5. Huấn luyện mô hình

```bash
# LightGBM per-flow
python3 -m ml.train_flow

# LightGBM per-device
python3 -m ml.train_device

# 1D-CNN (cần PyTorch)
python3 -m ml.train_ts
```

### 6. Đánh giá mô hình

```bash
python3 -m ml.evaluate \
  --flow-results ml/models/flow/cv_summary.json \
  --device-results ml/models/device/cv_summary.json \
  --out ml/results/
```

---

## 📊 Kết quả thực nghiệm

| Mô hình | Phương pháp đánh giá | F1 Score |
|---------|----------------------|----------|
| LightGBM Per-Flow (5s) | 5-fold LOSO CV | **0.995 ± 0.001** |
| LightGBM Per-Device (30s) | 5-fold LOSO CV | **0.997** |

### Phân loại chi tiết (LightGBM Per-Flow, fold tốt nhất)
| App | Precision | Recall | F1 |
|-----|-----------|--------|----|
| youtube | ~0.99 | ~0.99 | ~0.99 |
| spotify | ~1.00 | ~1.00 | ~1.00 |
| meet | ~1.00 | ~1.00 | ~1.00 |
| zalo | ~0.99 | ~0.99 | ~0.99 |
| chatgpt | ~0.99 | ~0.99 | ~0.99 |

---

## 🔬 Đặc trưng sử dụng

Tất cả đặc trưng đều **không cần giải mã payload**:

| Nhóm | Đặc trưng |
|------|-----------|
| Thống kê gói tin | `n_pkts_total`, `bytes_total`, `pkt_len_mean/std/min/max` |
| Hướng traffic | `n_pkts_fwd/bwd`, `bytes_fwd/bwd`, `fwd_bwd_pkt_ratio` |
| Inter-arrival time | `iat_mean`, `iat_std`, `iat_min`, `iat_max` |
| Throughput | `fwd_pkt_per_sec`, `bwd_pkt_per_sec` |
| Giao thức | `dest_port`, `is_tcp`, `is_udp` |

---

## 🧪 Kiểm thử

```bash
# Chạy toàn bộ test suite
pytest test_rule_engine.py -v

# Kiểm thử dataset builder
pytest test_ml_dataset_builder.py -v

# Kiểm tra rules Layer 1
python3 verify_layer1_rules.py
```

---

## 📖 Tài liệu liên quan

- [Hướng dẫn cài đặt Raspberry Pi](tools/PI_SETUP.md)
- [Kết quả đánh giá mô hình](ml/results/report.html)

---

## 📝 Ghi chú

- File PCAP không được đẩy lên GitHub (quá lớn) — xem `.gitignore`
- Model files lớn (`model_final.txt`) không được đẩy lên — dùng `git lfs` nếu cần
- Dữ liệu huấn luyện được sinh tổng hợp bằng `ml/gen_synthetic.py`
