# Hướng Dẫn Thu Thập Traffic Trên Laptop (Linux)

> Dùng khi chưa có Raspberry Pi hoặc muốn thu thập nhanh trên máy cá nhân.

---

## Yêu cầu

- Linux (Ubuntu / Debian)
- Có kết nối WiFi
- Quyền sudo

---

## Bước 1 — Tìm tên card mạng WiFi

```bash
ip link show
# Tìm dòng có state UP → thường là wlp62s0, wlan0, ...
# Ví dụ: wlp62s0 UP 192.168.1.22
```

---

## Bước 2 — Kích hoạt môi trường ảo

```bash
cd "/home/phuong/Documents/DO AN TOT NGHIEP"
source .venv/bin/activate
```

---

## Bước 3 — Thu thập từng app

### Cú pháp lệnh

```bash
sudo python3 tools/capture_session.py \
    --batch <tên_batch> \
    --iface <tên_card_mạng> \
    --dur 30 \
    --apps <tên_app>
```

### Ví dụ cụ thể

```bash
# Thu YouTube (30 phút)
sudo python3 tools/capture_session.py \
    --batch batch1 --iface wlp62s0 --dur 30 --apps youtube

# Thu Spotify (30 phút)
sudo python3 tools/capture_session.py \
    --batch batch1 --iface wlp62s0 --dur 30 --apps spotify

# Thu nhiều app cùng lúc (nối tiếp nhau)
sudo python3 tools/capture_session.py \
    --batch batch1 --iface wlp62s0 --dur 30 \
    --apps youtube spotify zalo
```

---

## Danh sách app và kịch bản sử dụng

| App | Lệnh | Việc cần làm trong 30 phút |
|-----|------|--------------------------|
| YouTube | `--apps youtube` | Xem video liên tục, đổi chất lượng 360p→1080p |
| Spotify | `--apps spotify` | Nghe nhạc playlist, KHÔNG tạm dừng |
| Zalo | `--apps zalo` | Nhắn tin 2 phút/lần, gửi 2-3 ảnh, 1 cuộc gọi thoại |
| Google Meet | `--apps meet` | Gọi video 2 chiều (cần người thứ 2) |
| ChatGPT | `--apps chatgpt` | Đặt 10+ câu hỏi dài, chờ trả lời xong rồi mới hỏi |
| other-idle | `--apps other-idle` | Để màn hình bật, KHÔNG chạm gì cả |
| other-web | `--apps other-web` | Duyệt VnExpress, Wikipedia, GitHub (KHÔNG mở app trên) |
| other-update | `--apps other-update` | Vào Play Store/App Store tải cập nhật nhiều app |

---

## Lịch thu thập theo buổi (batch)

### Batch 1 — Buổi chiều/tối
```
16:00 → 16:30  other-idle      (để máy)
16:30 → 17:00  other-web       (duyệt web)
17:00 → 17:30  Spotify         (nghe nhạc)
17:30 → 18:00  ChatGPT         (hỏi AI)
18:00 → 18:30  Zalo            (nhắn tin)
18:30 → 19:00  YouTube         (xem video)
19:00 → 19:30  other-update    (tải update)
19:30 → 20:00  Meet            (cần người thứ 2)
```

### Batch 2 — Buổi sáng (ngày hôm sau)
```
08:00 → ...    Lặp lại 8 app theo thứ tự bất kỳ
```

### Batch 3 — Buổi tối (ngày hôm sau)
```
20:00 → ...    Lặp lại 8 app
```

> Thu ít nhất 3 batch, lý tưởng 5 batch để model đủ mạnh.

---

## Checklist trước khi thu thập

```
[ ] Tắt VPN
[ ] Đóng hết app không cần thiết (Telegram, Facebook...)
[ ] Kết nối WiFi ổn định
[ ] Pin > 50% hoặc cắm sạc
[ ] Báo người thứ 2 sẵn sàng (cho Meet)
[ ] Chuẩn bị câu hỏi dài cho ChatGPT
[ ] Chuẩn bị playlist Spotify
[ ] Chuẩn bị danh sách app cần update trong Store
```

---

## Kiểm tra kết quả sau khi thu

```bash
# Xem file đã tạo
ls -lh captures/batch1/

# Phải thấy:
# capture_batch1_*.pcap     (> 50MB/app là ổn)
# labels_batch1_*.jsonl
# session_batch1_*.json
```

---

## Sau khi thu đủ 3 batch → Build dataset

```bash
# Build CSV dataset
python3 -m ml.dataset_builder --sessions captures/ --out ml/data/

# Kiểm tra
python3 -c "
import pandas as pd
df = pd.read_csv('ml/data/dataset_flow.csv')
print(df['label'].value_counts())
"

# Train model
python3 -m ml.train_flow
python3 -m ml.train_device
```

---

## Lỗi thường gặp

| Lỗi | Giải pháp |
|-----|----------|
| `Interface wlp61s0 không tồn tại` | Chạy `ip link show` tìm tên đúng (vd: `wlp62s0`) |
| `PermissionError` | Thêm `sudo` vào đầu lệnh |
| File PCAP < 5MB | App không thực sự chạy, thu lại |
| Meet chỉ 1 chiều | Yêu cầu người thứ 2 bật cả camera lẫn mic |
