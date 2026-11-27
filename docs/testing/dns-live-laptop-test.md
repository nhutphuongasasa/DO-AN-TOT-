> **Historical acceptance note (2026-11-26):** This report records a run from
> before the strict DNS-first early-exit correction. Any `hybrid_dns_sni`
> result shown below is historical evidence of the earlier implementation;
> the current runtime skips SNI after DNS identification.

# Laptop live test — Hybrid DNS + TCP/SNI Application Identification

## Mục tiêu

Kiểm tra đường đi DNS và TCP/SNI trong cùng PacketProcessor trên laptop thật: `DNS Query/Response → DNS Cache → DNS AppID`, song song với `TCP Flow → TCP Reassembly → TLS ClientHello → SNI AppID`.

## 1. Cài đặt (Linux)

```bash
cd hybrid-appid-starter
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e "[dev]"
python -c "import scapy; print('Scapy:', scapy.__version__)"
```

## 2. Chọn đúng card mạng

```bash
ip -br addr
```

Thay `wlp62s0` bằng interface Wi-Fi/Ethernet đang kết nối:

```bash
./run_dns_test.sh --interface wlp62s0 --duration 180
```

Hoặc đặt `config/network.json` về manual:

```json
{
  "network": {
    "mode": "manual",
    "interface": "wlp62s0"
  }
}
```

Rồi chạy:

```bash
./run_dns_test.sh --duration 180
```

## 3. Tạo DNS và application traffic

Bắt đầu capture trước khi tạo kết nối mới. SNI chỉ xuất hiện trong TLS ClientHello; kết nối đã mở trước khi capture hoặc kết nối tái sử dụng có thể không tạo ClientHello mới trong thời gian test.

Trong lúc terminal capture đang chạy, mở terminal thứ hai và chạy lần lượt:

```bash
nslookup chatgpt.com
curl -I --connect-timeout 10 https://chatgpt.com

nslookup facebook.com
curl -I --connect-timeout 10 https://www.facebook.com

nslookup tiktok.com
curl -I --connect-timeout 10 https://www.tiktok.com

nslookup youtube.com
curl -I --connect-timeout 10 https://www.youtube.com

nslookup spotify.com
curl -I --connect-timeout 10 https://open.spotify.com
```

Có thể mở website/app thay cho `curl`, nhưng phải tạo traffic trong lúc capture. Chạy các lệnh trên chính laptop đang capture. `nslookup` tạo truy vấn DNS mới; `curl` tạo kết nối tới domain vừa tra cứu.

## 4. Kết quả mong đợi

Khi nhận đủ DNS response và application Flow tương ứng, capture sẽ in dạng:

```text
[APP IDENTIFIED] app=chatgpt method=dns|sni|hybrid_dns_sni ...
[APP IDENTIFIED] app=facebook method=dns|sni|hybrid_dns_sni ...
[APP IDENTIFIED] app=tiktok method=dns|sni|hybrid_dns_sni ...
[APP IDENTIFIED] app=youtube method=dns|sni|hybrid_dns_sni ...
[APP IDENTIFIED] app=spotify method=dns|sni|hybrid_dns_sni ...
```

Cuối phiên:
- `DNS bindings created > 0`: DNS parser đã tạo mapping.
- `DNS-identified Flows > 0`: có Flow được nhận diện bằng DNS.
- `SNI ClientHellos > 0`: đã phân tích được ClientHello.
- `SNI-identified Flows > 0`: có Flow được nhận diện bằng SNI.
- `method=hybrid_dns_sni`: DNS và SNI cùng xác nhận một ứng dụng.
- `[PASS]`: cả năm ứng dụng mục tiêu xuất hiện qua DNS và/hoặc TCP SNI.
- `[PARTIAL]`: chỉ một phần ứng dụng được nhận diện.
- `[NOT CONFIRMED]`: chưa có Flow ứng dụng nào được nhận diện.

`other-web` không phải catch-all domain rule. Hostname không khớp 5 app vẫn để UNKNOWN/unclassified cho nhánh ML sau này.

## 5. Nếu không nhận diện được

1. Kiểm tra đúng interface với `ip -br addr`.
2. Chạy bằng `sudo`.
3. Chạy `nslookup` trong khi capture.
4. DoH/DoT có thể làm DNS response không xuất hiện dưới dạng DNS port 53.
5. Nếu DNS mapping đã tạo nhưng không có Flow identified, kiểm tra app traffic được tạo sau lookup và destination IP có nằm trong DNS answer hay không.
6. Không dùng `--dns-only` cho bài test nhận diện Flow; tùy chọn này chỉ để chẩn đoán DNS.

## 6. Unit tests

```bash
.venv/bin/python -m compileall -q src tests scripts
.venv/bin/python -m pytest -q
```

Sau khi cài dependencies, Scapy parser tests phải chạy thay vì skip. Nếu còn skip, gửi nguyên output.

## 7. Phạm vi

Bài test xác nhận DNS và SNI trên laptop/interface đã chọn. Nó không chứng minh laptop có thể nhìn thấy traffic của mọi thiết bị LAN khác; việc đó cần gateway capture hoặc switch mirror/SPAN. ECH, kết nối bắt đầu trước capture, TLS không có SNI và QUIC/HTTP3 có thể khiến TCP SNI không quan sát được.

## Acceptance test nâng cao (P0.5.4 + P0.6.3–P0.6.5)

Lệnh `./run_dns_test.sh --interface <NIC> --duration 180` hiện chạy trước:

1. DNS acceptance scenarios xác định: 5 domain rules (ChatGPT/Facebook/TikTok/YouTube/Spotify), shared IP cùng Application, shared IP khác Application (phải ambiguous), client isolation và TTL expiry.
2. Toàn bộ unit tests.
3. Live capture trên NIC được chọn, xử lý DNS và TCP/SNI qua cùng PacketProcessor.

Trong lúc live capture, mở terminal thứ hai tại thư mục dự án và chạy:

```bash
./generate_dns_test_traffic.sh
```

Script tạo `nslookup` và HTTPS request cho 5 dịch vụ. Kết quả live chỉ PASS đầy đủ khi cả 5 Application ID xuất hiện trong cùng phiên capture. Nếu mới nhận diện một phần, kết quả là PARTIAL và liệt kê ứng dụng chưa quan sát được; không coi đó là hoàn thành.

Lưu ý: các scenario shared-IP/client-isolation/TTL là kiểm thử logic xác định bằng dữ liệu DNS tổng hợp, không phải bằng chứng các dịch vụ Internet thật đang dùng chung IP. Live test kiểm chứng DNS/TCP/SNI thật trên laptop. Script không thể ép server/browser dùng TCP thay vì QUIC; nếu trình duyệt chuyển sang QUIC thì SNI parser TCP không nhìn thấy ClientHello UDP.

## P0.6.3–P0.6.5 TCP/SNI integration

The live test now reports the classification method (`dns`, `sni`, or
`hybrid_dns_sni`) and the DNS/SNI hostnames used as evidence. It counts each
Flow once per current application, including correcting the count if a later
higher-quality SNI result changes a DNS classification. The acceptance test
expects all five named apps across DNS and/or TCP SNI, not DNS alone.

For a targeted TCP-only SNI check, start capture before creating a new TLS
connection and ensure the client negotiates TCP (for example, disable QUIC in
the test browser or use `curl --http1.1` / `curl --http2` where available).
Do not infer TCP SNI coverage from a browser session that uses HTTP/3 over QUIC.

## P0.5.7 parser regression fix

P0.5.7 normalizes Scapy's DNS question/answer sections whether they are
single packet objects or PacketListField lists (the latter is used after live
packet dissection in Scapy 2.8). It also safely ignores responses with an empty
question section rather than allowing an `IndexError` to escape into the
pipeline. The live summary reports exception classes for any remaining
unexpected DNS processing errors.

The new serialized/deserialized CNAME+A regression test must run on the laptop
with Scapy installed; do not count it as verified if the Scapy-dependent tests
are skipped.
