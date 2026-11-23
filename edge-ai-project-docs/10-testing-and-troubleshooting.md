# 10 – Kiểm thử và xử lý sự cố

## 1. Nguyên tắc

Mỗi rủi ro kiến trúc phải có test tái hiện. Không chỉ chạy demo thấy dashboard có dữ liệu rồi kết luận pipeline đúng.

## 2. Test theo module

| Module | Test quan trọng |
|---|---|
| DNS parser/cache | QR bit, RCODE, TTL, CNAME, shared IP, client isolation |
| TLS parser | ClientHello một packet và nhiều TCP segments, thiếu SNI, ECH |
| QUIC parser | QUIC v1/v2, thiếu Initial packet, decrypt fail |
| Flow Tracker | hai chiều, server-first, timeout, tuple reuse |
| Dataset builder | nhãn biên session, flow cắt START/END, sample rỗng |
| Feature extraction | zero division, missing values, unit, direction |
| Burst extractor | idle gap, direction change, packet ordering |
| Predictor | schema mismatch, model missing, insufficient data |
| Pipeline | offline/live parity, parser fail không làm dừng flow |

## 3. Replay xác định

Dùng cùng PCAP, cùng config và cùng phiên bản code:
- replay hai lần;
- so sánh số flow;
- so sánh packet/byte count;
- so sánh feature vectors;
- so sánh kết quả classification.

Sai khác phải được giải thích, ví dụ do nondeterministic ordering hoặc timestamp handling.

## 4. Wireshark filters tham khảo

```text
dns && dns.flags.response == 1
tls.handshake.type == 1
quic && quic.long.packet_type == 0
ip.addr == 192.168.1.15
```

## 5. Kiểm tra log

README cũ gợi ý:
```bash
tail -10 traffic_events.jsonl | python3 -m json.tool
```

Nếu JSONL là mỗi dòng một JSON object, lệnh trên có thể không parse nhiều dòng như một JSON document. Dùng:
```bash
tail -10 traffic_events.jsonl | while IFS= read -r line; do
  printf '%s\n' "$line" | python3 -m json.tool
done
```

Đường dẫn log thực tế cần kiểm tra từ config/runtime.

## 6. Triệu chứng thường gặp

| Triệu chứng | Khả năng nguyên nhân | Kiểm tra |
|---|---|---|
| App toàn `unknown` | Thiếu SNI/DNS hoặc ML chưa đủ data | Log metadata, flow stats, model status |
| `sni=null` | QUIC, ECH, parser/reassembly | Kiểm tra packet và parser result |
| DNS cache rỗng | DoH/DoT, không bắt response, parser filter sai | Wireshark DNS response |
| Dashboard không có thiết bị | Sai LAN subnet/interface hoặc MAC/IP mapping | Capture packet, registry |
| PCAP ít packet | Chọn sai interface hoặc app không phát traffic | tcpdump/Wireshark |
| ML dự đoán bất thường | Feature mismatch, leakage, label noise | Schema, split, confusion matrix |
| Burst kết quả dao động | Boundary rule nhạy với gap threshold | Phân tích burst timeline |

## 7. Tiêu chí đóng bug

Một bug chỉ được đánh dấu fixed khi:
1. có test tái hiện trước sửa;
2. code được sửa;
3. test cũ và test mới đều pass;
4. replay PCAP không tạo regression;
5. cập nhật tài liệu nếu semantics thay đổi.
