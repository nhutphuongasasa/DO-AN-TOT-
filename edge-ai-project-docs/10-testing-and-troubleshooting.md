# 10 — Testing và Troubleshooting

## 1. Mục đích

Kiểm chứng từng module và toàn bộ thứ tự Hybrid flow. Một demo có output không đủ để chứng minh pipeline đúng.

## 2. Test matrix

| Module | Ca kiểm thử tối thiểu |
|---|---|
| Capture | live input, PCAP input, empty PCAP, timestamp |
| Packet Parser | TCP, UDP, malformed packet, unsupported layer |
| Flow Tracker | hai chiều, server-first, timeout, tuple reuse |
| DNS | QR, RCODE, A/AAAA, CNAME, TTL, shared IP, client scope |
| SNI | ClientHello một packet/nhiều segment, no SNI, ECH |
| Reconstruction | forward/backward ordering, missing direction |
| Burst Segmentation | idle gap, direction change, empty/short flow |
| CatBoost | feature order, missing artifact, class order |
| 1D-CNN | tensor shape, padding/truncation, missing artifact |
| Fusion | matching classes, branch conflict, missing branch |
| Application Classifier | threshold, UNKNOWN, reason code |

## 3. Test thứ tự Hybrid bắt buộc

1. DNS identified → output application; SNI call count = 0; ML call count = 0.
2. DNS unresolved + SNI identified → output application; ML call count = 0.
3. DNS unresolved + SNI unresolved → ML call count = 1.
4. ML branch chạy → CatBoost và 1D-CNN nhận đúng observation.
5. Hai branch output → Late Fusion được gọi.
6. Confidence dưới threshold → `UNKNOWN`.
7. Parser phụ lỗi → Flow tracking vẫn giữ packet hợp lệ.

## 4. Replay xác định

Với cùng PCAP, config và code version:
- so sánh packet count;
- so sánh Flow grouping và direction;
- so sánh DNS observations;
- so sánh Burst boundaries;
- so sánh feature vectors;
- so sánh prediction và evidence.

Mọi khác biệt phải có nguyên nhân được ghi nhận.

## 5. Wireshark filters

```text
dns && dns.flags.response == 1
tls.handshake.type == 1
quic
ip.addr == 192.168.1.15
```

## 6. Troubleshooting

| Triệu chứng | Kiểm tra |
|---|---|
| App toàn UNKNOWN | DNS/SNI evidence, ML readiness, input size, thresholds |
| DNS Cache rỗng | Capture DNS Response, DoH/DoT, parser QR/RCODE |
| DNS identify nhầm | Client scope, shared IP, TTL, domain mapping |
| SNI null | ECH, TLS reassembly, QUIC parser support |
| Burst count bất thường | Timestamp ordering, idle-gap config, direction |
| CatBoost error | Feature names/order, artifact version |
| 1D-CNN shape error | Sequence schema, padding/truncation |
| Fusion error | Class order, missing branch output, calibration |
| Live khác PCAP | Capture timestamp, packet loss, source path |

## 7. Tiêu chí đóng bug

- [ ] Có test tái hiện trước khi sửa.
- [ ] Test mới và test liên quan đều pass.
- [ ] Replay PCAP không tạo regression.
- [ ] Cập nhật tài liệu nếu contract/semantics thay đổi.
