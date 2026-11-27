# 10 — Testing và Troubleshooting

## 1. Mục đích

Kiểm chứng từng module và toàn bộ thứ tự Hybrid flow. Một demo có output không đủ để chứng minh pipeline đúng.

## 2. Test matrix

| Module | Ca kiểm thử tối thiểu |
|---|---|
| Capture | live input, PCAP input, empty PCAP, timestamp |
| Packet Parser | TCP, UDP, malformed packet, unsupported layer |
| Flow Tracker | hai chiều, server-first, timeout, tuple reuse |
| ML Candidate Gate | DNS/SNI early exit, explicit policy, pending, one-way, duplicate index, invalid metadata |
| DNS Parser | QR, RCODE, QNAME/QTYPE, A/AAAA/CNAME, UDP/TCP framing, malformed/truncated message |
| DNS Cache | TTL=0, expiry boundary, CNAME minimum expiry, refresh, multiple domains/IPs, session and client scope |
| DNS Identifier | exact/suffix boundary, exact precedence, conflicting rules, shared IP same-app vs cross-app, unknown client, Flow binding/reuse |
| SNI | ClientHello một packet/nhiều segment, no SNI, ECH |
| Reconstruction | forward/backward ordering, missing direction |
| Burst Segmentation | idle gap, direction change, empty/short flow |
| CatBoost | feature order, missing artifact, class order |
| 1D-CNN | tensor shape, padding/truncation, missing artifact |
| Fusion | matching classes, branch conflict, missing branch |
| Application Classifier | threshold, UNKNOWN, reason code |

## 3. Test thứ tự Hybrid bắt buộc

1. DNS identified → output application; SNI call count = 0; ML call count = 0.
2. DNS unresolved (cache miss, TTL expired, client unknown, unmapped domain, shared-IP ambiguity) → SNI is called.
3. DNS identified from multiple domain candidates all mapping to one Application → still identified.
4. Packet after DNS identification in the same Flow → reuses Flow result; no repeated DNS cache lookup.
5. DNS unresolved + SNI identified → output application; ML call count = 0.
6. DNS unresolved + SNI unresolved → ML call count = 1.
7. ML branch chạy → CatBoost và 1D-CNN nhận đúng observation.
8. Hai branch output → Late Fusion được gọi.
9. Confidence dưới threshold → `UNKNOWN`.
10. Parser phụ lỗi → Flow tracking vẫn giữ packet hợp lệ.

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

## Current test/evidence boundary — 2026-11-27

### Automated suite

Owner-supplied prior result for the project state described in the handover:

```bash
python -m compileall -q src/appid
PYTHONPATH="$PWD" pytest -q
# 195 passed, 1 skipped, 1 warning in 1.81s
```

This review did not rerun the suite on the ZIP. Do not report it as a fresh run. The archive includes unit tests across packet, Flow, DNS, SNI, UDP/QUIC, ML gate/Burst/statistics, PacketProcessor and capture wrappers, plus PCAP/Burst integration. No dedicated CatBoost inference test module is present.

### ML live smoke evidence

A separate owner-supplied live run with `--ml-model` recorded 24 candidate Flows evaluated, 23 admitted, 1 pending, 23 predictions and 0 inference errors. It establishes model loading and inference execution only; no ground truth was collected and correctness is not known.

### Status

`DONE` for documented prior unit-suite evidence; `NOT VERIFIED` for a fresh run against this ZIP, CatBoost accuracy, model-enabled PCAP end-to-end acceptance, inference latency and CPU/RAM profiling.

### Remaining

Do not rerun network capture or large PCAP as part of documentation handover. A future acceptance plan should add a small deterministic model-enabled PCAP fixture and ground-truth comparison, then separately profile live resource usage.
