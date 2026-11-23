# 11 — Roadmap và trạng thái

## 1. Quy ước trạng thái

- `IMPLEMENTED`: có source code xác định.
- `TESTED`: có test pass hoặc bằng chứng replay.
- `DESIGNED`: có trong sơ đồ/tài liệu, chưa xác nhận code.
- `OPEN`: thiếu thông số hoặc quyết định.

Không nâng trạng thái chỉ dựa trên sơ đồ.

## 2. Trạng thái theo snapshot được cung cấp

| Hạng mục | Trạng thái có thể xác nhận | Việc tiếp theo |
|---|---|---|
| Scapy dependency | IMPLEMENTED (dependency khai báo) | Xác minh runtime capture call path |
| Flow/Device ML scripts | IMPLEMENTED (file tồn tại) | Kiểm tra API, model type và metrics |
| Flow label encoder | IMPLEMENTED (artifact tồn tại) | Đồng bộ class mapping |
| DNS → SNI → Burst ML orchestration | DESIGNED | Tìm/viết orchestrator và test call order |
| DNS Cache hardening | DESIGNED / OPEN | Xác minh source, TTL, client scope |
| SNI mapping | DESIGNED / OPEN | Xác minh parser và rules |
| Bidirectional Flow Reconstruction | DESIGNED | Chốt input/output contract |
| Burst Segmentation | DESIGNED | Chốt boundary rule |
| CatBoost branch | DESIGNED / OPEN | Xác nhận implementation và artifact |
| 1D-CNN branch | DESIGNED / OPEN | Xác nhận framework, tensor schema |
| Late Fusion / Stacking | DESIGNED / OPEN | Chốt algorithm và training protocol |
| Final UNKNOWN policy | DESIGNED / OPEN | Chốt thresholds và reason codes |

## 3. Thứ tự triển khai

### P0 — Chốt contract
- [ ] Xác minh packet/Flow record hiện có.
- [ ] Chốt Flow ID, direction và packet ordering.
- [ ] Chốt DNS observation/cache lookup contract.
- [ ] Chốt SNI mapping contract.
- [ ] Chốt output result schema.

### P1 — Hoàn thiện rule-first path
- [ ] DNS Parser + DNS Cache.
- [ ] DNS Application Identification.
- [ ] TLS ClientHello Parser + SNI Mapping.
- [ ] Unit/integration tests cho DNS → SNI precedence.

### P2 — Hoàn thiện Burst input
- [ ] Bidirectional Flow Reconstruction.
- [ ] Burst Segmentation.
- [ ] Burst Statistics schema.
- [ ] Burst Sequence tensor schema.
- [ ] Offline/runtime parity tests.

### P3 — Hoàn thiện ML
- [ ] CatBoost training/inference.
- [ ] 1D-CNN training/inference.
- [ ] Late Fusion / Stacking.
- [ ] Confidence calibration và UNKNOWN policy.

### P4 — End-to-end validation
- [ ] PCAP replay qua toàn bộ Hybrid flow.
- [ ] Kiểm tra call order và branch skipping.
- [ ] Báo cáo per-class metrics.
- [ ] Đo latency/RAM trên thiết bị Edge.
- [ ] Đồng bộ README, architecture và code.

## 4. Definition of Done

Một module chỉ được đánh dấu `TESTED` khi:
- code có mặt;
- interface/input/output được mô tả;
- unit/integration test liên quan pass;
- có ít nhất một PCAP/test fixture tái lập;
- log có thể truy vết Flow ID;
- tài liệu khớp implementation.

## 5. Change log template

- Ngày:
- Module:
- Thay đổi:
- Lý do:
- File/code:
- Test:
- Kết quả:
- Tài liệu cập nhật:
