# Hybrid Network Application Identification

> Tài liệu chuẩn cho developer và AI Coding Agent. Giữ nguyên thứ tự **DNS → SNI → Burst-based ML → Late Fusion / Stacking → Application Classification**.

## 1. Mục tiêu
Nhận diện ứng dụng từ metadata và hành vi packet/flow, không giải mã payload ứng dụng.

## 2. Runtime architecture bắt buộc

```text
Packet Capture
  → Packet Parsing & Flow Tracking
  → DNS Parser + continuously updated, client-scoped DNS Cache
  → DNS-based Application Identification (Domain Rules + TTL + ambiguity check)
      ├─ DNS_IDENTIFIED → Application Result (END)
      └─ DNS_UNRESOLVED
          → TLS Parser + SNI Mapping
              ├─ SNI_IDENTIFIED → Application Result (END)
              └─ SNI_UNRESOLVED
                  → Bidirectional Flow Reconstruction
                  → Burst Segmentation
                      ├─ Burst Statistics → CatBoost
                      └─ Burst Sequence → 1D-CNN (PyTorch)
                  → Late Fusion / Stacking
                  → Application Classification
                  → Application label / UNKNOWN
```

**DNS rule:** cache được cập nhật liên tục và scope theo client; lookup dùng client IP + destination IP + Flow timestamp. Nhiều domain cùng IP nhưng cùng map một Application vẫn có thể identified; nhiều Application candidate thì unresolved. DNS identified thì bind kết quả vào Flow và packet sau reuse, không chờ packet thứ N.

**Early exit:** DNS identified thì không gọi SNI/ML. SNI chỉ chạy khi DNS unresolved. SNI identified thì không gọi ML. ML chỉ chạy khi cả DNS và SNI unresolved. Không được đổi thứ tự hoặc chạy ba tầng song song.

Ảnh kiến trúc gốc: `images/flow-overview.png`.

## 3. Module responsibilities

| Module | Trách nhiệm |
|---|---|
| Capture / Packet Parser | Nhận live interface hoặc PCAP, parse packet metadata |
| Flow Tracker | Gom packet, tạo Flow ID, xác định direction |
| DNS Parser / Cache / Identifier | Parser tạo response observations; Cache lưu client/domain/IP/CNAME/TTL liên tục; Identifier match verified Domain Rules và xử lý shared-IP ambiguity |
| TLS/SNI Parser / Mapper | Trích SNI từ ClientHello và map hostname |
| Flow Reconstructor | Tái tạo packet sequence hai chiều |
| Burst Segmenter | Chia packet sequence thành Burst |
| Burst Statistics | Tạo tabular features cho CatBoost |
| Burst Sequence Encoder | Encode chuỗi Burst cho 1D-CNN |
| CatBoost / 1D-CNN | Hai nhánh inference độc lập trên cùng Flow observation |
| Fusion | Hợp nhất scores từ hai branch |
| Application Classifier | Trả application label hoặc UNKNOWN |

Xem `edge-ai-project-docs/13-module-contracts.md` để biết data contract cụ thể.

## 4. Technology baseline

- Python
- Scapy cho packet capture/parsing
- YAML cho cấu hình
- CatBoost cho Burst Statistics
- **PyTorch cho 1D-CNN**
- pytest cho testing
- Rich cho CLI/logging nếu cần

PyTorch được chọn làm framework 1D-CNN. Điều này không có nghĩa source/model artifact đã tồn tại. Trạng thái implementation phải được xác minh riêng.

## 5. Source tree mục tiêu

```text
project/
├── config/
│   ├── app.yaml
│   ├── dns_mapping.yaml
│   ├── sni_mapping.yaml
│   └── model.yaml
├── src/appid/
│   ├── domain/models.py
│   ├── network/interfaces.py
│   ├── capture/{live,pcap}.py
│   ├── packet/parser.py
│   ├── pipeline/processor.py
│   ├── flow/{identity,tracker}.py
│   ├── dns/{models,parser,cache,domain_rules,identifier}.py
│   ├── tls/{client_hello,sni_mapper}.py
│   ├── burst/{reconstruction,segmentation,statistics,sequence}.py
│   ├── models/{catboost_model,cnn_1d,fusion}.py
│   └── inference/{classifier,orchestrator}.py
├── artifacts/{catboost,cnn,fusion}/
├── datasets/
├── tests/{unit,integration,fixtures}/
└── tools/
```

Đây là cấu trúc mục tiêu, không phải khẳng định các file đã có. Trước khi tạo source, Coding Agent phải kiểm tra repository hiện tại để tránh ghi đè/trùng chức năng.

## 6. Contract xuyên suốt

Giữ lineage `session_id → flow_id → burst_id`. Packet tối thiểu giữ timestamp, packet index, direction và packet length. Hai ML branch phải nhận dữ liệu từ cùng Flow observation và dùng cùng class mapping/order. Mọi prediction phải truy vết được về Flow và evidence.

Chi tiết type/field/input/output: `13-module-contracts.md`.

## 7. Implementation parameters

Thông số chia thành `FIXED`, `CONFIGURABLE`, `OPEN`. Không tự bịa giá trị cho idle-gap, direction-change boundary, feature list/order, CNN tensor shape/sequence length, padding/truncation, hyperparameters, fusion algorithm hoặc confidence threshold. Bảng chi tiết tại `14-implementation-parameters.md`.

## 8. Training / evaluation

- Dataset lineage: session → flow → burst.
- Group split theo session/batch; không để samples cùng Flow rơi vào nhiều split.
- Branch A: Burst Statistics → CatBoost.
- Branch B: Burst Sequence → PyTorch 1D-CNN.
- Fusion fit bằng validation outputs; test holdout chỉ dùng đánh giá cuối.
- Báo cáo Macro F1, weighted F1, per-class precision/recall/F1, confusion matrix và reject rate nếu có.
- Flow/Device LightGBM scripts cũ chỉ là baseline; không tự xem là CatBoost/1D-CNN implementation.

## 9. Cài đặt và kiểm thử

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
pytest -q
```

Lệnh chạy PCAP/live chỉ được ghi vào README sau khi entrypoint thật được implement; không dùng lệnh CLI giả định.

## 10. Hướng dẫn cho Coding Agent

1. Đọc README, `01-system-architecture.md`, `02-runtime-packet-flow.md`, `13-module-contracts.md`, `14-implementation-parameters.md`.
2. Kiểm tra source và tests hiện có trước khi tạo file.
3. Triển khai theo thứ tự packet/flow → DNS → SNI → reconstruction/burst → features → models → fusion → orchestrator.
4. Không đổi Hybrid order và không tự giải quyết mục `OPEN`.
5. Viết unit test cho từng contract; integration test phải chứng minh DNS/SNI early exit và ML fallback.
6. Cập nhật `11-roadmap-and-status.md` khi trạng thái code thay đổi.

## 11. Definition of Done
Module chỉ được đánh dấu TESTED khi code tồn tại, contract được thực hiện, tests pass, có fixture/PCAP tái lập, lineage đầy đủ và tài liệu khớp implementation.

## 12. Tài liệu
Các tài liệu `00`–`12` giữ nguyên vai trò hiện tại. Hai tài liệu bổ sung:
- `13-module-contracts.md`: interfaces và data contracts giữa module.
- `14-implementation-parameters.md`: parameter registry, trạng thái FIXED/CONFIGURABLE/OPEN.

## 8. P0.7.3 QUIC status

P0.7.3 adds a standalone QUIC v1 Initial inspector under
`src/appid/udp/quic/`. It uses Python `cryptography` for RFC 9001 Initial key
schedule, AES header protection and AES-128-GCM validation, then parses Initial
frames, reassembles CRYPTO data and extracts visible ClientHello/SNI. It is not
yet connected to the shared live/PCAP PacketProcessor; that integration is
P0.7.4. See `architecture/quic-v1-initial-parsing.md` and
`testing/p0.7.3-quic-v1-initial.md`.

## Next implementation increment

P1.0 is **ML Candidate Gate + immutable Flow observation adapter**. Reuse existing FlowTracker/FlowState; do not create a second bidirectional Flow identity. P1.0 does not implement Burst segmentation or ML models. See [`../architecture/decision-ml-flow-order.md`](../architecture/decision-ml-flow-order.md).
