# 12 — Glossary và Architecture Decisions

## 1. Thuật ngữ

| Thuật ngữ | Ý nghĩa |
|---|---|
| Packet | Gói tin mạng |
| PCAP | File lưu packet capture |
| Flow | Nhóm packet thuộc cùng kết nối logic |
| 5-tuple | Source IP/port, destination IP/port, protocol |
| Flow ID | Định danh Flow trong capture/session |
| Direction | Chiều packet so với client/LAN endpoint |
| DNS Cache | Kho bằng chứng DNS client/domain/IP/CNAME có TTL, cập nhật liên tục; không phải IP→Application map |
| Application Domain Rules | Danh sách domain đã xác minh gắn với Application ID |
| DNS Application Identifier | Module tra DNS Cache, match Domain Rules và kết luận DNS identified/unresolved |
| DNS Identified | DNS evidence đủ điều kiện map application |
| DNS Unresolved | DNS không đủ điều kiện; chuyển sang SNI |
| SNI | Server Name Indication trong TLS ClientHello |
| SNI Identified | SNI map được application |
| SNI Unresolved | SNI không đủ điều kiện; chuyển sang ML |
| Burst | Nhóm packet liên tiếp theo segmentation rule |
| Burst Statistics | Feature thống kê của Burst |
| Burst Sequence | Chuỗi Burst có thứ tự |
| CatBoost | Model Branch A trong sơ đồ |
| 1D-CNN | Model Branch B trong sơ đồ |
| Late Fusion / Stacking | Giai đoạn hợp nhất output hai branch |
| UNKNOWN | Không đủ evidence/confidence để trả application |
| Session | Một lần thu thập có PCAP và metadata |
| Data leakage | Dữ liệu cùng nguồn lọt qua train/test split |

## 2. Quyết định kiến trúc bắt buộc

### D1 — DNS trước SNI
DNS-based Application Identification là phương án đầu tiên. SNI chỉ được gọi khi DNS unresolved.

### D2 — SNI trước ML
TLS SNI Mapping là phương án thứ hai. ML chỉ được gọi khi SNI unresolved.

### D3 — Early exit
Flow được DNS hoặc SNI identified phải trả Application và bỏ qua ML.

### D4 — Hai nhánh ML
Branch A dùng Burst Statistics + CatBoost. Branch B dùng Burst Sequence + 1D-CNN.

### D5 — Late Fusion
Output hai branch được hợp nhất ở Late Fusion / Stacking trước Application Classification.

### D6 — UNKNOWN hợp lệ
Thiếu evidence, input, model hoặc confidence thì trả `UNKNOWN`; không ép nhãn.

### D7 — Shared IP không phải định danh
Một IP có thể phục vụ nhiều domain/application. DNS lookup phải giữ ambiguity.

### D8 — Offline/runtime parity
Dataset builder và runtime dùng chung Flow/Burst/feature contract.

### D9 — Giữ metadata lineage
Mọi Burst và prediction phải truy ngược được về `flow_id` và `session_id` khi có.


### D11 — DNS Cache là evidence store, không phải Application map

DNS Parser tạo observations; DNS Cache lưu client-scoped Domain/CNAME/IP bindings theo TTL; DNS Application Identifier mới quyết định Application bằng Application Domain Rules. Cache lookup theo client IP + destination IP + Flow timestamp, không theo IP đơn lẻ.

### D12 — DNS early identification và Flow result reuse

Tại lần DNS evaluation đầu tiên khi Flow đủ metadata/evidence, có thể kết luận ngay; không có packet-N threshold riêng. Khi identified, bind Application và evidence snapshot vào Flow để packet sau reuse. TTL hết hạn không làm mất kết quả Flow đã identified, nhưng không cho phép mapping hết hạn nhận diện Flow mới.

### D13 — Shared IP candidate aggregation

Nếu nhiều domain candidates hợp lệ cùng map một Application ID thì DNS identified. Nếu candidates map nhiều Application ID thì DNS unresolved và chuyển SNI. Không chọn candidate theo thứ tự, độ mới, TTL lớn nhất hoặc số packet.

### D14 — Domain normalization and matching

Chuẩn hóa lowercase, bỏ trailing dot và canonicalize IDN/Punycode. Domain rules dùng exact hoặc suffix theo ranh giới DNS label; exact ưu tiên, suffix cụ thể nhất ưu tiên; conflicting rules cùng mức ưu tiên là ambiguous. Không substring match.

## 3. Open decisions — không tự giả định

| ID | Cần quyết định | Vì sao cần |
|---|---|---|
| O-01 | Runtime minimum observation timing (số packet/thời gian trước lần Flow evaluation đầu tiên) | Xác định khi Flow được đánh giá; DNS không đặt ngưỡng N riêng |
| O-02 | SNI domain mapping rules | Quyết định SNI_IDENTIFIED |
| O-03 | Burst idle-gap threshold | Xác định Burst boundary |
| O-04 | Có tách Burst khi direction đổi không | Ảnh hưởng segmentation |
| O-05 | CatBoost feature list/order | Khóa model input |
| O-06 | 1D-CNN tensor shape/sequence length | Khóa model input |
| O-07 | Padding/truncation/normalization | Đảm bảo inference hợp lệ |
| O-08 | Late Fusion hay Stacking cụ thể | Xác định training/inference |
| O-09 | Confidence threshold và calibration | Xác định UNKNOWN |
| O-10 | Thời điểm phát prediction | Xác định minimum observation |
| O-11 | Final output schema | Đồng bộ module và dashboard |
| O-12 | Runtime source paths/entrypoint | Tránh tạo file trùng chức năng |

## 4. Quy tắc cho Coding Agent

1. Đọc `README.md`, sau đó `01-system-architecture.md`.
2. Giữ nguyên thứ tự DNS → SNI → ML.
3. Tìm implementation hiện có trước khi tạo file mới.
4. Không đổi Flow/Device LightGBM baseline thành CatBoost/1D-CNN nếu chưa có code tương ứng.
5. Không tự điền Open Decisions bằng giá trị phỏng đoán.
6. Khi cần giả định để triển khai, ghi rõ trong PR/code comment và cập nhật tài liệu.
7. Thêm test chứng minh nhánh DNS/SNI early exit và ML fallback.


## 5. Framework decision

### D10 — PyTorch cho 1D-CNN

Framework 1D-CNN được chọn là **PyTorch**. Điều này không đồng nghĩa source/model artifact đã tồn tại. Tensor shape, sequence length, channels, preprocessing và hyperparameters vẫn là OPEN, quản lý trong `14-implementation-parameters.md`.

## 6. Tài liệu contract

- `13-module-contracts.md`: interfaces/data contracts.
- `14-implementation-parameters.md`: FIXED / CONFIGURABLE / OPEN.

### D15 — QUIC Initial phải được xác thực trước khi trích SNI

QUIC v1 Initial sử dụng RFC 9001 key schedule, header protection removal và
AES-128-GCM authentication. Chỉ plaintext có AEAD tag hợp lệ mới được parse
frame/CRYPTO và đưa vào TLS ClientHello parser. QUIC CRYPTO chứa handshake bytes,
không phải TLS records; không đưa raw UDP payload vào TCP reassembly. P0.7.3
chỉ hỗ trợ QUIC v1 Initial; QUIC v2 và 0-RTT/1-RTT nằm ngoài phạm vi.

### D16 — Original DCID là connection context

Initial secrets của QUIC được dẫn xuất từ Original DCID của client Initial.
Server Initial dùng DCID khác (thường là client SCID), vì vậy server Initial
đầu tiên trong capture cần Original DCID đã biết từ connection context. Không
được suy đoán Original DCID từ server packet.

## Accepted architecture decisions (2026-11-24)

### ML Candidate Selection precedes ML preparation

After DNS unresolved and SNI unresolved, the orchestrator marks a Flow as an ML candidate. Candidate selection/admission is a gate, not a classifier. The required order is ML Candidate Selection → ML-specific Bidirectional Flow Reconstruction → Burst Segmentation/Features → CatBoost + 1D-CNN → Late Fusion → Application/UNKNOWN. DNS- or SNI-identified Flow must early-exit.

### Reuse FlowTracker identity for ML reconstruction

The existing FlowTracker already groups both directions under one Flow ID and assigns client-relative direction. ML Reconstruction consumes that FlowState to validate/normalize an ML observation. It must not create a second Flow ID, regroup the tuple, or perform TCP payload reassembly/decryption.
