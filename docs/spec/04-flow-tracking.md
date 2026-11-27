# 04 — Packet Parsing, Flow Tracking và Bidirectional Flow

## 1. Mục đích

Flow Tracker gom packet thành Flow logic, giữ packet sequence và direction để DNS/SNI enrichment cũng như Burst ML sử dụng.

## 2. Phạm vi

**Làm:** canonical Flow key, Flow ID, client/remote endpoint, direction, timestamp, packet sequence và lifecycle.

**Không làm:** không quyết định application; không tự phân đoạn Burst; không chạy model.

## 3. Phụ thuộc

- Nhận ParsedPacket từ Packet Parsing.
- Cung cấp Flow và packet sequence cho DNS/SNI identification và ML branch.
- Bidirectional Flow Reconstruction ở bước 7 dùng packet sequence hai chiều đã gắn Flow ID.

## 4. Luồng xử lý

1. Nhận ParsedPacket.
2. Tự phát hiện subnet từ các IP/prefix trên network interface đang UP; allowlist/denylist interface là tùy chọn. Chỉ xác định client khi đúng một endpoint thuộc các subnet đã phát hiện.
3. Tạo canonical key không phụ thuộc chiều packet.
4. Tìm hoặc tạo FlowState.
5. Gán direction `forward` hoặc `backward`.
6. Cập nhật packet count, bytes, timestamp và packet sequence.
7. Gắn DNS/TLS metadata khi parser cung cấp.
8. Đóng Flow bằng thao tác lifecycle tường minh; idle timeout TCP/UDP vẫn OPEN nên không tự đóng theo thời gian.
9. Giữ Flow record đủ lâu để downstream consumer hoàn tất.

## 5. Input / Output

**5-tuple**

`(src_ip, src_port, dst_ip, dst_port, protocol)`

**Flow output logic**
- `flow_id`
- `canonical_5tuple`
- `client_endpoint`
- `remote_endpoint`
- `first_seen`, `last_seen`
- `packets_forward`, `packets_backward`
- `bytes_forward`, `bytes_backward`
- ordered packet metadata: timestamp, direction, packet length

Ví dụ hai chiều:
- `10.0.0.5:51000 → 142.1.1.1:443 TCP`: forward.
- `142.1.1.1:443 → 10.0.0.5:51000 TCP`: backward.

## 6. Quy tắc nghiệp vụ

- BR-01: Hai chiều của cùng kết nối thuộc một Flow.
- BR-02: Direction được xác định tương đối với client/LAN endpoint, không dựa đơn thuần vào packet đầu tiên.
- BR-03: Flow ID ổn định trong một capture session.
- BR-04: Packet order được giữ theo timestamp capture; packet out-of-order phải được xử lý có quy tắc.
- BR-05: TCP/UDP idle timeout là OPEN; P0.3 không tự áp dụng timeout hoặc giá trị `120s`.
- BR-06: Tuple reuse sau khi Flow đóng không được trộn vào Flow cũ.
- BR-07: Feature window 5 giây (nếu còn dùng) không đồng nghĩa Flow idle timeout.
- BR-08: ML chỉ nhận Flow sau khi DNS và SNI đều unresolved.
- BR-09: LAN subnet được phát hiện từ network interface đang UP; loopback/link-local/unspecified/multicast bị loại. Không tự loại virtual interface vì không thể suy đoán vai trò; dùng allowlist/denylist nếu cần.
- BR-10: Nếu cả hai endpoint hoặc không endpoint nào thuộc LAN subnet, direction là `UNKNOWN`.
- BR-11: Khi Flow đóng tường minh, packet tiếp theo có cùng tuple tạo Flow ID mới. Session đã đóng không nhận packet mới.

## 7. Lỗi và trường hợp biên

| Tình huống | Hành vi |
|---|---|
| Server packet đến trước | Xác định endpoint bằng LAN/subnet config |
| Capture bắt đầu giữa Flow | Tạo Flow partial; không giả định thấy SYN |
| Out-of-order packet | Giữ timestamp; reconstruction xử lý theo policy |
| Duplicate packet | Không tự loại nếu chưa có duplicate policy |
| Idle timeout chưa chốt | Không tự finalize; caller phải đóng Flow/session tường minh |
| Tuple reuse | Tạo Flow ID mới |
| Nhiều client tới cùng server | Tạo Flow riêng theo endpoint tuple |

## 8. File/hàm chính

- Runtime Flow Tracker path: cần tìm trong source repository; không có đường dẫn implementation được xác nhận trong snapshot.
- `ml/features.py`: README cũ mô tả Flow feature extraction tại đây; kiểm tra source trước khi thay contract.
- Không tạo module mới nếu Flow Tracker hiện hữu đã đáp ứng contract.

## 9. Tiêu chí nghiệm thu

- [x] Hai chiều cùng connection có cùng Flow ID (unit test).
- [x] Direction forward/backward đúng với client endpoint từ LAN subnet tự phát hiện (unit test).
- [x] Server-first capture không đảo direction (unit test).
- [x] Tuple reuse sau close tường minh tạo Flow ID mới (unit test).
- [x] Flow đã đóng vẫn được giữ trong tracker để downstream consumer đọc; integration với Burst pipeline chưa nằm trong P0.3.
- [ ] Replay PCAP cho cùng cấu hình tạo Flow grouping ổn định (chưa có replay fixture trong P0.3).

## 10. Ví dụ

Một TCP connection có packet client→server và server→client. Flow Tracker gom cả hai vào cùng Flow ID, đánh dấu từng packet direction và chuyển packet sequence sang bước Bidirectional Flow Reconstruction.


## 11. P0.3 implementation contract

- `FlowTracker` tự gọi `discover_interface_subnets()` khi không truyền `lan_subnets`; phát hiện subnet từ interface đang UP qua `psutil`.
- Có thể giới hạn interface bằng `interface_allowlist` hoặc loại bằng `interface_denylist`. Virtual interface được giữ nếu đang UP; môi trường triển khai quyết định qua allow/deny list.
- Chỉ có đúng một endpoint IP thuộc LAN subnet mới xác lập client endpoint. Hai endpoint cùng LAN hoặc đều ngoài LAN trả `UNKNOWN`.
- Flow ID tăng tuần tự trong từng session (`<session_id>:flow-000001`); cùng FlowKey đang active gom hai chiều vào một Flow.
- Packet metadata được giữ đầy đủ và `ordered_packets` sắp theo `(timestamp, packet_index)`. Duplicate không bị tự loại.
- `close_flow()` và `close_session()` là lifecycle API. Không có idle timeout mặc định; TCP FIN/RST cũng không tự đóng Flow trong increment này. Sau close, tuple reuse tạo Flow ID mới.

## Boundary with future ML Bidirectional Flow Reconstruction

The current FlowTracker is responsible for canonical bidirectional identity: both directions belong to one Flow ID, direction is client-relative, and packet metadata is retained. The future ML Reconstruction stage consumes this existing FlowState and creates an ML-specific observation with deterministic ordering, direction-coverage metadata, and data-quality flags.

It must not create a second Flow ID, regroup the 5-tuple, change direction semantics, reassemble TCP payload, or decrypt application data. This separates already-implemented Flow tracking from the future ML preparation adapter.

## Current source implementation — 2026-11-27

### Module name: Flow tracking and lifecycle

**Source files**
- `src/appid/flow/identity.py`
- `src/appid/flow/tracker.py`
- `src/appid/domain/models.py`
- Integration: `src/appid/pipeline/processor.py`

**Implemented**
Canonical bidirectional Flow keys normalize endpoint ordering. Tracker creates session-scoped Flow IDs, assigns client-relative FORWARD/BACKWARD/UNKNOWN direction, retains packet metadata, and exposes active/all Flows. UDP pseudo-Flows expire after configurable idle timeout (PacketProcessor default 60 seconds) and are capacity-bounded (default 10,000); capacity pressure evicts the oldest active UDP Flow. Session close closes remaining active Flows.

**Integrated**
Every accepted TCP/UDP PacketRecord enters FlowTracker. Finalized Flows are passed once through `_finalize_flows()` using `_finalized_flow_ids`.

**Tested**
`tests/unit/flow/test_identity.py`, `tests/unit/flow/test_tracker.py`, PacketProcessor and capture tests. Previously supplied full-suite evidence is recorded in the project completion assessment; not rerun against this ZIP.

**Status**
`DONE`.

**Remaining**
TCP Flow idle timeout is not implemented in `FlowTracker`; TCP Flows remain active until session close. This is relevant to long-running live capture and resource growth. UDP QUIC connection state has its own bounded timeout/capacity policy.
