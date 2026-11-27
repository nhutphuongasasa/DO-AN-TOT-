# 02 — Network Packet Capture và Packet Parsing

## 1. Mục đích

Nhận packet từ live interface hoặc PCAP, parse metadata cần thiết và chuyển packet vào Flow Tracking. Cả hai nguồn phải dùng chung packet-processing path.

## 2. Phạm vi

**Làm**
- Live capture và offline PCAP replay.
- Giữ timestamp gốc của packet.
- Parse Ethernet/IP/TCP/UDP header cần cho Flow.
- Nhận diện DNS và TLS/QUIC packet để chuyển parser tương ứng.

**Không làm**
- Không tự nhận diện application.
- Không tự tạo DNS/SNI mapping.
- Không tính CatBoost/1D-CNN prediction.

## 3. Phụ thuộc

- Scapy được khai báo trong `requirements.txt`.
- Packet Capture gọi Packet Parser.
- Packet Parser chuyển packet metadata sang Flow Tracker và protocol parsers.

## 4. Luồng xử lý

1. Chọn nguồn: live interface hoặc PCAP.
2. Nhận packet và giữ capture timestamp.
3. Kiểm tra packet có Ethernet/IP và TCP/UDP hay không.
4. Parse địa chỉ, port, protocol, packet length và transport metadata.
5. Chuyển packet metadata vào Flow Tracker để gán Flow ID và direction.
6. Chuyển raw packet/transport-payload view tạm thời (cùng packet_index/timestamp/Flow context) sang DNS Parser và protocol parsers tương ứng.
7. DNS Parser đọc payload để tạo observation; payload không được giữ trong FlowRecord, Dataset hoặc log. DNS/TLS parser phụ lỗi không làm mất packet metadata đã track.
8. Không để lỗi parser phụ làm dừng capture/Flow tracking.

## 5. Input / Output

| Object | Trường tối thiểu |
|---|---|
| Input packet | Raw packet + capture timestamp |
| ParsedPacket | `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `packet_length`, `transport_flags` |
| Output | PacketRecord metadata cho Flow Tracker; raw packet/protocol-payload view tạm thời cho protocol parsers |

Tên class và kiểu Python chính thức phải khớp implementation; bảng trên là contract logic.

## 6. Quy tắc nghiệp vụ

- BR-01: Live capture và PCAP replay dùng chung parser/processing path.
- BR-02: Không thay timestamp capture bằng thời điểm parser xử lý.
- BR-03: Packet không hỗ trợ không được đưa vào Flow như packet hợp lệ.
- BR-04: DNS/TLS parser failure không được làm mất packet khỏi Flow statistics nếu header transport vẫn hợp lệ.
- BR-05: Không lưu payload nhạy cảm vào log.
- BR-06: PacketRecord/FlowRecord chỉ giữ metadata; protocol payload được chuyển tạm thời qua side channel cho parser cần thiết.
- BR-07: DNS parser không được chỉ nhận PacketRecord metadata-only; phải nhận raw DNS message bytes hoặc raw packet view.
- BR-08: Protocol parsing failure không làm mất packet hợp lệ khỏi Flow tracking.

## 7. Lỗi và trường hợp biên

| Tình huống | Hành vi |
|---|---|
| Packet thiếu IP/TCP/UDP | Bỏ qua khỏi flow pipeline; ghi counter nếu cần |
| Packet malformed | Đánh dấu parse error; tiếp tục capture |
| PCAP rỗng | Báo input rỗng; không tạo prediction |
| Interface không tồn tại/không có quyền | Dừng capture và trả lỗi cấu hình rõ ràng |
| TLS ClientHello chia nhiều TCP segment | Chuyển đủ stream data cho TLS reassembly/parser |
| DNS parser lỗi | Flow tracking vẫn tiếp tục |

## 8. File/hàm chính — implementation snapshot 2026-11-26

- `src/appid/capture/live.py`: `SingleNICCapture`; chọn đúng một NIC, gọi Scapy `sniff()` và chuyển packet vào `PacketProcessor.process()`.
- `src/appid/capture/pcap.py`: `replay_pcap()`; đọc PCAP bằng `PcapReader` và chuyển packet vào cùng `PacketProcessor.process()`.
- `src/appid/packet/parser.py`: `parse_packet()`; tạo `PacketRecord` metadata-only và giữ timestamp/wire length khi nguồn cung cấp.
- `src/appid/pipeline/processor.py`: `PacketProcessor.process()`; LAN filter, DNS observation/cache, Flow tracking, DNS identification, TCP/SNI và UDP/QUIC inspection.
- `src/appid/flow/tracker.py`: `FlowTracker`; quản lý Flow ID, packet sequence và lifecycle.

Không tạo entrypoint hoặc class capture mới khi các thành phần trên đã tồn tại.

## 9. Tiêu chí nghiệm thu

- [ ] Cùng PCAP chạy hai lần cho cùng số packet parse được.
- [ ] Timestamp output khớp timestamp trong PCAP.
- [ ] Packet TCP/UDP được parse đúng 5-tuple.
- [ ] Packet lỗi parser không làm dừng xử lý các packet sau.
- [ ] Live và PCAP path gọi cùng packet-processing function.

## 10. Ví dụ

Một packet TCP từ `192.168.1.10:51000` đến `142.1.1.1:443` được parse thành metadata gồm source/destination IP, port, protocol TCP, timestamp và packet length; sau đó chuyển sang Flow Tracker.


## 11. QUIC v1 Initial parser boundary (historical P0.7.3)

At P0.7.3 the `QUICInitialConnection` component was standalone. That statement
is historical and was superseded by P0.7.4 integration described below.

## 12. P0.7.4 shared TCP + UDP processing (current implementation)

The current `PacketProcessor` dispatches both TCP and UDP after the same packet
normalization and selected-LAN filter. TCP keeps the existing bounded TCP
reassembly → TLS ClientHello/SNI path. UDP uses structural protocol
identification, and a QUIC v1 Initial candidate enters the QUIC decrypt/CRYPTO
reassembly/TLS ClientHello path. DNS observations are still parsed from the raw
packet before Flow storage. Both live capture and PCAP replay use this same
processor.

UDP pseudo-Flow idle expiry and capacity are independent from TCP lifecycle. A
QUIC Connection is not a UDP Flow: authenticated Initial DCID/SCID aliases can
link more than one UDP Flow to one QUIC Connection. The current CID tracker
does not process 1-RTT NEW_CONNECTION_ID frames. QUIC Initial/SNI evidence is
not a claim that HTTP/3 requests completed; ECH inner names are not recovered.
See `docs/architecture/p0.7.4-hybrid-tcp-udp-pipeline.md`.

## Current source implementation — 2026-11-27

### Source files
- `src/appid/capture/live.py`: `SingleNICCapture`, interface selection, Scapy sniff callback, shutdown/export/stats, `--ml-model`.
- `src/appid/capture/pcap.py`: `replay_pcap()`, `ReplayResult`, CLI and `--ml-model`.
- `src/appid/packet/parser.py`: Scapy packet to `PacketRecord`.
- `src/appid/pipeline/processor.py`: shared `PacketProcessor.process()` and Flow finalization.

### Implemented / integrated
Live and PCAP call the same `PacketProcessor.process()`. It parses metadata, rejects unsupported packets and packets outside the configured LAN, updates DNS observation/cache, handles UDP idle expiry/capacity, adds the packet to FlowTracker, then tries DNS → TCP SNI → UDP/QUIC. Flow finalization runs Candidate Gate, Burst segmentation and optional CatBoost inference.

### Tested
Unit coverage exists in `tests/unit/packet/`, `tests/unit/capture/`, and `tests/unit/pipeline/`; PCAP/Burst integration is in `tests/integration/test_pcap_burst_pipeline.py`. Previously supplied suite result: 195 passed, 1 skipped, 1 warning. Not rerun on this ZIP.

### Status
`DONE` for shared live/PCAP processing and CLI model-path plumbing.

### Remaining
A model-enabled PCAP acceptance result is `NOT VERIFIED`. Live CLI does not print final Flow results after `processor.close()`. CPU/RAM, packet-loss and long-duration profiling are not measured.
