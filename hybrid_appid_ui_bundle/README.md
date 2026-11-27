# Hybrid Network Application Identification

Laptop-focused implementation of the Hybrid Network Application Identification pipeline.

## Architecture

`Single NIC Capture / PCAP Replay → Packet Parser → LAN Subnet Filter → Shared Flow Tracker → DNS Identification (early exit) → TCP/SNI or UDP/QUIC SNI (only if DNS unresolved) → ML Candidate Gate (only if both unresolved)`

DNS, TCP/TLS SNI and UDP/QUIC v1 Initial/SNI are integrated into the same `PacketProcessor` used by live NIC capture and PCAP replay. Runtime identification follows strict DNS-first early exit: a DNS match ends identification; SNI is inspected only when DNS is unresolved; only Flows unresolved by both can reach ML Candidate Gate. Flow observation, candidate admission, bidirectional reconstruction and Burst segmentation are implemented. ML V2 training/evaluation is complete and frozen; runtime model inference is deliberately deferred. On 2026-11-26, TCP/SNI passed 5/5 target apps, QUIC SNI mapped all five target apps from live-captured PCAP, and a mixed TCP+QUIC PCAP replay processed 5,899/5,899 packets with zero parse errors.

## Source tree

```text
src/appid/
├── domain/       # Shared domain models and enums
├── network/      # NIC discovery and one-interface selection
├── capture/      # Live NIC capture and offline PCAP input
├── packet/       # Raw packet parsing into PacketRecord
├── pipeline/     # Shared DNS + TCP/SNI + UDP/QUIC processing path
├── flow/         # Flow identity, direction, state and lifecycle
├── ml/           # Candidate gate, Flow observations, Burst pipeline and export (no model inference)
├── dns/          # DNS parser, cache, domain rules and identifier
├── sni/          # TLS ClientHello parser, TCP reassembly and SNI identifier
├── appid/        # Unified DNS/TCP/QUIC evidence fusion
└── udp/          # UDP protocol analyzer, Flow lifecycle and QUIC v1 Initial/CID tracking
```

No generic `common/` package is used. Each module lives with the feature it implements.

## Setup môi trường Linux (Ubuntu/Debian)

Sau khi giải nén ZIP, mở Terminal tại thư mục dự án và chạy một lệnh:

```bash
chmod +x start.sh
./start.sh
```

`start.sh` gọi `setup_linux.sh` để cài Python 3, `venv`, công cụ build và thư viện
capture hệ thống; tạo/cập nhật `.venv`; cài project cùng Scapy, PyYAML, psutil,
`cryptography`, aioquic, pytest và Ruff. Sau đó script kiểm tra dependencies,
compile source/tests, chạy lint cho các module ML đã thay đổi và chạy toàn bộ
unit/integration tests có thể thực hiện trong môi trường. Yêu cầu Python 3.10 trở lên; script dùng
`apt` nên hiện hỗ trợ Ubuntu/Debian.

Các chế độ:

```bash
./start.sh                 # setup + toàn bộ test an toàn
./start.sh --no-setup      # dùng .venv hiện có, chỉ kiểm tra và test
./start.sh --live          # setup + test + live-NIC acceptance (opt-in)
```

Live-NIC capture chỉ chạy khi truyền `--live`; script dùng sudo riêng cho bước đó.
Log mỗi lần chạy được lưu trong `logs/`. Các lệnh `setup_linux.sh` và
`run_tests.sh` vẫn được giữ để tương thích với quy trình cũ.

Hoặc kích hoạt môi trường để chạy lệnh Python/project:

```bash
source .venv/bin/activate
python -m pytest -q -rs
```

Môi trường dự án được cô lập trong `.venv`; không cần cài package Python vào hệ thống.

## Live capture on exactly one NIC

Edit `config/network.json`:

```json
{
  "network": {
    "mode": "auto",
    "interface": null
  }
}
```

- `auto`: choose the first active interface with a usable IPv4/IPv6 address in OS enumeration order.
- `manual`: set `interface` to an exact interface name. If it is unavailable, startup fails; no fallback occurs.
- `--interface` can select a NIC directly from the command line.
- Capture binds Scapy to the selected interface only. The selected interface's subnet is the only LAN subnet used by the Flow pipeline.
- Capture prints Flow state when first observed and when its AppID changes. `--verbose` enables packet-by-packet output. Final CatBoost results are attached during shutdown finalization and are not printed afterward by this live CLI.
- On Ctrl+C, the processor closes active Flows and optionally writes completed Burst records to JSONL/TSV.

Run from the repository root (Linux; capture commonly requires root or capture capabilities). Use the exact NIC name you want to monitor; `--interface` overrides `config/network.json` and prevents auto-selecting a different active NIC:

```bash
sudo .venv/bin/python -m appid.capture.live \
  --config config/network.json --interface wlp62s0 \
  --burst-jsonl artifacts/live-bursts.jsonl \
  --burst-tsv artifacts/live-bursts.tsv
```

## Offline PCAP replay

PCAP replay uses the exact same parser, subnet filter and Flow Tracker as live capture. Specify the LAN subnet represented by the PCAP:

```bash
python -m appid.capture.pcap sample.pcap --lan-subnet 192.168.1.0/24
```

Optionally provide a stable session ID for reproducible comparisons:

```bash
python -m appid.capture.pcap sample.pcap --lan-subnet 192.168.1.0/24 --session-id test-session
```

Only TCP/UDP packets with at least one endpoint in the selected LAN subnet are tracked. Packets outside it are counted and ignored. The original capture timestamp is retained. UDP pseudo-Flows expire after the configured idle timeout (default 60 seconds) and are bounded by active-flow capacity (default 10,000). TCP Flow lifecycle remains separate; all active Flows close when the capture/replay session ends.

## Current scope — source snapshot 2026-11-27

The runtime includes P0 packet/Flow foundations, DNS parser/cache/AppID, TCP TLS ClientHello/SNI, UDP protocol analysis and QUIC v1 Initial/SNI, Candidate Gate, Burst segmentation/statistics/export, and optional CatBoost Flow V2 inference. **ML runtime inference is integrated** in `PacketProcessor`; older statements elsewhere in this README/docs saying it is deferred are historical and superseded by this snapshot.

Runtime order: DNS → TCP SNI → UDP/QUIC SNI. On Flow finalization, unresolved Flows pass Candidate Gate → Burst segmentation → 70-feature Flow aggregation → CatBoost inference if `--ml-model` is configured. Rule-classified Flows do not enter ML.

### Laptop acceptance snapshot — 2026-11-26 (historical, separate from ML run)

- TCP/TLS SNI: all five target applications (ChatGPT, Facebook, TikTok, YouTube and Spotify) returned HTTP 200 and were identified by PacketProcessor from the captured PCAP.
- QUIC v1: HTTP/3 probes completed for three of five services; nevertheless, the captured QUIC Initial traffic exposed SNI for all five target applications and PacketProcessor identified ten target QUIC flows. This is SNI/AppID evidence, not proof that all five HTTP/3 requests completed.
- Mixed TCP + QUIC replay: 5,899 raw/parsed/tracked packets, zero unsupported packets, zero parse errors and zero packets outside the configured LAN subnet; five TCP/SNI flows and ten QUIC/SNI flows identified.
- Burst export from the mixed replay: 484 JSONL records and 484 TSV records (485 TSV lines including the header).
- 2026-11-26 live DNS + TCP/SNI acceptance: 180 seconds on `wlp62s0`; 4,352 raw / 4,018 parsed / 3,853 tracked packets; 172 observed Flows; 57 DNS bindings; 10 DNS-identified Flows; 19 SNI ClientHellos; 5 SNI-identified Flows; all five target apps observed via DNS and/or TCP SNI; DNS, packet and SNI parse errors were zero. This run did not establish live QUIC identification.
- `./start.sh --no-setup`: 194 passed, 1 skipped; Ruff and Python compile passed. The skip is the opt-in root live-NIC test.
- Earlier live Burst export: 2,078 JSONL records and 2,078 TSV records. Mixed TCP + QUIC PCAP replay emitted 484 Burst records.
- CPU/RAM profiling and a quantified resource soak remain open. These DNS/SNI/QUIC acceptance figures are separate from the ML live inference run below.


### CatBoost Flow V2 runtime smoke — supplied result

Model path: `outputs/p1_5_full_dataset_wirelen_v2/catboost_flow_v2/catboost_flow_v2.cbm`.

```bash
sudo -E .venv/bin/python -m appid.capture.live --interface wlp62s0 \
  --ml-model outputs/p1_5_full_dataset_wirelen_v2/catboost_flow_v2/catboost_flow_v2.cbm
```

Model record supplied by project owner: 70 features, 6 classes (`chatgpt`, `facebook`, `other-web`, `spotify`, `tiktok`, `youtube`), 1,362 trees, approximately 19 MB. CatBoost is optional (`pip install -e ".[ml,dev]"`).

One supplied run: 171 raw packets, 167 parsed, 164 tracked; 24 ML candidates evaluated, 23 admitted, 0 rejected, 1 pending; 23 predictions, 0 inference errors; 24 Flows finalized and 108 Bursts. This confirms model loading and inference execution only, not correctness or accuracy.

**Output caveat:** live CLI prints Flow state during packet arrival. CatBoost inference runs during finalization in `processor.close()`, after packet output; the live CLI does not subsequently print/export final Flow predictions. Optional JSONL/TSV exports are Burst records, not Flow prediction records. PCAP replay returns/prints finalized Flow summaries but has no structured Flow CSV/JSON export. No inference latency or CPU/RAM profiling is implemented/evidenced.

The model binary and `outputs/` directory are not included in this source ZIP; supply the `.cbm` artifact separately.

## Verify real traffic capture on one Linux NIC

For an opt-in real-NIC smoke test that sends a uniquely marked UDP broadcast,
observes it on the selected interface, and asserts that it creates a Flow in
`FlowTracker`, follow [`docs/testing/live-nic-capture.md`](docs/testing/live-nic-capture.md).

```bash
sudo .venv/bin/python scripts/verify_live_nic.py --config config/network.json
```

This requires Linux root/capture privileges and a selected NIC with IPv4. It
verifies the local outgoing capture path; it is not a packet-loss or inbound
traffic benchmark.


## P0.5 DNS Application Identification

DNS parsing/cache/identification is integrated into the shared live/PCAP `PacketProcessor`. Configure approved application domains in `config/dns_mapping.yaml` (the package includes conservative rules for ChatGPT, Facebook, TikTok, YouTube and Spotify). DNS responses are correlated to observed queries, stored per session/client/destination with TTL and CNAME-chain expiry, then matched to domain rules. Identified results are bound to `FlowState.identification_result`; subsequent packets reuse that result. DNS payload is parsed transiently and is not retained in Flow records.

Run tests with project dependencies installed: `python -m pip install -e '.[dev]' && pytest`. Scapy-dependent parser tests require Scapy.

## Kiểm thử DNS trên laptop

Kiểm thử live DNS + TCP/SNI trên laptop theo hướng dẫn [`docs/testing/dns-live-laptop-test.md`](docs/testing/dns-live-laptop-test.md).

```bash
sudo .venv/bin/python scripts/test_dns_live.py --interface wlp62s0 --duration 180
```

## Chạy kiểm thử DNS trên laptop bằng một lệnh (Linux)

Sau khi giải nén ZIP, mở Terminal tại thư mục `hybrid-appid-starter` và chạy:

```bash
./run_dns_test.sh
```

Lần đầu script tự tạo `.venv`, cài Scapy và dependencies, sau đó yêu cầu quyền
`sudo` để bắt gói tin. Các lần sau dùng lại môi trường đã cài.

Muốn chỉ định card mạng cụ thể:

```bash
./run_dns_test.sh --interface wlp62s0 --duration 180
```

Trong lúc capture, mở terminal khác và tạo traffic:

```bash
nslookup chatgpt.com && curl -I https://chatgpt.com
nslookup facebook.com && curl -I https://www.facebook.com
nslookup tiktok.com && curl -I https://www.tiktok.com
nslookup youtube.com && curl -I https://www.youtube.com
nslookup spotify.com && curl -I https://open.spotify.com
```

Không dùng `--dns-only` để xác nhận TCP/SNI identification vì tùy chọn này chỉ
capture DNS port 53. Bài test mặc định capture toàn bộ TCP/UDP trên NIC đã chọn.

### P0.5.4 DNS acceptance test

Run `./run_dns_test.sh --interface <NIC> --duration 180`. The launcher runs deterministic DNS policy scenarios and unit tests first, then starts live capture. During capture, run `./generate_dns_test_traffic.sh` in a second terminal to exercise all five target services. Full live PASS requires all five Application IDs to be observed; otherwise the result is PARTIAL.

## DNS laptop acceptance test (P0.5.6)

Run the capture first:

```bash
./run_dns_test.sh --interface wlp62s0 --duration 180
```

While capture is active, run in a second terminal:

```bash
./generate_dns_test_traffic.sh
```

The traffic generator discovers the default-route DNS server and sends `nslookup`
queries directly to it. This intentionally bypasses the local `systemd-resolved`
stub (`127.0.0.53`), whose loopback traffic is not visible on the physical Wi-Fi
interface. You can override the resolver with `DNS_SERVER=192.168.1.1`.

The runner executes deterministic DNS acceptance scenarios and the unit suite
before starting live capture. A failing unit test stops the run; do not treat a
scenario-only PASS as a complete live test.

P0.5.6 fixes fallback Client IP inference for DNS responses from a home-router
resolver: the router may be inside the same LAN subnet as the client. If there is
no correlated query, the parser accepts the response destination as the client
only when the response source port is 53 and that destination belongs to a
configured LAN network. The DNS traffic generator also uses corrected `awk`
syntax for default-gateway discovery.

### P0.5.7 parser compatibility note

P0.5.7 handles Scapy 2.8 DNS `PacketListField` question/answer sections as well
as single-packet sections, and adds a serialized-packet CNAME+A regression test.
The live summary also reports unexpected DNS exception classes for diagnosis.


## P0.5.9 — DNS parser fix and diagnostics

P0.5.9 fixes DNS Answer flattening when Scapy PacketListField entries contain
additional DNSRR records in their payload chain (for example CNAME followed by A/AAAA).
It also adds metadata-only diagnostics for query/response correlation, individual
Answer records, DNS cache decisions, and Flow identification.

Enable detailed live logs with:

```bash
./run_dns_test.sh --interface wlp62s0 --duration 180 --dns-debug 2>&1 | tee dns-debug.log
```

Without `--dns-debug`, the live test retains concise output and prints parser
diagnostic counters in its final summary. See
[`docs/testing/dns-diagnostics.md`](docs/testing/dns-diagnostics.md).

## P0.6.1 TLS ClientHello / SNI parsing

P0.6.1 adds an independent `appid.sni` module for parsing a complete TLS
Handshake record containing a ClientHello and extracting the visible SNI
`host_name`. It performs bounded length checks, hostname normalization
(lowercase, trailing-dot removal and IDNA conversion), and reports explicit
statuses: `PARSED`, `NO_SNI`, `INVALID_TLS`, `INCOMPLETE`, `UNSUPPORTED`, and
`ECH_DETECTED`.

Example:

```python
from appid.sni import TLSClientHelloParser

result = TLSClientHelloParser().parse(tls_tcp_payload)
print(result.status, result.server_name, result.reason_code)
```

This `appid.sni` entrypoint expects a TCP payload containing a complete TLS
record; QUIC/HTTP3 is not handled by this TCP parser, and TLS is not decrypted.
TCP segmentation/reassembly, Flow integration and SNI application rules are
implemented by P0.6.2–P0.6.5 as documented below. QUIC v1 Initial has a separate
P0.7.3 inspector under `appid.udp.quic`; P0.7.4 wires this inspector into the
shared `PacketProcessor` for both live capture and PCAP replay. It removes
QUIC Initial packet protection and extracts visible ClientHello/SNI from CRYPTO
frames. TLS 1.3 ClientHello can still expose SNI unless ECH is
used; the parser marks ECH and does not recover the encrypted inner name. DNS
code and DNS cache behavior are unchanged.


## P0.6.3–P0.6.5 TCP SNI AppID integration

The shared `PacketProcessor` now runs the TCP identification path after Flow
tracking and DNS evidence processing:

1. Use the Flow's LAN-derived client endpoint to select only client-to-server
   TCP payloads; do not guess direction from port numbers.
2. Feed TCP sequence numbers and SYN/FIN/RST flags into the bounded,
   per-Flow/per-direction `TCPReassembler`.
3. Accumulate at most 64 KiB of contiguous client-stream data per Flow and pass
   it to `TLSClientHelloParser` until the ClientHello is complete.
4. Match the normalized SNI hostname against the same conservative,
   reviewed rules in `config/dns_mapping.yaml`.
5. Bind a classified result to `FlowState.identification_result`. DNS is
   authoritative and ends the identification path. TCP/TLS SNI is attempted
   only when DNS is unresolved; a verified SNI match then ends identification.
   If a valid DNS mapping arrives after an earlier SNI result, DNS replaces it.

The only named application labels are `chatgpt`, `facebook`, `spotify`,
`tiktok`, and `youtube`. Unmapped hostnames remain unclassified; `other-web` is
not a catch-all rule and is reserved for a later classifier/dataset path.

This integration applies to both live capture and PCAP replay because both use
the same `PacketProcessor`. It identifies visible TLS ClientHello SNI only; it
does not decrypt TLS, recover ECH inner names, parse QUIC/HTTP3, or guarantee
identification for mid-stream captures that missed the ClientHello. Real-NIC
acceptance still needs to be run on the target Linux laptop with Scapy and
capture privileges.

Run unit tests:

```bash
./run_tests.sh
```

For PCAP validation, replay a capture containing a complete TCP handshake and
ClientHello using the same `appid.capture.pcap` command documented above.


## P0.7.3 QUIC v1 Initial inspection

`appid.udp.quic.QUICInitialConnection` parses QUIC v1 Initial datagrams, derives
RFC 9001 Initial keys using `cryptography`, removes AES header protection,
validates/decrypts AES-128-GCM payloads, parses Initial frames and reassembles
CRYPTO data by offset. The existing TLS ClientHello parser then extracts the
visible SNI. Authentication must succeed before SNI is returned. QUIC v2,
0-RTT/1-RTT, ECH inner names and live/PCAP integration are not included.

```python
from appid.udp.quic import QUICInitialConnection

inspector = QUICInitialConnection()
result = inspector.process_datagram(udp_payload)
print(result.status, result.sender_role, result.sni, result.ech_detected)
```

A server Initial first observed requires `original_dcid` from the client
Initial. Full design and scope: [`docs/architecture/quic-v1-initial-parsing.md`](docs/architecture/quic-v1-initial-parsing.md).

## Kiểm thử QUIC / HTTP/3 cho 5 ứng dụng (P0.7.3)

P0.7.3 có bộ phát sinh traffic HTTP/3-only và công cụ đọc PCAP để kiểm tra
QUIC Initial → TLS ClientHello → SNI → AppID rule. Xem hướng dẫn đầy đủ tại
[`docs/testing/quic-http3-live-test.md`](docs/testing/quic-http3-live-test.md).

```bash
# Terminal 1: bắt UDP/443 trên đúng card mạng
sudo tcpdump -ni wlp62s0 -s 0 -w quic-five-apps.pcap 'udp port 443'

# Terminal 2: phát HTTP/3 thật, không fallback TCP
./generate_quic_test_traffic.sh

# Sau khi dừng tcpdump: giải mã QUIC Initial và đối chiếu SNI/rule
.venv/bin/python scripts/inspect_quic_initial_pcap.py quic-five-apps.pcap
```

Traffic generator yêu cầu curl có `--http3-only`; chỉ kết quả `HTTP version 3`
mới được tính là HTTP/3 thành công. P0.7.3 chưa tích hợp QUIC vào live
`PacketProcessor`, nên dùng PCAP inspector để xác nhận AppID ở phase này.


HTTP/3 test traffic uses the Python `aioquic` dependency (installed by `./setup_linux.sh`); a curl build with HTTP/3 support is not required. See `docs/testing/quic-http3-live-test.md`.

## P0.7.4 Hybrid TCP + UDP / QUIC AppID

The shared processor now identifies UDP protocol signatures and inspects
QUIC v1 Initial packets for visible TLS ClientHello/SNI. QUIC SNI uses the same
approved domain mapping as TCP SNI. UDP Flow IDs and QUIC Connection IDs are
separate; authenticated Initial CIDs can link multiple observed UDP Flows.

Important interpretation:

- `transport_protocol=UDP` describes the transport layer.
- `application_protocol=QUIC_INITIAL` means a QUIC v1 Initial was successfully
  decrypted. It does **not** prove a completed HTTP/3 request.
- ECH is detected but the encrypted inner hostname is not recovered.
- Unmapped hostnames remain unresolved, not `other-web`.
- QUIC v2, 0-RTT/1-RTT, HTTP/3 payload decoding and full CID migration tracking
  are not implemented.

`PacketProcessor` accepts independent `enable_udp_analysis` and
`enable_quic_analysis` switches. UDP Flow defaults are a 60-second idle timeout
and 10,000 active flows; QUIC defaults are 4,096 active connections, a
120-second idle timeout and 1 MiB CRYPTO data per connection. See
[`docs/architecture/p0.7.4-hybrid-tcp-udp-pipeline.md`](docs/architecture/p0.7.4-hybrid-tcp-udp-pipeline.md)
for contracts and limitations.

Build-container validation for this package: **122 passed, 2 skipped**.
Scapy-dependent DNS parsing and real-NIC integration are skipped in this
container; run `./setup_linux.sh` then `./run_tests.sh` on the Linux laptop.
P0.7.4 live NIC and integrated PCAP acceptance remain pending.

## P0.7.5 — TCP SNI acceptance (forced HTTP/1.1)

To test TCP independently from QUIC, run the one-command capture/probe/replay
workflow on the Linux laptop:

```bash
sudo ./run_tcp_appid_test.sh wlp62s0
```

This uses `dumpcap` to capture TCP/443 (180-second hard limit by default), issues five direct HTTPS probes with `curl --http1.1`,
optionally prints TLS SNI with `tshark`, and replays the same PCAP through the
shared PacketProcessor. It writes `p075-tcp-five-apps.pcap` and
`p075-tcp-five-apps-traffic-report.tsv` by default. See
[`docs/testing/p0.7.5-tcp-sni-live-acceptance.md`](docs/testing/p0.7.5-tcp-sni-live-acceptance.md)
for acceptance criteria. Successful curl requests alone do not count as AppID
PASS; expected SNI and per-flow PacketProcessor classifications must be present.


## P1.2 Burst integration

Completed Flows are passed through the ML candidate gate and Burst pipeline.
The baseline policy is configurable through `PacketProcessor` constructor
arguments and currently uses:

- Minimum Flow packets: `2`
- Minimum Flow duration: `0.0` seconds
- Burst idle-gap boundary: `0.5` seconds (a gap strictly greater than the threshold splits)
- TCP finalization: capture-session close
- UDP finalization: idle expiration or active-Flow capacity eviction

Rule-classified DNS/SNI Flows are not admitted to the ML Burst path. Each Flow
is finalized at most once. No partial Burst snapshots are emitted for active
Flows. Packet payload is not used by Burst reconstruction.

PCAP replay returns `ReplayResult.bursts`. Optional machine-readable exports:

```bash
appid-pcap-replay capture.pcap --lan-subnet 192.168.1.0/24 \
  --burst-jsonl bursts.jsonl --burst-tsv bursts.tsv
```

JSONL and TSV contain `session_id`, `flow_id`, `burst_index`, `direction`,
`start_ts`, `end_ts`, `duration_seconds`, `packet_count`, `total_bytes`, and
`inter_burst_gap_seconds`.


## P1.4 – Burst/Flow feature CSV export

Feature export dùng chung các hàm thống kê P1.3, không đọc payload và không tự
đặt padding, truncation hay scaling. Ví dụ sau khi đã có `bursts` từ
`BurstSegmenter`:

```python
from appid.ml import export_burst_features_csv, export_flow_features_csv

export_burst_features_csv(bursts, "artifacts/burst_features.csv")
export_flow_features_csv([bursts], "artifacts/flow_features.csv")
```

`burst_features.csv` có một dòng cho mỗi Burst; `flow_features.csv` có một dòng
cho mỗi Flow (mỗi phần tử đầu vào là tập Burst của đúng một Flow). Cột và thứ tự
cột lấy trực tiếp từ schema P1.3. Giá trị chưa xác định (ví dụ IAT của Burst một
packet) được ghi thành ô trống. Input rỗng tạo CSV chỉ có header. `session_id` và
`flow_id` được giữ để truy vết, không phải feature đầu vào cho mô hình; cần loại
chúng (cùng metadata/label) khỏi ma trận huấn luyện để tránh leakage.


## P1.5 dataset extraction (Spotify pilot first)

See [`P1_5_PILOT_GUIDE.md`](P1_5_PILOT_GUIDE.md). The extractor is `export_p1_5_features.py`; it writes Burst CSV + Flow-sequence JSONL and a manifest, and `tools/audit_p1_5_dataset.py` checks their structural consistency.


## Runtime identification policy — 2026-11-26

The accepted architecture is DNS → SNI → ML with early exit. A valid DNS match is authoritative and skips TCP/TLS SNI and UDP/QUIC SNI. If DNS is unresolved, the applicable SNI parser may identify the Flow and stop further identification. Only Flows unresolved by both stages can be considered by ML Candidate Gate. The previous evidence-fusion policy (combine DNS/SNI agreement and prefer SNI on conflict) is historical and superseded.
