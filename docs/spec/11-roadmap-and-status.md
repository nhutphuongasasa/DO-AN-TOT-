# Current status snapshot — 2026-11-27 (authoritative)

This snapshot reflects the current source archive and the project-owner supplied ML live result. Older phase entries below are historical records only.

| Area | Current status | Evidence / remaining work |
|---|---|---|
| Shared live/PCAP PacketProcessor | Implemented | Both entrypoints call `PacketProcessor.process()` |
| DNS parser/cache/rules | Implemented | DNS-first integration and DNS unit/integration tests |
| TCP reassembly + TLS SNI | Implemented within visible-SNI scope | SNI parser/reassembly/integration tests and historical acceptance |
| UDP protocol + QUIC v1 Initial/SNI | Partial | QUIC v1 Initial decrypt/CRYPTO/SNI; not general HTTP/3 decryption |
| Flow tracking + Burst pipeline | Implemented | Candidate Gate, reconstruction, segmentation and statistics integrated |
| CatBoost Flow V2 runtime | Integrated | Model optional; 70 features; owner-supplied live run: 23 predictions / 0 inference errors |
| Flow prediction export | Partial | In-memory Flow results; PCAP terminal summary; no structured Flow CSV/JSON; live final result not printed |
| Automated source validation | Prior result supplied | 195 passed, 1 skipped, 1 warning; not rerun against this ZIP |
| ML accuracy / ground-truth evaluation | Not verified for this runtime run | Prediction count is not accuracy evidence |
| Model-enabled PCAP acceptance | Not verified | Runtime path exists; no run evidence supplied |
| CPU/RAM, latency and resource soak | Not verified | No measurement evidence or runtime instrumentation found |

## Immediate project objective

Continue from the integrated CatBoost runtime; do not treat ML inference as deferred. Do not infer correctness from successful inference. Next work is final Flow result visibility/export, model-enabled PCAP acceptance, ground-truth evaluation, confidence/UNKNOWN policy, and resource profiling. QUIC PCAP evidence, DNS/TCP-SNI live acceptance and the ML live run are separate experiments.

1. Preserve the 195-pass test result as previously supplied evidence, not a fresh run against this ZIP.
2. Keep the model binary external to the lightweight source archive and document its exact path.
3. Add Flow prediction export and post-finalization live reporting.
4. Verify model-enabled PCAP replay and evaluate predictions against ground truth.
5. Measure inference latency, CPU/RAM and long-running Flow state growth.

---

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
| DNS Parser / DNS Cache / DNS Identifier (P0.5) | IMPLEMENTED; core unit tests pass; Scapy parser tests pending dependency-enabled run | Run Scapy DNS fixtures and live/PCAP DNS capture validation |
| SNI mapping | DESIGNED / OPEN | Xác minh parser và rules |
| Normalized bidirectional Flow identity (P0.2) | IMPLEMENTED / TESTED (17 unit tests passed at P0.2) | Được Stateful Flow Tracker P0.3 sử dụng |
| Stateful Flow Tracker / Flow lifecycle (P0.3) | IMPLEMENTED / UNIT TESTED | Đã tích hợp vào shared packet pipeline; idle timeout vẫn OPEN |
| Single-NIC live capture + PCAP replay (P0.4) | IMPLEMENTED; live-NIC smoke test PASS trên Linux host của người dùng | Tiếp tục kiểm thử inbound, multi-flow, bidirectional và các acceptance còn lại |
| Bidirectional Flow Reconstruction | DESIGNED | Chốt input/output contract |
| Burst Segmentation | DESIGNED | Chốt boundary rule |
| CatBoost branch | DESIGNED / OPEN | Xác nhận implementation và artifact |
| 1D-CNN branch | DESIGNED / OPEN | Xác nhận framework, tensor schema |
| Late Fusion / Stacking | DESIGNED / OPEN | Chốt algorithm và training protocol |
| Final UNKNOWN policy | DESIGNED / OPEN | Chốt thresholds và reason codes |

## 3. Thứ tự triển khai

### P0 — Chốt contract
- [ ] Xác minh packet/Flow record hiện có.
- [x] Chốt canonical bidirectional Flow identity và Direction enum contract (P0.2).
- [x] Implement Stateful Flow ID allocation/lifecycle và LAN endpoint policy từ active-interface subnet discovery (P0.3); idle timeout vẫn OPEN.
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
- [x] PCAP replay qua packet parser và Flow Tracker (P0.4); DNS/SNI/ML path vẫn ở các phase sau.
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


## 6. Tài liệu hóa contract và parameters

- [x] README runtime order và source tree mục tiêu.
- [x] Module contracts logic (chưa phải source implementation).
- [x] Parameter registry FIXED / CONFIGURABLE / OPEN.
- [x] Framework 1D-CNN chọn PyTorch.
- [ ] Xác nhận các giá trị OPEN bằng thiết kế/thực nghiệm.
- [ ] Implement source theo contract và cập nhật trạng thái module.


## 7. P0.2 implementation log

- Module: Normalized Bidirectional Flow Identity.
- Code: `src/appid/flow/identity.py`.
- Tests: `tests/unit/flow/test_identity.py` plus existing unit suite.
- Scope: pure identity and explicit-role direction helper only; no stateful tracking.
- OPEN after P0.2: TCP/UDP idle timeout. P0.3 resolves client endpoint from host-interface LAN subnet discovery; ambiguous cases remain UNKNOWN.


## 8. P0.3 implementation log

- Module: Stateful Flow Tracker and host-interface LAN subnet discovery.
- Code: `src/appid/flow/tracker.py`, `src/appid/network/interfaces.py`.
- LAN role policy: discover IPv4/IPv6 subnets from currently-up interfaces using `psutil`; optional interface allowlist/denylist; only exactly one LAN endpoint establishes client role.
- Lifecycle: explicit `close_flow()` / `close_session()`; no TCP/UDP idle timeout and no FIN/RST auto-close.
- Flow IDs: sequential and session-scoped; closed tuple reuse creates a new ID.
- Packet sequence: retain packet index, timestamp, direction and packet length; deterministic chronological view by timestamp then packet index. Duplicate packets are retained.
- Validation: see P0.3 implementation notes and test run.


## 9. P0.4 implementation log

- Module: single-NIC live capture, packet parsing, shared processing pipeline and offline PCAP replay.
- Code: `src/appid/capture/`, `src/appid/packet/`, `src/appid/pipeline/`, `src/appid/network/`, `src/appid/flow/`, `src/appid/domain/`.
- Live capture binds to one selected interface only.
- Live and PCAP sources use the same `PacketProcessor` and preserve source timestamps.
- PCAP replay requires an explicit LAN subnet because an offline file is not intrinsically bound to a host NIC.
- Validation: unit tests cover processor filtering and replay fixture when Scapy is installed; live hardware capture remains environment-dependent.


## 10. P0.4.1 — Real NIC verification

- [x] Thêm script smoke test phát UDP broadcast có marker qua đúng NIC được chọn.
- [x] Capture được bind tường minh vào interface đã chọn; sender bind source IP và `SO_BINDTODEVICE`.
- [x] Xác minh packet marker đi qua `PacketProcessor` và tạo Flow trong `FlowTracker`.
- [x] Thêm pytest integration test opt-in, mặc định skip để không tự capture trên máy developer/CI.
- [x] Người dùng chạy smoke test trên Linux host: interface `wlp62s0`, subnet `192.168.1.0/24`, 3 marker frames captured/parsed/tracked, 1 Flow được tạo.
- [ ] Chưa chứng minh inbound từ LAN peer, traffic trên NIC khác bị loại trong bài test đối chứng, nhiều Flow TCP/UDP đồng thời, bidirectional reuse hoặc tuple reuse qua live traffic.


## 11. P0.5 — DNS design lock (2026-11-23; historical baseline)

- Historical status at design-package creation: **DESIGNED / CONTRACT LOCKED**. This baseline is superseded by the source implementation recorded in section 12.
- Architecture alignment: continuous DNS Cache update → DNS Application Identification FIRST → `DNS_IDENTIFIED` early exit / `DNS_UNRESOLVED` → TLS/SNI SECOND → unresolved → Burst-based ML.
- Locked decisions: client-scoped cache; query does not create positive mapping; successful response only; A/AAAA/CNAME; minimum TTL expiry across CNAME chain; normalized exact/label-boundary suffix domain rules; multiple candidates on shared IP; same-Application candidates identify, cross-Application candidates unresolved; Flow-level result binding/reuse; no DNS packet-N threshold.
- Source layout target: `src/appid/dns/{models,parser,cache,domain_rules,identifier}.py`; verified domain rules in `config/dns_mapping.yaml`.
- At the time of this historical design package, no DNS source was included. DNS source implementation and core tests are now recorded in section 12. Full DNS-unresolved → SNI call-order integration remains pending because SNI orchestrator is not yet implemented.


## 7. P0.5 source implementation status

- `src/appid/dns/parser.py`: IMPLEMENTED. Parses Scapy DNS over UDP/TCP, correlates response to observed query by session/transaction/transport/endpoints, and falls back to a uniquely LAN-destined response only when client scope is unambiguous.
- `src/appid/dns/cache.py`: IMPLEMENTED. Session/client-scoped A/AAAA/CNAME bindings, CNAME chain validation, minimum TTL expiry, shared-IP candidates.
- `src/appid/dns/domain_rules.py`: IMPLEMENTED. IDNA/lowercase/trailing-dot normalization, exact/suffix label-aware matching, exact and most-specific precedence.
- `src/appid/dns/identifier.py`: IMPLEMENTED. DNS_IDENTIFIED only when all matching candidate domains resolve to one Application ID; shared-app domains are accepted, cross-app ambiguity is unresolved.
- `src/appid/pipeline/processor.py`: DNS observations are extracted from the original raw packet before metadata-only Flow storage; DNS results are bound to Flow and reused by later packets.
- `FlowState.identification_result`: stores the DNS early-exit `IdentificationResult` and evidence snapshot.
- `config/dns_mapping.yaml`: populated in P0.5.1 with 33 conservative, sourced suffix rules for the five named applications; `other-web` remains a non-DNS catch-all class.
- Current environment validation: 48 passed, 2 skipped. The Scapy-dependent parser tests were skipped because Scapy is not installed in the build environment; install project requirements and run `pytest` to execute them. The existing opt-in live NIC test remains skipped by default.
- SNI and Burst ML orchestration are not implemented by this P0.5 source change; unresolved DNS remains unclassified at this pipeline boundary for the next stage to handle.


## 12. P0.5 — DNS source implementation

See `docs/IMPLEMENTATION_NOTES.md` for files, test results and environment limitations. DNS parser/cache/identifier are implemented and integrated with Flow state. The domain-rule file was initially empty; it is populated by P0.5.1 with a conservative seed mapping. See `docs/spec/15-dns-domain-rule-provenance.md`.


## 13. P0.5.1 — Dataset-aligned DNS domain rules

- [x] Align DNS rules to the five named application labels in the six-class Flow dataset: `chatgpt`, `facebook`, `tiktok`, `youtube`, `spotify`.
- [x] Add 33 suffix rules to `config/dns_mapping.yaml`; preserve exact/suffix and label-boundary matching.
- [x] Keep `other-web` out of DNS rules; unmatched domains remain DNS-unresolved for SNI/ML.
- [x] Exclude broad shared-provider domains and sibling Meta/ByteDance products to reduce false positives.
- [x] Add rule provenance and deliberate exclusions in `docs/spec/15-dns-domain-rule-provenance.md`.
- [x] Add config-loading, representative-host, negative-boundary and shared-provider tests.
- Validation: 52 passed, 2 skipped; compileall passed. Scapy DNS parser tests and opt-in live NIC integration remain skipped in this environment.
- Limitation: these are seed rules from public domain references, not an exhaustive inventory of every hostname observed in the user's 25,263 samples. Refine from isolated labeled PCAP/DNS sessions before claiming complete DNS coverage.

## 14. P0.5.4 — DNS acceptance test expansion

The laptop test launcher now runs deterministic DNS acceptance scenarios and unit tests before live capture. A companion traffic generator sends DNS lookups and HTTPS requests for the five target apps. Live output reports identified Flows per Application and is fully PASS only when all five are observed; partial observations remain PARTIAL. See `docs/testing/dns-live-laptop-test.md` and `docs/IMPLEMENTATION_NOTES.md`.


## P0.6.2 implementation status

P0.6.2 TCP Reassembly core is implemented in `src/appid/sni/tcp_reassembly.py`
with bounded per-Flow/per-direction stream buffers. It handles segmentation,
out-of-order delivery, retransmissions, first-seen overlaps and sequence-number
wraparound, with explicit timeout and memory cleanup APIs. Unit tests cover
these behaviors. This milestone does not yet connect reassembly to live capture
or call the TLS parser; that integration remains a subsequent milestone. See
`docs/architecture/tcp-reassembly-design.md` and
`docs/releases/P0.6.2-release-notes.md`.

## P0.7 — UDP and QUIC roadmap

- [x] **P0.7.1 UDP Flow Tracking** — standalone bounded UDP pseudo-flow
  tracking, bidirectional datagram/byte counters, LAN-based direction policy,
  idle expiry and explicit lifecycle controls. See
  `docs/architecture/udp-flow-tracking-design.md` and
  `docs/releases/P0.7.1-release-notes.md`.
- [x] **P0.7.2 UDP Protocol Identification** — standalone conservative protocol metadata
  identification for DNS, DHCPv4, NTP, STUN and QUIC Initial candidates, with explicit
  UNKNOWN handling and no port-only identification. Unit/build validation recorded separately.
- [x] **P0.7.3 QUIC v1 Initial Parsing** — v1 Initial header, RFC 9001 key
  schedule, header protection, packet-number reconstruction, AES-GCM
  authentication/decryption, Initial frames, CRYPTO reassembly and visible
  ClientHello/SNI extraction. Standalone; not yet integrated into live/PCAP.
- [x] **P0.7.4 Hybrid TCP + UDP Identification** — integrated UDP/protocol/QUIC
  evidence into the shared PacketProcessor and common Flow reporting; build
  unit/synthetic integration tests pass. User-laptop live acceptance remains OPEN.

P0.7.1 does not claim live integration or UDP application identification.


## 14. P0.6.3–P0.6.5 — TCP SNI AppID integration (2026-11-24)

| Component | Source status | Validation status | Notes |
|---|---|---|---|
| TCP SNI domain mapping | IMPLEMENTED | UNIT TESTED | Reuses `config/dns_mapping.yaml`; five named app IDs only |
| TCP reassembly → ClientHello parser | IMPLEMENTED | UNIT TESTED | Integrated in shared `PacketProcessor`; out-of-order segments covered |
| DNS → SNI early-exit policy | IMPLEMENTED | UNIT TESTED | DNS match exits; SNI is evaluated only for DNS-unresolved Flows; late DNS overrides earlier SNI |
| Live capture integration | IMPLEMENTED | NOT LIVE-ACCEPTED IN BUILD ENV | `SingleNICCapture` uses the shared processor; target laptop acceptance pending |
| PCAP replay integration | IMPLEMENTED | UNIT TESTED AT PROCESSOR LEVEL | Uses the same `PacketProcessor`; Scapy PCAP replay not run in this container |

Build-container tests after this change: 88 passed, 2 skipped; Python compileall
passed. Scapy is absent and dependency installation was blocked by unavailable
network access, so Scapy-specific fixtures and real-NIC capture remain pending.
Do not mark TCP fully accepted until the dependency-enabled laptop test and
live capture acceptance pass. This paragraph is a historical P0.6.3–P0.6.5
snapshot; UDP/QUIC work is recorded in sections 16–17 below.


## 15. P0.6.5 — TCP live acceptance update (2026-11-24)

| Check | User laptop evidence | Status |
|---|---|---|
| Linux setup + Scapy runtime | `setup_linux.sh` completed; Python 3.12.3, Scapy 2.8.0 | PASS |
| Full unit suite | 98 passed, 1 skipped, 1 warning | PASS |
| DNS deterministic acceptance | 9/9 scenarios | PASS |
| Live capture on selected NIC | `wlp62s0`, `192.168.1.18/24`; 1,607 raw packets, 146 Flows | PASS (short run) |
| TCP/SNI path | 74 TCP payload packets, 66 ClientHellos, 5 SNI-identified Flows | PASS (observed traffic) |
| Five target app labels | ChatGPT, Facebook, TikTok, YouTube, Spotify all observed; `hybrid_dns_sni` / `DNS_SNI_AGREE` logged for each | PASS |
| Full 180-second soak | User stopped capture after 11 seconds | OPEN |

Interpretation: P0.6.5 is verified on the user's live NIC for the observed short capture. Do not claim a completed 180-second soak or universal SNI-only coverage. See `docs/testing/p0.6.5-tcp-laptop-acceptance-2026-11-24.md`.

### Updated implementation order

1. [x] P0.6.3 SNI application mapping.
2. [x] P0.6.4 DNS + SNI evidence fusion.
3. [x] P0.6.5 shared live/PCAP processor integration; short live laptop acceptance passed.
4. [ ] P0.6.6 full-duration TCP acceptance (complete the configured 180-second run and preserve full output).
5. [x] P0.7.2 standalone UDP protocol identification package (implemented; build tests recorded in its test report).
6. [ ] P0.7.3 QUIC Initial parsing and TLS ClientHello/SNI extraction.
7. [x] P0.7.4 hybrid TCP + UDP source integration; [ ] user-laptop live/PCAP acceptance.

Note: P0.6.6 full 180-second TCP acceptance remains OPEN; this UDP module was developed in parallel and does not waive that acceptance gate.


## 16. P0.7.2 — UDP protocol identification

- [x] Add stateless per-datagram UDP protocol classifier.
- [x] Add conservative structural signatures for DNS, DHCPv4, NTP, STUN and QUIC Initial candidates.
- [x] Keep port-only or malformed payloads UNKNOWN.
- [x] Add tests for positive and negative signature cases.
- [x] Integrate UDP protocol classifier and QUIC Initial analyzer into shared live/PCAP PacketProcessor (P0.7.4).
- [ ] Validate integrated live UDP/QUIC behavior on the user's laptop.
- [x] Implement QUIC v1 packet protection and Initial decryption (P0.7.3);
  QUIC v2 and live/PCAP integration remain out of scope.

See `docs/architecture/udp-protocol-identification.md`,
`docs/releases/P0.7.2-release-notes.md` and
`docs/testing/p0.7.2-udp-protocol-identification.md`.


## 17. P0.7.3 — QUIC v1 Initial parsing (2026-11-24)

| Component | Source status | Validation status | Notes |
|---|---|---|---|
| QUIC v1 Initial header/version parser | IMPLEMENTED | UNIT TESTED | Rejects non-v1 and non-Initial packets |
| RFC 9001 Initial key schedule | IMPLEMENTED | RFC VECTOR PASS | `cryptography`; key/IV/HP compared to RFC 9001 vector |
| Header protection + packet number + AEAD | IMPLEMENTED | SYNTHETIC FIXTURE PASS | AES-128-ECB HP and AES-128-GCM tag validation |
| Initial frame parsing | IMPLEMENTED | UNIT TESTED | PADDING, PING, ACK/ACK_ECN, CRYPTO and CONNECTION_CLOSE |
| CRYPTO reassembly | IMPLEMENTED | UNIT TESTED | Per sender, offset-based, bounded, conflict rejection |
| TLS ClientHello / SNI extraction | IMPLEMENTED | UNIT TESTED | Reuses existing TLS parser; ECH inner name not recovered |
| HTTP/3-only traffic generator | IMPLEMENTED | STATIC CHECKED; RUNTIME PENDING | aioquic; QUIC v1 / h3 ALPN only; no curl dependency; live request not run |
| PCAP QUIC Initial → SNI → AppID rule inspector | IMPLEMENTED | SYNTAX CHECKED | Scapy required; not run against a live PCAP here |
| UDP Flow / PacketProcessor integration | IMPLEMENTED | SYNTHETIC INTEGRATION TESTED | Shared PacketProcessor; live NIC acceptance pending |

Build-container validation: focused QUIC tests **12 passed**; full suite
**109 passed, 2 skipped**. Skips are Scapy-dependent DNS parser tests (Scapy
not installed) and opt-in root live-NIC integration. `compileall` passed. No
live QUIC capture was run. The HTTP/3 generator and PCAP inspection workflow are documented in `docs/testing/quic-http3-live-test.md`; scripts were syntax/CLI checked only, not run against the network. See also `docs/testing/p0.7.3-quic-v1-initial.md`.

### Updated implementation order

1. [x] P0.7.1 UDP Flow Tracking (standalone).
2. [x] P0.7.2 UDP Protocol Identification (standalone).
3. [x] P0.7.3 QUIC v1 Initial parsing and visible SNI (standalone).
4. [x] P0.7.4 integrate UDP protocol metadata and QUIC Initial inspection into
   shared live/PCAP processing; add authenticated Initial CID linking and AppID
   evidence fusion.
5. [ ] Run integrated P0.7.4 live NIC capture and PCAP replay on the user laptop.

P0.6.6 full 180-second TCP laptop acceptance remains OPEN. P0.7.3 does not
change or waive that separate acceptance gate.


### P0.7.3 — HTTP/3 test-tool correction

The initial curl-backed generator was incompatible with the user's Ubuntu curl
8.5.0 (`libcurl` was built without HTTP/3). It has been replaced by an aioquic
client and `aioquic>=1.2,<2.0` is now a project dependency. The new generator
uses HTTP/3 ALPN and QUIC v1 only, validates certificates, and never falls
back to TCP. Runtime validation is pending because the build container could
not reach PyPI; laptop live acceptance remains OPEN.


## 18. P0.7.4 — Hybrid TCP + UDP / QUIC integration (2026-11-24)

| Component | Source status | Build validation | Notes |
|---|---|---|---|
| Shared TCP/UDP PacketProcessor dispatch | IMPLEMENTED | UNIT/INTEGRATION TESTED | Same processor used by live capture and PCAP replay |
| UDP protocol identification | IMPLEMENTED | UNIT TESTED | DNS/DHCPv4/NTP/STUN/QUIC candidate; structural checks retained |
| UDP Flow lifecycle | IMPLEMENTED | UNIT TESTED | Shared Flow IDs; UDP-only idle expiry and active-flow capacity |
| QUIC v1 Initial processing in UDP path | IMPLEMENTED | SYNTHETIC INTEGRATION TESTED | Authenticated Initial → CRYPTO → ClientHello → SNI → AppID |
| QUIC Connection/CID tracker | IMPLEMENTED | UNIT TESTED | Authenticated Initial CIDs link UDP Flow IDs; not full 1-RTT migration |
| DNS → QUIC SNI early-exit policy | IMPLEMENTED | UNIT TESTED | QUIC SNI is evaluated only for DNS-unresolved UDP Flows |
| Live/PCAP counters | IMPLEMENTED | STATIC/UNIT CHECKED | Same PacketProcessor; no new live capture or PCAP run in build container |
| Five-app live integrated acceptance | OPEN | NOT RUN | Must rerun on user's Linux laptop with this P0.7.4 ZIP |

Build-container result: **122 passed, 2 skipped**. `compileall` and shell
syntax checks passed. Scapy is unavailable here; DNS Scapy parser tests and
opt-in live NIC integration remain skipped. This is source/unit/synthetic
integration validation, not a live network acceptance claim.

Limitations: QUIC v1 Initial only; no v2, Retry, 0-RTT/1-RTT, HTTP/3 payload
decoding or ECH inner-SNI recovery. CID linkage uses CIDs authenticated/seen
in Initial packets; NEW_CONNECTION_ID frames are not processed. A successful
Initial decrypt or SNI match does not prove a completed HTTP/3 request. The
previous P0.7.3 laptop PCAP result remains valid evidence for its standalone
inspector, not a substitute for P0.7.4 integrated live acceptance.

Next actions:

1. [x] Integrate UDP dispatch and QUIC Initial processing into `PacketProcessor`.
2. [x] Add separate UDP Flow lifecycle and QUIC Connection/CID state.
3. [x] Add common DNS/TCP/QUIC evidence policy and protocol-specific counters.
4. [x] Add synthetic end-to-end tests and document constraints.
5. [ ] Run `./setup_linux.sh` and `./run_tests.sh` on the user's laptop.
6. [ ] Run integrated live capture on `wlp62s0` and confirm all five app labels
   using UDP/QUIC and TCP/DNS evidence as observed; save the full report.
7. [ ] Replay the same captured PCAP through the integrated processor and
   compare AppID evidence/results with the live run.


## 19. P0.7.5 — TCP SNI live acceptance tooling

| Component | Source status | Build validation | Notes |
|---|---|---|---|
| Forced TCP HTTPS generator | IMPLEMENTED | SHELL SYNTAX PASS | curl `--http1.1`; no HTTP/3 fallback |
| Single-NIC TCP/443 capture runner | IMPLEMENTED (P0.7.5.2) | SHELL SYNTAX PASS | Uses dumpcap, SIGINT cleanup and 180s hard limit; repeat laptop run required |
| TCP SNI PCAP inspection | IMPLEMENTED | LIVE RUN PENDING | Uses tshark when installed; optional |
| Shared PacketProcessor PCAP replay | IMPLEMENTED | EXISTING TESTS PASS | Per-flow AppID/method/reason now printed |
| Five-app TCP live acceptance | OPEN | NOT RUN IN BUILD ENVIRONMENT | Requires user laptop PCAP and replay evidence |

P0.7.5 is a validation/tooling increment, not a claim that TCP live acceptance
has passed. P0.7.5.2 replaces the AppArmor-blocked background tcpdump cleanup
with dumpcap; the revised runner still requires a complete laptop rerun. Run `sudo ./run_tcp_appid_test.sh <interface>` on the Linux laptop.
A completed curl request is not sufficient: expected TCP TLS SNI must appear in
the PCAP and the shared PacketProcessor replay must classify the TCP flow.

Next actions:
1. [x] Add forced HTTP/1.1 probes for ChatGPT, Facebook, TikTok, YouTube and Spotify.
2. [x] Add one-command TCP/443 capture, optional tshark inspection and PacketProcessor replay.
3. [x] Include per-flow AppID/method/reason in PCAP replay output.
4. [ ] Re-run P0.7.5.2 live acceptance on the user's Linux laptop and preserve its report.
5. [ ] Re-run/compare integrated UDP/QUIC and TCP evidence, then execute the 180-second stability test.

## P0.7.5.4 user laptop live acceptance — 2026-11-24

**PASS — based on user-provided terminal output.**

- Unit tests: 135 passed, 1 skipped, 1 warning (Scapy DNS deprecation warning).
- Five HTTP probes (ChatGPT, Facebook, TikTok, YouTube, Spotify): HTTP 200 and curl exit 0.
- dumpcap: 2,180 packets captured, 0 dropped; final PCAP 3,346,168 bytes, mode 0644.
- tshark observed all five expected SNI hostnames.
- Strict replay: raw=2180, parsed=2180, tracked=2180, unsupported=0, parse_errors=0; sni_errors=2 (non-fatal diagnostic).
- Strict verifier: 5/5 target TCP/SNI AppIDs PASS.

This proves TCP/SNI acceptance only, not live QUIC/HTTP3 or ML model behavior.

## Accepted next implementation increment

**P1.0 — ML Candidate Gate + immutable Flow observation adapter**
- [x] Reuse FlowTracker/FlowState; do not create another bidirectional Flow identity.
- [x] Add candidate states `ELIGIBLE`, `PENDING`, `REJECTED` and reason codes.
- [x] Candidate eligibility requires DNS and SNI both unresolved.
- [x] Define immutable ML observation with existing `session_id`/`flow_id`, ordered packet metadata, direction coverage, and quality flags.
- [x] Test DNS/SNI early exit, admission, ordering, direction preservation, one-way Flow, and invalid metadata.
- [x] Do not implement Burst segmentation or models in P1.0.

**Implementation note:** no minimum packet-count or duration default is selected. Without an explicit `FlowObservationPolicy`, the gate returns `PENDING / OBSERVATION_POLICY_UNCONFIGURED`. Duplicate packet-index handling also remains pending until its policy is decided.

**P1.1** implements Burst Segmentation after boundary rules are decided. CatBoost, 1D-CNN, Late Fusion, and ML runtime inference remain unimplemented.


## P1.1 — Bidirectional Flow Reconstruction + Burst Segmentation

- [x] Reuse the immutable P1.0 Flow observation adapter and preserve the existing FlowTracker identity.
- [x] Implement ML-specific bidirectional reconstruction without creating a second Flow ID or parsing payload.
- [x] Implement immutable Burst records with stable `session_id → flow_id → burst_index` lineage.
- [x] Fix direction-change boundary: FORWARD/BACKWARD/UNKNOWN transitions start a new Burst; UNKNOWN remains distinct.
- [x] Add configurable idle-gap boundary without selecting a numeric default (`None` disables it; split when gap is strictly greater than threshold).
- [x] Add unit tests for direction boundaries, idle gaps, one-way flows, identity preservation and invalid policy values.
- [ ] Burst Statistics schema and formulas (P1.2).
- [ ] Burst Sequence tensor schema and preprocessing (P1.2).
- [ ] Dataset-specific idle-gap selection using the user's CSV and validation experiments.

P1.1 does not implement CatBoost, 1D-CNN, Late Fusion, training, or runtime ML orchestration.


## Runtime policy correction — 2026-11-26

The prior evidence-fusion behavior (DNS/SNI agreement and SNI-preferred conflict) is superseded. The current source implements the accepted DNS-first early-exit architecture. Unit tests now cover DNS early exit and DNS precedence over SNI. Previous live acceptance logs are retained as historical evidence of the earlier implementation and must not be interpreted as a fresh acceptance run of this policy change.

## Current authoritative status — 2026-11-27

This section supersedes earlier statements in this roadmap that say runtime ML inference is deferred. Those statements remain historical snapshots only.

### Delivered / integrated
- Shared PacketProcessor used by single-NIC Live Capture and offline PCAP replay.
- Packet parsing, canonical bidirectional Flow tracking and UDP expiry/capacity handling.
- DNS parser/cache/domain rules and DNS-first early exit.
- Bounded TCP reassembly, TLS ClientHello/SNI mapping.
- UDP protocol checks and QUIC v1 Initial decrypt/CRYPTO/SNI path.
- Candidate Gate, immutable Flow observation, Burst reconstruction/segmentation/statistics.
- CatBoost Flow V2 runtime integration: optional model load, 70 Flow features, ordered `predict_proba`, Flow result attachment.
- Live run supplied by owner: 23 predictions, 0 inference errors.

### Validated evidence
- Prior owner-supplied test command: compileall plus pytest; 195 passed, 1 skipped, 1 warning in 1.81 seconds. Not rerun on this ZIP.
- One ML live run: 171 raw, 167 parsed, 164 tracked; 24 candidate Flows evaluated, 23 admitted, 1 pending; 23 predictions, 0 inference errors; 24 Flows finalized, 108 Bursts.
- Older DNS/TCP-SNI and mixed TCP/QUIC acceptance results remain separate historical evidence. They must not be merged with the ML live run.

### Open items / next work
1. Add final Flow-level result export (CSV/JSONL) and ensure live shutdown displays or persists post-finalization predictions.
2. Verify model-enabled PCAP replay end-to-end on a small known fixture.
3. Evaluate against ground truth; report per-class precision/recall/F1, macro-F1 and confusion matrix. Do not infer accuracy from prediction counts.
4. Define calibrated confidence/UNKNOWN policy; current argmax always emits one of six model classes when inference succeeds.
5. Measure inference latency, CPU/RAM and long-running Flow state growth; TCP Flows currently do not idle-expire.
6. Keep the model binary and large datasets outside the lightweight source archive but document exact paths/checksums in a separate artifact manifest.

### Status vocabulary
`DONE` = implemented and integrated with relevant tests/evidence; `PARTIAL` = bounded scope or output/acceptance gap; `NOT IMPLEMENTED` = absent in source; `NOT VERIFIED` = cannot be established from code or supplied results.
