# Implementation Notes

## P0.1 — Domain contracts

- `src/appid/domain/models.py`: `PacketRecord`, direction/protocol enums, identification evidence and result models.
- Tests: `tests/unit/packet/test_models.py`.

## P0.2 — Flow identity

- `src/appid/flow/identity.py`: canonical bidirectional endpoint tuple and explicit client-endpoint direction resolution.
- Direction is not inferred from the first packet or port heuristics.
- Tests: `tests/unit/flow/test_identity.py`.

## P0.3 — Stateful Flow Tracker and one-NIC policy

- `src/appid/flow/tracker.py`: session-scoped Flow IDs, active/closed lifecycle, packet sequence, counters and tuple reuse after explicit close.
- `src/appid/network/interfaces.py`: active interface discovery, interface selection (`auto`/`manual`) and subnet discovery helpers.
- One session selects exactly one interface. `auto` uses the first usable active interface in OS enumeration order. `manual` fails closed if the requested interface is unavailable.
- No idle timeout is invented. FIN/RST does not automatically close a Flow.

## P0.4 — Capture, parsing and shared processing

- `src/appid/capture/live.py`: Scapy live capture bound to exactly the selected NIC.
- `src/appid/capture/pcap.py`: offline PCAP replay.
- `src/appid/packet/parser.py`: Scapy packet to normalized `PacketRecord` conversion for IPv4/IPv6 TCP/UDP.
- `src/appid/pipeline/processor.py`: shared processing path for live and PCAP sources: parse → selected-LAN filter → FlowTracker.
- Capture timestamps from the source packet are retained; parser wall-clock time is never substituted.
- Unsupported packets and parser errors are counted and skipped without stopping the stream. Packets outside the selected LAN are counted and ignored.
- Empty PCAP input is reported as an error; no prediction is generated.

## Validation notes

Run `python -m pip install -e ".[dev]"` followed by `pytest -q`. Live NIC capture requires an actual Linux interface and suitable privileges. Offline replay tests create deterministic PCAP fixtures. The build environment did not execute hardware capture; the user subsequently ran the P0.4.1 smoke test successfully on their Linux host (details below).

## P0.4.1 — Real Linux single-NIC capture verification

- `scripts/verify_live_nic.py`: opt-in smoke test that resolves the selected NIC from the same config, binds Scapy capture to that NIC only, emits a uniquely marked UDP broadcast through a socket bound to the same NIC (`SO_BINDTODEVICE`), and asserts the marked packet is parsed, subnet-filtered and inserted into `FlowTracker`.
- `docs/testing/live-nic-capture.md`: setup, manual/auto NIC configuration, commands, expected output, troubleshooting and acceptance checklist.
- `tests/integration/test_live_nic_linux.py`: real-NIC pytest test, skipped by default; enable with `APPID_RUN_LIVE_NIC_TEST=1` and root/capture privileges.
- Automated suite in this build: `40 passed, 1 skipped`; compile check passed.
- User-reported target-host result: PASS on interface `wlp62s0`, local address `192.168.1.18`, subnet `192.168.1.0/24`; 3 marker frames seen, 3 raw packets processed, 3 parsed, 3 tracked, 1 Flow created with 3 packets.
- Scope limitation: this proves the outbound marker capture path on the selected NIC. It does not yet prove inbound traffic from another LAN device, exclusion of a second NIC via a controlled comparison, multiple concurrent TCP/UDP flows, or all Flow lifecycle acceptance cases.


## P0.5 — DNS design lock (documentation only)

- `docs/spec/03-dns-cache-design.md`: locked DNS Parser/Cache/Identifier responsibilities, client-scoped lookup, A/AAAA/CNAME, TTL expiry, domain normalization/rules, shared-IP ambiguity, Flow result reuse and acceptance criteria.
- `docs/spec/02-runtime-packet-flow.md` and `13-module-contracts.md`: clarified metadata-only `PacketRecord` plus ephemeral raw protocol-payload side channel; DNS payload is parsed but not persisted into Flow/Dataset/logs.
- `docs/spec/01-system-architecture.md`, `09-runtime-classification.md`, `12-glossary-and-decisions.md`, `14-implementation-parameters.md`, `10-testing-and-troubleshooting.md`, `PROJECT-README.md`, and `11-roadmap-and-status.md` updated to the same DNS → SNI → Burst ML architecture and rule contracts.
- Locked DNS rules: cache updates continuously; query does not create positive mapping; successful response only; A/AAAA/CNAME; CNAME binding expires at minimum TTL in the chain; normalized exact/label-boundary suffix rules; all candidates same app = identified; candidates across apps = unresolved; first eligible Flow DNS evaluation can identify immediately; Flow result is reused by later packets.
- Historical note: this section records the initial documentation-only P0.5 design package. It is superseded by the P0.5 source implementation section immediately below.

## P0.5 — DNS Parser, Cache and Application Identifier

Implemented under `src/appid/dns/` with separate parser, cache, domain-rule and identifier modules. The shared `PacketProcessor` extracts DNS evidence from the original Scapy packet after the selected-LAN filter, then stores only normalized metadata in DNS Cache. DNS positive bindings are scoped by capture session, client IP and resolved destination IP; CNAME chain expiry uses the minimum TTL across the chain and terminal A/AAAA record. A DNS identification result is stored on `FlowState.identification_result` and reused for later packets.

`config/dns_mapping.yaml` now contains 33 conservative suffix rules for `chatgpt`, `facebook`, `tiktok`, `youtube`, and `spotify`, aligned to the five named app classes in the six-class Flow dataset. `other-web` is intentionally not a DNS catch-all. Domain provenance and deliberate exclusions are documented in `docs/spec/15-dns-domain-rule-provenance.md`. SNI and Burst ML fallback orchestration remain subsequent implementation work.

Validation in the current build environment: `python -m compileall -q src tests` passed; `pytest -q` reported 48 passed, 2 skipped. Scapy is absent in this environment, so Scapy-specific DNS parser tests and the opt-in live NIC integration test did not execute. Ruff is also not installed. Run `pip install -e '.[dev]'` in the project environment, then `pytest` and `ruff check src tests` to complete those checks.


## P0.5.1 — Dataset-aligned DNS domain rules

- Added 33 suffix rules across ChatGPT, Facebook, TikTok, YouTube and Spotify.
- Kept `other-web` as an ML class only; unmatched DNS names do not become `other-web`.
- Excluded broad provider roots (`googleapis.com`, `gstatic.com`, `cloudflare.com`, etc.), generic ByteDance infrastructure, and Instagram/WhatsApp/Threads from the Facebook class.
- Added tests for YAML loading, each application's representative hostnames, label-boundary false positives and shared-provider exclusions.
- Validation: `python -m compileall -q src tests` passed; `python -m pytest -q` → 52 passed, 2 skipped. The skipped tests are the Scapy-dependent DNS parser test module (Scapy unavailable in this build environment) and the opt-in live NIC integration test.
- Domain source references and limitations: `docs/spec/15-dns-domain-rule-provenance.md`. The rules are a conservative seed list; they have not been exhaustively validated against all DNS names in the 25,263-row dataset.

## P0.5.4 — DNS acceptance test expansion

- Added `scripts/test_dns_scenarios.py`: deterministic acceptance checks for five target app domain rules, same-application shared-IP resolution, cross-application shared-IP ambiguity, client isolation, and TTL expiry.
- `run_dns_test.sh` now runs the deterministic scenarios and complete unit suite before starting live NIC capture.
- Added `generate_dns_test_traffic.sh` to produce system-resolver DNS lookups and HTTPS requests for ChatGPT, Facebook, TikTok, YouTube and Spotify from a second terminal.
- Live test now reports identified Flow counts by Application and only reports full PASS when all five target Application IDs are observed; otherwise it reports PARTIAL and names missing apps.
- Validation in the build environment: 9/9 deterministic scenarios passed; 52 unit tests passed; 2 skipped (Scapy unavailable in this build environment for parser fixture tests; opt-in root live-NIC test). Shell syntax and Python compilation passed. `ruff` was not installed in the build environment.
- The deterministic shared-IP/client/TTL checks use synthetic DNS observations. They validate policy logic, not claims about the real CDN/IP behavior of public services.

### P0.5.7 DNS answer-section compatibility

Scapy 2.8 dissects DNS `qd`/`an` sections as PacketListField collections, while
some in-memory test packets expose a single packet object. The DNS parser now
normalizes both representations before reading questions and answer records.
A serialized/deserialized CNAME+A regression test covers the live dissection
shape. The live runner also prints unexpected DNS exception types separately,
so `dns_processing_errors` is diagnosable instead of being only an aggregate.

## P0.5.9 — DNS Answer flattening and diagnostics

- Fixed DNS Answer normalization so DNSRR payload chains nested inside Scapy's
  PacketListField entries are traversed. This prevents an A/AAAA record following
  a CNAME from being silently dropped.
- Added packet-level diagnostic logging for DNS query/response correlation, Answer
  records, cache insertion/hit/miss, and application identification decisions.
- Added `--dns-debug` to the live test and parser diagnostic reason counters to its
  final summary. Logs contain metadata only; packet payloads are not logged.
- Added isolated regression tests for nested RR chains and duplicate prevention.
- The Scapy wire-roundtrip regression test remains in `tests/unit/dns/test_parser.py`
  and must be run on the laptop's Scapy installation.

## P0.5.10 — Scapy 2.8 CNAME+A regression fixture correction

- Corrected `test_deserialized_response_parses_packetlist_cname_and_address_answers` to construct the DNS answer section as a `PacketListField` list (`an=[CNAME, A]`).
- The previous fixture chained two `DNSRR` objects as one payload. Under Scapy 2.8 this does not represent two entries in the answer `PacketListField` and the serialized packet's answer count/section therefore omitted the terminal A record. The parser's existing flattening logic continues to support both PacketListField collections and nested RR payload chains.
- Validation in this build environment: deterministic DNS acceptance scenarios 9/9 passed; `pytest -q` 57 passed, 2 skipped; `compileall` passed. Scapy is not installed in this isolated build environment, so the Scapy-dependent wire-roundtrip test module was skipped here; rerun `pytest -q` in the user's `.venv` (where Scapy 2.8.0 is installed) to execute that exact regression test. Live NIC capture was not run in this environment.

## P0.6.2 — Bounded TCP Reassembly

- Added `src/appid/sni/tcp_reassembly.py` as a standalone component. It accepts
  a Flow ID, explicit direction, TCP sequence number, payload, timestamp and
  SYN/FIN/RST flags; it emits only newly contiguous bytes.
- Supports TCP segmentation, out-of-order buffering, retransmission
  suppression, first-seen overlap policy, 32-bit sequence wraparound, and
  independent forward/backward buffers.
- Adds configurable limits for stream count, per-stream and global buffered
  bytes, sequence gap, segment payload size, and idle lifetime. Adds explicit
  `cleanup(now)`, `close_flow(flow_id)` and RST cleanup.
- Added 10 unit tests covering stream ordering, overlap, duplicates, direction
  and Flow isolation, wraparound, timeouts, memory bounds and reset cleanup.
- Added `docs/architecture/tcp-reassembly-design.md` and
  `docs/releases/P0.6.2-release-notes.md` describing architecture, API,
  policies, limitations, and verification scope.
- DNS source under `src/appid/dns/` and P0.6.1 TLS/SNI parser files were not
  edited. `PacketProcessor` and live capture were not integrated in this
  milestone; live SNI identification is not claimed. A later integration
  milestone must pass emitted bytes into `TLSClientHelloParser`.
- Build-container validation: `PYTHONPATH=src python3 -m pytest -q
  tests/unit/sni/test_tcp_reassembly.py tests/unit/sni/test_tls_parser.py` →
  21 passed. Scapy is not installed in this build container, so the complete
  DNS/Scapy-backed suite and real-NIC capture could not be validated here.
  Run `./setup_linux.sh` then `./run_tests.sh` on the target Linux host before
  treating the ZIP as fully accepted.
- Final build-container regression after P0.6.2: `PYTHONPATH=src python3 -m
  pytest -q -rs` → **78 passed, 2 skipped**. Skip reasons: Scapy-dependent DNS
  parser tests (Scapy unavailable in this container) and opt-in root live-NIC
  integration. Focused TLS parser + TCP reassembly tests: **21 passed**;
  `compileall` and shell syntax checks passed. Ruff is unavailable. DNS source
  and P0.6.1 TLS parser source were byte-compared with the uploaded P0.6.1 ZIP
  and remain unchanged. Real-NIC capture was not run in this environment.

## P0.7.1 — UDP Flow Tracking

- Added standalone `src/appid/udp/flow_tracker.py`; UDP is modeled as a
  bidirectional, session-scoped pseudo-flow and datagrams are counted rather
  than reassembled as a byte stream.
- Tracks datagrams and packet-length bytes by forward/backward/unknown
  direction. Client direction is assigned only when exactly one endpoint is
  inside configured LAN subnets; otherwise direction remains UNKNOWN.
- Added configurable idle timeout and maximum active-flow count, plus explicit
  cleanup, flow close and session close operations.
- Added unit tests for bidirectional accounting, canonical identity, session
  isolation, ambiguous direction, idle expiry, capacity, and lifecycle.
- Added `docs/architecture/udp-flow-tracking-design.md` and
  `docs/releases/P0.7.1-release-notes.md`.
- Scope limitation: not integrated into live capture/PacketProcessor; no UDP
  protocol classification, QUIC Initial parsing, QUIC SNI, or AppID mapping.
  Existing generic FlowTracker already recognizes UDP metadata; this module
  adds a dedicated UDP lifecycle/accounting contract without changing it.


## P0.6.3–P0.6.5 — TCP SNI AppID integration (2026-11-24)

- **Source baseline:** `hybrid-appid-starter-p0.7.1-udp-flow-tracking.zip` from
  the project Library. Baseline suite in this container: 85 passed, 2 skipped.
- **Added:** `src/appid/sni/identifier.py`; it reuses the existing YAML domain
  rules rather than maintaining a second list that could drift.
- **Integrated:** `src/appid/pipeline/processor.py` now sends client-direction
  TCP payload through the existing bounded reassembler and TLS ClientHello
  parser. This same processor is used by live NIC capture and PCAP replay.
- **Flow result policy:** SNI-only result uses method `sni`; matching DNS+SNI
  evidence uses `hybrid_dns_sni`; conflicts prefer SNI and record the DNS app in
  metadata. `other-web` remains non-catch-all.
- **Bounds/cleanup:** 64 KiB temporary ClientHello accumulation per Flow,
  existing reassembler limits, idle cleanup and close/terminal cleanup.
- **Observability:** live and PCAP summaries expose SNI parser and classifier
  counters.
- **Tests:** `python3 -m pytest -q` → 88 passed, 2 skipped;
  `python3 -m compileall -q src tests` → passed.
- **Environment limitation:** Scapy absent and package installation could not
  reach the package index. Thus Scapy-backed DNS parser tests and live NIC
  capture were not executed here. New integration tests use doubles for packet
  metadata and verify out-of-order TCP segment reassembly, SNI mapping,
  unmapped-host behavior and DNS/SNI agreement.
- **Next:** run the full dependency-enabled test suite and live TCP acceptance on
  the user's Linux laptop. Only after that should TCP be marked fully accepted
  and work move to UDP/QUIC.


## P0.6.5 — User laptop live acceptance (2026-11-24)

- User ran `./setup_linux.sh` successfully on Linux with Python 3.12.3 and Scapy 2.8.0.
- User ran `./run_tests.sh`: **98 passed, 1 skipped, 1 warning**. The warning is Scapy 2.8's DNS `qd`/`an`/`ns`/`ar` deprecation notice.
- `./run_dns_test.sh --interface wlp62s0 --duration 180`: deterministic DNS acceptance **9/9 passed**; live capture ran on `wlp62s0` (`192.168.1.18/24`) and was manually interrupted after 11.0 seconds.
- Live summary: 1,607 raw packets, 1,569 parsed, 1,568 tracked, 146 Flows; 74 TCP payload packets; 66 TLS ClientHellos; 5 SNI-identified Flows; 5 DNS-identified Flows.
- All five target apps were observed (`chatgpt`, `facebook`, `tiktok`, `youtube`, `spotify`); each observed app Flow logged `method=hybrid_dns_sni`, `reason=DNS_SNI_AGREE`. Runner printed its all-five-applications PASS.
- Caveat: this is a successful **11-second live acceptance**, not a completed 180-second soak run. The log also reports 61 unmapped SNI names and 5 SNI parse errors; DNS and packet parse errors were zero. See `docs/testing/p0.6.5-tcp-laptop-acceptance-2026-11-24.md` for the evidence and limits.
- Status: TCP live integration is verified on the user's NIC for the observed traffic; full-duration stability remains OPEN. P0.7.2 standalone UDP protocol identification is now implemented; QUIC Initial decryption and shared UDP pipeline integration remain open.

## P0.7.2 — UDP protocol identification (implementation package)

- Added `src/appid/udp/protocol_identifier.py` with stateless, per-datagram
  structural checks for DNS, DHCPv4, NTP, STUN and QUIC Initial candidates.
- Ports are corroborating checks only; arbitrary payloads on well-known ports
  remain `UNKNOWN`. The module reports protocol metadata, not one of the six
  application labels.
- QUIC is deliberately reported as `QUIC_INITIAL_CANDIDATE` with confidence
  below 1.0. Version-specific packet-type interpretation, header protection
  removal, Initial decryption and TLS ClientHello/SNI parsing are not included;
  these belong to P0.7.3.
- Added deterministic unit tests for positive signatures, malformed packets,
  port-only false positives and QUIC candidate labeling.
- This module is currently standalone: it is not wired into `PacketProcessor`
  or live capture. P0.7.4 owns the unified UDP/TCP reporting integration.
- Validation in this build container: 6 UDP classifier tests passed; compileall passed; full suite 96 passed, 2 skipped (Scapy DNS parser dependency absent; opt-in live NIC test). Ruff unavailable. No live UDP capture was run. Full details: `docs/testing/p0.7.2-udp-protocol-identification.md`.


## P0.7.3 — QUIC v1 Initial Parsing

- Added `src/appid/udp/quic/` with v1 Initial header/varint parsing, RFC 9001
  Initial HKDF key schedule, AES header protection removal, packet-number
  reconstruction, AES-128-GCM authentication/decryption, Initial-frame parser,
  bounded per-sender CRYPTO reassembly and connection-scoped SNI extraction.
- Reuses `TLSClientHelloParser` by wrapping the reassembled TLS handshake
  message in a synthetic TLS record envelope; QUIC CRYPTO data itself is not a
  TLS record and is never sent to TCP reassembly.
- Client Initial establishes original DCID only after successful authentication.
  Server Initial first observed requires an explicit original DCID; no guess is
  made. Authentication failure never yields SNI.
- Added `cryptography>=42.0,<47.0` to runtime dependencies.
- Scope: QUIC v1 Initial only. No QUIC v2, Retry, 0-RTT/1-RTT, ECH inner
  recovery, UDP Flow/PacketProcessor integration, live capture or AppID mapping.
- Focused QUIC tests: 12 passed, including RFC 9001 key schedule vector.
- Full build-container suite: 109 passed, 2 skipped (Scapy DNS parser dependency
  absent; opt-in root live-NIC test). `compileall` passed. Live QUIC capture not run.
- Design and evidence: `docs/architecture/quic-v1-initial-parsing.md`,
  `docs/releases/P0.7.3-release-notes.md`,
  `docs/testing/p0.7.3-quic-v1-initial.md`.


## P0.7.3 — HTTP/3 traffic generator and PCAP SNI verification (2026-11-24)

- Added `generate_quic_test_traffic.sh` and
  `scripts/generate_quic_test_traffic.py`. It probes ChatGPT, Facebook, TikTok,
  YouTube and Spotify using `curl --http3-only`; it accepts a request as HTTP/3
  only when curl exits successfully and reports HTTP version `3`. It records
  expected SNI, status, remote IP and timing in a JSON report. Redirects are not
  followed; proxy environment variables are bypassed unless `--allow-proxy` is
  specified.
- Added `scripts/inspect_quic_initial_pcap.py`. It reads a captured PCAP with
  Scapy, groups bidirectional UDP endpoint pairs, runs the standalone QUIC v1
  Initial inspector, extracts visible SNI, and applies the existing
  `config/dns_mapping.yaml` rules. Unmapped hostnames remain `UNMAPPED`, not
  `other-web`.
- Added the complete live procedure and result interpretation in
  `docs/testing/quic-http3-live-test.md`; README now links to it.
- Validation: both scripts pass Python bytecode compilation; traffic generator
  `--help` runs; a fake-curl offline smoke test verified all five result rows and
  HTTP/3 status parsing (not a network test); full suite `PYTHONPATH=src python3 -m pytest -q -rs` →
  **109 passed, 2 skipped**. Local curl is 8.10.1 and exposes `--http3-only`.
- Not run: no external HTTP/3 requests, no live NIC capture, and no PCAP
  inspection. Scapy is absent in this build environment, so the PCAP helper was
  syntax-checked but not exercised against a capture. Ruff was not run.
- Important: this helper enables offline QUIC/SNI verification for P0.7.3; it
  does not wire QUIC into the shared live `PacketProcessor`. That remains P0.7.4.


## P0.7.3 — HTTP/3 generator compatibility correction (2026-11-24)

- User laptop has curl 8.5.0 whose `Features` do not include HTTP3; executing
  `curl --http3-only` returns: `the installed libcurl version doesn't support this`.
  The presence of the option in curl help was not sufficient to establish
  HTTP/3 capability.
- Replaced the traffic generator backend with Python `aioquic`; the generator
  no longer depends on curl or a custom libcurl build. Added
  `aioquic>=1.2,<2.0` to runtime dependencies and setup verification.
- Generator advertises HTTP/3 ALPN only, restricts QUIC to v1, validates TLS
  certificates, connects directly over UDP, and has no HTTP/2/TCP fallback.
  Per-target failures remain failures and are not counted as QUIC traffic.
- Validation limitation in this build container: package installation from
  PyPI was blocked by unavailable DNS/network. The script was reviewed and
  syntax-checked, but aioquic runtime and live HTTP/3 requests were NOT run here.
  The user's next `./setup_linux.sh` will install the declared dependency when
  package access is available.

## P0.7.4 — Hybrid TCP + UDP / QUIC integration (2026-11-24)

- **Shared dispatch:** `src/appid/pipeline/processor.py` now dispatches UDP
  datagrams after the same packet normalization and LAN filter used by TCP.
  Live NIC capture and PCAP replay both instantiate this `PacketProcessor`.
- **Canonical Flow identity:** TCP and UDP packet tuples continue to use the
  shared `src/appid/flow/tracker.py` and one session-scoped Flow ID namespace.
  UDP idle expiry is separate from TCP; active UDP Flow count is bounded.
- **UDP analyzer:** `src/appid/udp/analyzer.py` composes the existing
  structural `UDPProtocolIdentifier` with the QUIC v1 Initial connection tracker.
  DNS/DHCPv4/NTP/STUN remain protocol labels, not application labels.
- **QUIC connection tracking:** `src/appid/udp/quic/connection_tracker.py`
  tracks a separate QUIC connection identity, original DCID, authenticated
  Initial DCID/SCID aliases and linked UDP Flow IDs. CID aliases are created
  only after successful Initial decryption. The current code links Initial
  packets on another UDP tuple when an already-indexed CID is observed; it
  does not parse 1-RTT NEW_CONNECTION_ID frames and does not claim full QUIC
  migration support.
- **Evidence fusion:** `src/appid/appid/evidence_engine.py` applies QUIC SNI
  using the existing approved domain rules. Evidence source is
  `quic_tls_sni`; DNS agreement uses `hybrid_dns_quic_sni` /
  `DNS_QUIC_SNI_AGREE`; conflicts prefer authenticated SNI and preserve the
  DNS application as `dns_conflict_application`. Unmapped hostnames remain
  unresolved, not `other-web`.
- **Protocol separation:** `FlowState.application_protocol` is `QUIC_INITIAL`
  after successful Initial decrypt; it is not reported as HTTP/3. The
  `quic_connection_id` is stored separately from the UDP `flow_id`.
- **Controls:** `PacketProcessor` exposes `enable_udp_analysis`,
  `enable_quic_analysis`, `udp_idle_timeout`, and `max_active_udp_flows`.
  `UDPAnalyzer` / `QUICConnectionTracker` bound connection count, idle lifetime,
  per-connection CRYPTO bytes and CIDs per connection.
- **Observability:** live and PCAP summaries include UDP protocol counts,
  UDP lifecycle/capacity events, QUIC Initial candidates/decrypt/reject counts,
  QUIC SNI mapping counts, ECH detections and QUIC connection capacity events.
- **Tests added:** QUIC CID/connection linking across UDP tuples, invalid AEAD
  rejection, idle cleanup, connection capacity eviction, DNS/QUIC agreement
  and conflict, UDP Flow expiry/capacity, QUIC-disabled behavior and a synthetic
  UDP → QUIC Initial → ClientHello SNI → AppID `PacketProcessor` integration.
- **Validation in this build environment:** `python -m pytest -q` →
  **122 passed, 2 skipped**; `python -m compileall -q src tests` → PASS;
  shell syntax checks → PASS. Scapy is not installed, so Scapy-dependent DNS
  parser tests and opt-in live NIC integration remain skipped. No live NIC
  capture or PCAP replay was run here.
- **Laptop acceptance remains OPEN:** rerun the dependency-enabled test suite
  and the P0.7.4 integrated capture on the user's Linux laptop. Prior P0.7.3
  standalone PCAP evidence is not evidence that this new pipeline has passed
  live acceptance.


## Runtime policy correction — DNS-first early exit (2026-11-26)

The former P0.6/P0.7 evidence-fusion policy (combine DNS and SNI; prefer SNI on conflict) is historical and superseded. The current runtime follows the accepted `DNS → SNI → ML` order: DNS match exits; otherwise SNI is attempted; only unresolved Flows can reach ML Candidate Gate. A valid DNS mapping arriving after an SNI result replaces that result. Historical test reports above describe the implementation at the time they were run and are not retroactively changed.
