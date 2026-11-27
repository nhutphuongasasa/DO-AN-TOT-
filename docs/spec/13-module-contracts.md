# 13 — Module Contracts

> Contract logic cho source implementation mới. Tên field dùng snake_case. Mọi record capture giữ `session_id`; mọi record thuộc connection giữ `flow_id`.

> **Runtime policy (2026-11-26):** DNS-first early exit is implemented. DNS
> identification is authoritative; TCP/TLS SNI and QUIC SNI are evaluated only
> for Flows that remain unresolved after DNS.

## 1. PacketRecord
**Producer:** Capture + Packet Parser. **Consumer:** Flow Tracker. DNS/TLS parsers consume a separate ephemeral protocol-payload view from the same raw packet; payload bytes are not stored in FlowRecord.

| Field | Type logic | Ý nghĩa |
|---|---|---|
| `session_id` | string | Capture session |
| `packet_index` | int | Thứ tự packet trong session |
| `timestamp` | float | Unix timestamp, giữ độ chính xác gốc |
| `src_ip`, `dst_ip` | string | Endpoint IP |
| `src_port`, `dst_port` | int/null | Port nếu có |
| `transport` | string | TCP/UDP/other |
| `packet_length` | int | Theo một quy ước length thống nhất |
| `tcp_flags` | int/null | TCP flags nếu có |

Không làm parser crash khi packet không có TCP/UDP layer. Không trộn captured length với wire length.

## 2. FlowRecord và direction
Flow identity dựa trên protocol và endpoint tuple không phân biệt chiều. `flow_id` duy nhất trong session; tuple reuse sau khi Flow kết thúc tạo Flow ID mới.

Fields logic: `session_id`, `flow_id`, `protocol`, `client_ip/client_port`, `server_ip/server_port`, `start_ts`, `last_seen_ts`, ordered packet list, `status`.

Direction enum:
- `FORWARD`: client → server
- `BACKWARD`: server → client
- `UNKNOWN`: chưa đủ căn cứ xác định endpoint role

Không mặc định source port là client port. Server-first capture cần được xử lý rõ ràng.

## 3. DNSObservation / DNS Cache / DNS Identifier

### 3.1 DNSObservation

Producer: DNS Parser. Consumer: DNS Cache.

Fields logic:
- `session_id`, `observed_at`, `packet_index`.
- `client_ip` (nullable only when client cannot be established; unscoped observations cannot identify a client Flow).
- `transaction_id`, `transport`, query/response endpoint tuple for correlation when available.
- `query_name`, `query_type`, `response_code`, `is_response`.
- `answer_records[]`: `owner_name`, `record_type` (`A`, `AAAA`, `CNAME`, other), `value`, `ttl_seconds`.

Only successful DNS Response with usable answer chain may create positive mapping. Query may be held for correlation but never creates Domain↔IP mapping.

### 3.2 DNS Cache Binding

A binding preserves `session_id`, `client_ip`, original `queried_domain`, `resolved_ip`, `cname_chain[]`, source record metadata, `observed_at`, and `expires_at`. Multiple domains per IP and multiple IPs per domain are supported. Cache lookup is scoped by client and destination IP; IP alone is never a cache identity.

For direct A/AAAA, expiry follows that address record TTL. For CNAME-derived binding, expiry is the minimum expiry among every CNAME link and the terminal A/AAAA record. TTL=0 is not cached; expired records are not returned. PCAP replay evaluates expiry using capture timestamps for determinism.

### 3.3 Application Domain Rules

Rules map verified normalized domains to `application_id`, with exact or DNS-label-boundary suffix matching. Exact match wins over suffix; longest/more-specific suffix wins. Same-precedence conflicting rules are ambiguous. Matching is not substring matching. QNAME and CNAME names are preserved as separate evidence candidates; a generic CDN CNAME does not imply an Application unless explicitly present in verified rules.

### 3.4 DNS Identifier

Input: `session_id`, `flow_id`, `client_ip`, `destination_ip`, `flow_timestamp`.

Intermediate DNS decision output: `status` (`DNS_IDENTIFIED` / `DNS_UNRESOLVED`), optional `application_id`, `method=dns` when identified, `reason_code`, evidence candidates/rule IDs/expiry; `confidence` may be null for rule-based results. Runtime Orchestrator converts `DNS_IDENTIFIED` into the shared final `IdentificationResult` (`status=CLASSIFIED`, `method=DNS`); the intermediate DNS status is not a replacement for the shared final result enum.

Decision contract:
1. Client endpoint must be known; `UNKNOWN` client means DNS unresolved.
2. Lookup all unexpired bindings for `(client_ip, destination_ip)` at the Flow evaluation timestamp and correct session scope.
3. Match every candidate domain against verified Application Domain Rules.
4. No valid app candidate → unresolved.
5. All valid candidates resolve to exactly one distinct Application ID → identified, even if several domains matched.
6. Candidates resolve to multiple Application IDs → unresolved (`DNS_SHARED_IP_AMBIGUOUS`). Never choose by newest observation, largest TTL, or packet count.

DNS Cache updates continuously. At the Flow's first DNS evaluation when it meets runtime observation requirements, an eligible mapping may identify immediately; there is no DNS-specific packet-N threshold. An identified Application/evidence snapshot is bound to the Flow and reused by later packets. TTL expiry prevents reuse for new Flow decisions but does not retroactively erase an already identified Flow result.

DNS Parser, Cache and Identifier do not invoke SNI or ML. Runtime Orchestrator owns DNS → SNI → Burst ML precedence.

## 4. SNIObservation / SNI Mapping
SNIObservation giữ `session_id`, `flow_id`, `timestamp`, normalized `server_name`, `parser_status`, `evidence_packet_indexes`.

SNI lấy từ TLS ClientHello khi quan sát được. Không có SNI, ECH hoặc ClientHello không parse được thì unresolved; không suy diễn hostname. SNI Mapper output cùng logical shape với DNS Identifier.

## 5. ReconstructedFlow
Input là packet records của một Flow. Output giữ `session_id`, `flow_id`, ordered packet list, direction, timestamp, packet index, packet length, `ordering_status`, `data_quality_flags`.

Ordering deterministic; timestamp bằng nhau thì tie-break bằng packet index. Không trộn packet của Flow khác.

## 6. Burst
Burst giữ `session_id`, `flow_id`, `burst_index`, `start_ts`, `end_ts`, `duration`, direction/direction composition theo schema, `packet_count`, `total_bytes`, ordered packet metadata và `inter_burst_gap` nếu được định nghĩa.

Boundary phải lấy từ config. Numeric idle-gap và rule direction-change hiện chưa được xác định; không hard-code trước khi chốt.

## 7. Branch A — Burst Statistics → CatBoost
Input là feature vector cấp Flow được tổng hợp từ Burst list theo schema version. Output giữ `class_names` (ordered), `scores`, `model_version`, `feature_schema_version`, `session_id`, `flow_id`. Feature names/order phải được khóa trong artifact metadata.

## 8. Branch B — Burst Sequence → PyTorch 1D-CNN
Input là tensor encode từ cùng Burst observation với Branch A. Batch dimension được giữ trong model API. Channel/sequence dimensions phải được chốt trước training.

Output giữ `class_names` (cùng order với CatBoost), `scores`, `model_version`, `sequence_schema_version`, `session_id`, `flow_id`. Inference dùng `model.eval()` và inference mode. Preprocessing runtime phải reuse fitted parameters từ training artifact; không fit scaler trên live traffic.

## 9. Late Fusion / Stacking
Input là scores của CatBoost và CNN cùng class mapping/version metadata. Preconditions: class order giống nhau, scores cùng `session_id`/`flow_id`, schema/model tương thích.

Output là fused scores, candidate class, fusion version và branch availability/conflict information. Chưa quyết định weighted average, voting hay meta-learner; không tự chọn trước khi fusion design được chốt.

## 10. Final IdentificationResult
Logical output:

```json
{
  "session_id": "session-id",
  "flow_id": "flow-id",
  "status": "CLASSIFIED",
  "application": "application-name",
  "method": "dns",
  "confidence": null,
  "reason_code": "DNS_MAPPING_MATCH",
  "evidence": [],
  "model_versions": {}
}
```

`method` dự kiến: `dns`, `sni`, `burst_fusion`. `status` tối thiểu phân biệt `CLASSIFIED` và `UNKNOWN`. Confidence có thể null nếu rule-based path không cung cấp xác suất. Schema serialize cụ thể sẽ được chọn khi tạo source.

## 11. Orchestration contract

```python
def identify_flow(flow):
    dns_result = dns_identifier.identify(flow)
    if dns_result.is_identified:
        return final_result_from_dns(dns_result)

    sni_result = sni_identifier.identify(flow)
    if sni_result.is_identified:
        return final_result_from_sni(sni_result)

    reconstructed = reconstruct_bidirectional(flow)
    bursts = segment_bursts(reconstructed)
    stats = build_burst_statistics(bursts)
    sequence = encode_burst_sequence(bursts)
    catboost_scores = catboost.predict_scores(stats)
    cnn_scores = cnn.predict_scores(sequence)
    fused_scores = fusion.combine(catboost_scores, cnn_scores)
    return application_classifier.classify(fused_scores)
```

Đây là pseudocode thể hiện thứ tự và module boundary, không phải implementation hoàn chỉnh.

## 12. Invariants bắt buộc test
- DNS identified → SNI và ML không được gọi.
- DNS unresolved + SNI identified → ML không được gọi.
- DNS/SNI unresolved → ML được gọi.
- Hai branch ML nhận cùng `session_id`/`flow_id`.
- CatBoost và CNN dùng cùng class order.
- Fusion từ chối scores sai class order hoặc sai Flow.
- Mọi output truy vết được và có reason code.


## 13. P0.5 DNS source contract (implemented)

- `DNSParser.parse(raw_packet, session_id, packet_index, lan_networks) -> DNSObservation | None`; query messages update only temporary correlation state, never positive cache.
- `DNSCache.update(observation) -> int`; returns number of positive bindings created. `lookup(session_id, client_ip, destination_ip, timestamp)` returns only unexpired candidates for that session/client/IP.
- `ApplicationDomainRules.match(domain)` returns the highest-priority exact/most-specific suffix rules.
- `DNSApplicationIdentifier.identify(...)` returns `DNS_IDENTIFIED` only for exactly one distinct Application ID; otherwise returns `DNS_UNRESOLVED` with a reason code.
- `PacketProcessor` performs DNS parsing on the original packet after LAN filtering and before metadata-only Flow processing; it does not retain raw DNS payload.
- `FlowState.identification_result` stores the immutable logical DNS result snapshot after early exit.

## 10. QUIC v1 Initial Inspector (P0.7.3; integrated in P0.7.4)

**Producer:** UDP datagram inspection. **Consumer:** current shared
`PacketProcessor` through `UDPAnalyzer`; it is no longer standalone.

Input: one QUIC v1 UDP datagram plus optional `original_dcid` connection
context. The first successfully authenticated client Initial establishes the
Original DCID. A server Initial observed first requires the caller to supply
that Original DCID.

Output `QUICInitialResult`:

- `status`: `DECRYPTED` or `REJECTED`.
- `version`, `sender_role`, `packet_number`, `dcid`, `scid`.
- `frame_types`, `reason_code`.
- `sni`: visible ClientHello SNI only after successful Initial AEAD validation.
- `ech_detected`: indicates ECH extension; does not recover inner hostname.

State is scoped to one `QUICInitialConnection`: sender-specific largest packet
number and bounded CRYPTO offset streams. The caller must not share one
connection object across unrelated QUIC connections. UDP Flow/CID migration
tracking and PacketProcessor integration are not part of P0.7.3.


## 11. P0.7.4 Hybrid UDP / QUIC integration contract

`PacketProcessor` is the shared entrypoint for live NIC and PCAP. After
normalization and LAN filtering, TCP packets retain the TCP reassembly/SNI path;
UDP packets are tracked in the same Flow ID namespace and passed to
`UDPAnalyzer` when UDP analysis is enabled.

`UDPAnalyzer.analyze(payload, src_port, dst_port, flow_id, timestamp)` first
returns a structural `UDPProtocol` label. Only `QUIC_INITIAL_CANDIDATE` is
passed to `QUICConnectionTracker`; only authenticated Initial packets can
create or update QUIC Connection/CID state. The connection tracker returns a
separate QUIC connection ID and a set of linked UDP Flow IDs.

`EvidenceEngine.apply_sni(flow, hostname, application, source, rule_ids)`
sets an SNI result only when the Flow has no prior identification result. DNS
is evaluated first and causes early exit; QUIC SNI is reached only for DNS-
unresolved UDP Flows. Unmapped hostnames do not create an AppID. `FlowState.transport`
remains TCP/UDP while `FlowState.application_protocol` may report
`QUIC_INITIAL`; this does not claim completed HTTP/3.

UDP Flow idle timeout/capacity and QUIC connection idle timeout/capacity are
independent. See `docs/architecture/p0.7.4-hybrid-tcp-udp-pipeline.md` for
defaults, counters and protocol limitations.

## ML Candidate and Reconstruction contract (design target)

**ML Candidate Selection**
- Input: final DNS and SNI decisions plus existing Flow identity.
- Eligible only when DNS and SNI are both unresolved.
- Output state: `ELIGIBLE`, `PENDING`, or `REJECTED`, with a reason code.
- This gate does not invoke CatBoost, 1D-CNN, or fusion.
- Minimum observation policy remains OPEN.

**MLFlowObservation / ReconstructedFlow**
- Preserve `session_id`, existing `flow_id`, protocol, ordered packet metadata, direction, timestamp, packet index, packet length, direction coverage, and data-quality flags.
- Deterministic ordering uses `(timestamp, packet_index)`.
- Reuse FlowTracker identity and direction semantics; never create a second Flow ID or regroup the 5-tuple.
- Do not include/decode encrypted application payload or duplicate TCP reassembly.
- Duplicate handling and missing-timestamp admission policy remain OPEN.

Both model branches derive from the same observation and Burst lineage: `session_id → flow_id → burst_index`.


### P1.1 implementation contract

- `BidirectionalFlowReconstructor.reconstruct(flow)` delegates to the existing `FlowObservationAdapter`; it preserves `session_id`, `flow_id`, packet order, direction and payload-free metadata. It never allocates a Flow ID or reparses PCAP.
- `BurstSegmenter.segment(observation, policy)` returns immutable Burst records ordered by `burst_index`, preserving `session_id → flow_id → burst_index`.
- A direction transition always starts a new Burst. `UNKNOWN` is treated as its own direction run and is never merged with FORWARD/BACKWARD.
- `BurstSegmentationPolicy.idle_gap_seconds` is explicit and optional. `None` disables idle-gap splitting; a positive configured threshold splits only when `gap > threshold`. No numeric default is selected.
- Burst records include ordered packet metadata, `start_ts`, `end_ts`, `duration_seconds`, `packet_count`, `total_bytes`, direction and `inter_burst_gap_seconds` (None for the first Burst).
- Minimum packet count, maximum Burst count, CatBoost features, CNN tensor layout and model inference remain outside P1.1.

### P1.0 implementation contract

The source module is `appid.ml.candidate_gate`.

- `MLCandidateGate.evaluate(flow, policy=None) -> CandidateDecision` consumes the existing `FlowState`; it never creates or changes a Flow ID.
- `CandidateDecision.state` is `ELIGIBLE`, `PENDING`, or `REJECTED`; `reason` is a stable `CandidateReason` code.
- A classified DNS/SNI result is rejected from ML admission (`RULE_BASED_IDENTIFICATION_PRESENT`).
- Missing policy remains `PENDING / OBSERVATION_POLICY_UNCONFIGURED`. No minimum packet or duration default is assumed while the project parameter is OPEN.
- `FlowObservationPolicy` requires explicit `min_packets` and `min_duration_seconds` from the caller.
- `FlowObservationAdapter.adapt(flow)` creates a frozen, payload-free snapshot. Packet ordering is `(timestamp, packet_index)`; packet direction is copied from FlowTracker without re-inference.
- One-way observations are retained and flagged; they are not silently discarded.
- Duplicate packet indexes remain `PENDING / DUPLICATE_PACKET_INDEX_POLICY_UNRESOLVED`; no deduplication policy is assumed.
- Invalid identity, timestamp, endpoint or packet metadata is rejected as `INVALID_PACKET_METADATA`.
- The adapter does not perform TCP reassembly, payload inspection, Burst segmentation or model inference.

`PacketProcessor.evaluate_ml_candidate(flow, policy=...)` exposes the gate after the shared DNS/SNI processing path. The caller must supply an explicit observation policy before a Flow can become `ELIGIBLE`.

Both model branches will later derive from the same observation and Burst lineage: `session_id → flow_id → burst_index`.
