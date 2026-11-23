# 13 — Module Contracts

> Contract logic cho source implementation mới. Tên field dùng snake_case. Mọi record capture giữ `session_id`; mọi record thuộc connection giữ `flow_id`.

## 1. PacketRecord
**Producer:** Capture + Packet Parser. **Consumer:** Flow Tracker, DNS/TLS parser.

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

## 3. DNSObservation / DNS Cache
DNSObservation giữ `session_id`, `timestamp`, `client_ip` nếu có, `query_name`, `query_type`, `response_code`, answer records (type/value/TTL), `is_response`.

Cache phải hỗ trợ expiry theo TTL và client scope khi có thể. CNAME chain phải được giữ hoặc resolve theo policy. Shared IP không phải bằng chứng đủ để xác định app; ambiguous mapping phải trả unresolved.

DNS Identifier output logic: `status` (IDENTIFIED/UNRESOLVED), `application`, `evidence`, `reason_code`, optional `confidence`.

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
