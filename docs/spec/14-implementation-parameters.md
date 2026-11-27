# 14 — Implementation Parameters

> Không biến giá trị minh họa thành mặc định chính thức. `FIXED` = kiến trúc bắt buộc; `CONFIGURABLE` = đọc từ config; `OPEN` = cần quyết định/thực nghiệm trước khi implement phần phụ thuộc.

## 1. Runtime
| Parameter | Status | Contract |
|---|---|---|
| Identification order | FIXED | DNS → SNI → Burst ML |
| DNS/SNI early exit | FIXED | Identified thì kết thúc identification |
| ML branches | FIXED | CatBoost + 1D-CNN trên cùng Flow observation |
| Fusion position | FIXED | Sau hai model outputs |
| Unknown state | FIXED | Có UNKNOWN |
| Minimum observation / prediction timing | OPEN | Chưa có ngưỡng packet/time; `FlowObservationPolicy` phải được caller truyền rõ ràng, thiếu policy thì Candidate Gate trả `PENDING` |

## 2. Flow
| Parameter | Status | Contract |
|---|---|---|
| Flow identity | FIXED | Protocol + endpoint tuple, normalize hai chiều |
| Flow ID scope | FIXED | Unique trong session |
| Direction | FIXED | FORWARD/BACKWARD/UNKNOWN |
| Equal timestamp ordering | FIXED | Deterministic tie-break bằng packet index |
| TCP/UDP idle timeout | OPEN | Chưa có giá trị |
| Client/server role resolution | FIXED (P0.3) | Auto-discover active-interface LAN subnets; client is the sole endpoint inside discovered LAN; ambiguous/no match → UNKNOWN |
| Tuple reuse | FIXED | Flow ID mới |

## 3. DNS và SNI
| Parameter | Status | Contract |
|---|---|---|
| DNS TTL expiry | FIXED | Record expiry = observed time + record TTL; TTL=0 không cache; CNAME binding dùng minimum expiry của chain + terminal A/AAAA |
| DNS client scope | FIXED | Cache lookup theo client IP + destination IP; unknown client không đủ điều kiện DNS identify |
| DNS records | FIXED | Parse A, AAAA, CNAME; chỉ successful response có answer chain hợp lệ tạo positive mapping |
| CNAME policy | FIXED | Giữ QNAME gốc và chain; mỗi tên match rules độc lập; không suy app từ CDN target không có rule |
| Domain normalization | FIXED | Lowercase, bỏ trailing dot, IDN/Punycode canonicalization; không substring match |
| Domain rule matching | FIXED | Exact ưu tiên; suffix match theo DNS label boundary, longest/more-specific wins; same-precedence conflict ambiguous |
| Shared IP | FIXED | Lưu nhiều domain candidate; không dùng IP đơn lẻ để kết luận app |
| DNS ambiguity policy | FIXED | Nhiều candidate cùng một Application → identified; nhiều Application → unresolved |
| DNS flow binding | FIXED | DNS identified gắn Application/evidence snapshot vào Flow; packet tiếp theo reuse |
| DNS packet-N threshold | FIXED | Không có ngưỡng N riêng; kết luận ở lần DNS evaluation đầu tiên đủ metadata/evidence |
| DNS mapping confidence | FIXED | Rule-based DNS không tự tạo xác suất; confidence có thể null; evidence + reason code bắt buộc |
| DNS query correlation retention | OPEN | Cần chốt thời gian giữ pending query cho response correlation; không thay TTL của DNS answer records |
| SNI source | FIXED | TLS ClientHello |
| Hostname normalization | CONFIGURABLE | Quy tắc phải thống nhất |
| ECH/no SNI | FIXED | Unresolved |
| SNI domain mapping rules | OPEN | Cần mapping/ambiguity policy |

## 4. Burst
| Parameter | Status | Contract |
|---|---|---|
| Input | FIXED | Reconstructed bidirectional Flow |
| Grouping scope | FIXED | Không trộn Flow |
| Packet ordering | FIXED | Deterministic chronological order |
| Idle-gap threshold | CONFIGURABLE / OPEN | Caller phải truyền ngưỡng dương; chưa chọn numeric default. `None` nghĩa là tắt idle-gap boundary. |
| Split on direction change | FIXED | Mỗi lần direction thay đổi (FORWARD/BACKWARD/UNKNOWN) bắt đầu Burst mới. |
| Minimum packets / maximum bursts | OPEN | Chưa chỉ định |
| One-direction Flow | FIXED | Giữ và biểu diễn thiếu direction |

## 5. CatBoost
| Parameter | Status | Contract |
|---|---|---|
| Input | FIXED | Burst Statistics |
| Feature list/order/formulas | OPEN | Khóa thành schema version |
| Missing value policy | OPEN | Cần quyết định |
| Objective / depth / learning rate / iterations | OPEN | Tune trên validation |
| Class weights | OPEN | Dựa trên dataset/validation |
| Output | FIXED | Scores gắn ordered class names |

## 6. PyTorch 1D-CNN
| Parameter | Status | Contract |
|---|---|---|
| Framework | FIXED | PyTorch |
| Model family | FIXED | 1D-CNN |
| Input semantic | FIXED | Burst Sequence |
| Tensor layout | OPEN | Chưa chốt N×C×L hay layout khác |
| Sequence length | OPEN | Chưa có giá trị |
| Feature/channel order | OPEN | Cần khóa |
| Padding/truncation | OPEN | Chưa xác định |
| Normalization | OPEN | Fit trên train, reuse runtime |
| Layers/channels/kernel | OPEN | Tune trên validation |
| Optimizer/learning rate/batch/epochs | OPEN | Chọn qua thí nghiệm |
| Inference mode | FIXED | `model.eval()` + inference mode |

## 7. Fusion và final classifier
| Parameter | Status | Contract |
|---|---|---|
| Fusion inputs | FIXED | CatBoost + 1D-CNN scores |
| Class order | FIXED | Hai branch phải giống nhau |
| Fusion algorithm | OPEN | Chưa chọn average/voting/meta-learner |
| Calibration | OPEN | Cần đánh giá |
| Missing branch policy | OPEN | Không giả vờ có đủ outputs |
| Confidence threshold | OPEN | Chọn trên validation |
| Insufficient data | FIXED | UNKNOWN/insufficient-data |
| Missing artifact | FIXED | Không trả classification thành công giả |
| Reason code | FIXED | Mọi kết quả cần lý do/evidence |

## 8. Config layout gợi ý

```yaml
runtime:
  identification_order: [dns, sni, burst_ml]

flow:
  tcp_idle_timeout_seconds: null
  udp_idle_timeout_seconds: null

dns:
  cache:
    respect_record_ttl: true
    client_scoped: true
    cache_zero_ttl: false
    cname_expiry: minimum_chain_ttl
  domain_rules:
    matching: exact_then_longest_suffix
    normalize: lowercase_strip_trailing_dot_idna_ascii
    substring_matching: false
  identification:
    shared_ip_same_application: identified
    shared_ip_multiple_applications: unresolved
    bind_result_to_flow: true

burst:
  idle_gap_seconds: null
  split_on_direction_change: null

models:
  catboost:
    feature_schema_version: null
  cnn_1d:
    framework: pytorch
    sequence_length: null
    tensor_layout: null
  fusion:
    algorithm: null

classifier:
  confidence_threshold: null
  unknown_label: UNKNOWN
```

`null` có nghĩa là chưa chốt. Config loader cần báo lỗi nếu tham số bắt buộc vẫn null; không tự chọn giá trị mặc định ngầm.

## 9. Thứ tự chốt
1. Flow endpoint role/direction/timeouts.
2. DNS ambiguity và SNI mapping.
3. Burst boundary.
4. CatBoost feature schema.
5. CNN sequence fields, tensor layout, length, padding/truncation/normalization.
6. Model hyperparameters.
7. Fusion algorithm.
8. Calibration và UNKNOWN threshold.
9. Khóa schema/config version rồi mới chạy test holdout.

## 10. Không được tự ý
- Không đổi DNS → SNI → ML thành chạy song song.
- Không chạy ML khi DNS hoặc SNI đã identified.
- Không thay CatBoost/1D-CNN bằng model khác.
- Không tự điền các mục OPEN.
- Không tune trên test set.
- Không để preprocessing training khác runtime.

## 11. QUIC v1 Initial (P0.7.3)

| Parameter | Status | Contract |
|---|---|---|
| Supported QUIC version | FIXED | v1 only (`0x00000001`); reject other versions |
| Initial key derivation | FIXED | RFC 9001 Initial salt + HKDF-SHA256 using Original DCID |
| Header protection | FIXED | AES-128-ECB mask from 16-byte sample at `pn_offset + 4` |
| Packet protection | FIXED | AES-128-GCM; authenticate unprotected header as AAD |
| Packet number | FIXED | Reconstruct truncated PN using sender-specific largest received |
| Initial frames | FIXED | PADDING, PING, ACK, ACK_ECN, CRYPTO, CONNECTION_CLOSE, APPLICATION_CLOSE |
| CRYPTO reassembly | FIXED | Per sender, offset-based, reject conflicting overlap |
| CRYPTO memory | FIXED | Default 1 MiB per sender and maximum 4096 stored segments |
| Server Initial first observed | FIXED | Requires externally supplied Original DCID; never infer from packet DCID |
| ECH | FIXED | Detect extension; do not claim/recover inner ClientHello hostname |
| QUIC v2 / 0-RTT / 1-RTT | OUT OF SCOPE | Not parsed/decrypted in P0.7.3 |
| UDP live/PCAP integration | IMPLEMENTED / LIVE ACCEPTANCE OPEN | Shared PacketProcessor; see P0.7.4 release evidence |


## 12. P0.7.4 UDP / QUIC runtime parameters

| Parameter | Default | Scope |
|---|---:|---|
| `enable_udp_analysis` | `True` | PacketProcessor; disable UDP protocol analysis but keep UDP Flow tracking and DNS parsing |
| `enable_quic_analysis` | `True` | PacketProcessor/UDPAnalyzer; disable QUIC decryption but keep UDP protocol identification |
| `udp_idle_timeout` | 60 seconds | UDP pseudo-Flow idle expiry |
| `max_active_udp_flows` | 10,000 | Maximum active UDP pseudo-Flows; oldest active UDP Flow is evicted at capacity |
| QUIC `max_connections` | 4,096 | Maximum active QUIC Initial connection states |
| QUIC `idle_timeout` | 120 seconds | QUIC connection/CID alias expiry |
| QUIC `max_crypto_bytes` | 1 MiB | Per-connection CRYPTO stream memory bound |
| QUIC `max_cids_per_connection` | 8 | Initial-observed CID aliases per connection |

These values are constructor defaults in the current source; they are not yet
loaded from a user-editable JSON configuration file.

## ML candidate and reconstruction parameters

| Parameter | Status | Decision / value |
|---|---|---|
| Candidate eligibility | FIXED | DNS unresolved AND SNI unresolved |
| Candidate gate vs inference | FIXED | Candidate selection is admission only; no model call |
| Flow identity | FIXED | Reuse existing `session_id` and `flow_id` from FlowTracker |
| Direction semantics | FIXED | Preserve client-relative `FORWARD` / `BACKWARD` / `UNKNOWN` |
| Packet ordering | FIXED | Deterministic `(timestamp, packet_index)` ordering |
| Minimum packets / observation duration | OPEN | Must be designed and validated; no guessed threshold |
| Flow-close / pending policy | OPEN | Define wait, pending, or reject behavior |
| Duplicate packet handling in ML | OPEN | Source metadata preserved; ML policy TBD |
| Missing/invalid timestamp admission | OPEN | Define reject/quality-flag policy |
| Burst idle-gap threshold | OPEN / CONFIGURABLE | Chọn bằng thí nghiệm trên training/validation data; không hard-code default. |
| Direction-change Burst boundary | FIXED | Split khi direction thay đổi; UNKNOWN là một direction riêng, không gộp vào FORWARD/BACKWARD. |
| Minimum/maximum Burst count | OPEN | To be decided with model input design |
