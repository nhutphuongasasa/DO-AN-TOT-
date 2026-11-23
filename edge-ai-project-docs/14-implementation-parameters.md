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
| Minimum observation / prediction timing | OPEN | Chưa có ngưỡng packet/time |

## 2. Flow
| Parameter | Status | Contract |
|---|---|---|
| Flow identity | FIXED | Protocol + endpoint tuple, normalize hai chiều |
| Flow ID scope | FIXED | Unique trong session |
| Direction | FIXED | FORWARD/BACKWARD/UNKNOWN |
| Equal timestamp ordering | FIXED | Deterministic tie-break bằng packet index |
| TCP/UDP idle timeout | OPEN | Chưa có giá trị |
| Client/server role resolution | OPEN | Cần policy cho server-first/ambiguous capture |
| Tuple reuse | FIXED | Flow ID mới |

## 3. DNS và SNI
| Parameter | Status | Contract |
|---|---|---|
| DNS TTL expiry | FIXED | Tuân theo record TTL |
| DNS client scope | FIXED | Giữ client scope khi có thể |
| CNAME handling | CONFIGURABLE | Policy phải thống nhất |
| Shared IP | FIXED | Không dùng IP đơn lẻ để kết luận app |
| DNS ambiguity policy | FIXED | Ambiguous → unresolved |
| DNS mapping confidence | OPEN | Chưa có policy |
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
| Idle-gap threshold | OPEN | Chưa có numeric value |
| Split on direction change | OPEN | Chưa xác định |
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
