# 01 — Kiến trúc hệ thống

## 1. Flow runtime chuẩn

Thứ tự dưới đây là chuẩn kiến trúc. Không hoán đổi DNS và SNI.

```text
1. Network Packet Capture
   Live interface hoặc PCAP
             |
             v
2. Packet Parsing & Flow Tracking
   Headers, timestamp, direction, 5-tuple / Flow ID, packet sequence
             |
             v
3. DNS Parser + DNS Cache
   Parse DNS Response; lưu Domain-IP-Client-TTL
             |
             v
4. DNS-based Application Identification — FIRST
       | DNS_IDENTIFIED            | DNS_UNRESOLVED
       v                           v
   Return Application       5. TLS Parser + SNI Mapping — SECOND
   Stop; skip ML                   | SNI_IDENTIFIED       | SNI_UNRESOLVED
                                   v                      v
                              Return Application    6. Burst-based ML
                                                     Classification
                                                            |
                                                            v
                                              7. Bidirectional Flow
                                                 Reconstruction
                                                            |
                                                            v
                                              8. Burst Segmentation
                                                   /          \
                                                  v            v
                                      Branch A: Statistics  Branch B: Sequence
                                           CatBoost              1D-CNN
                                                  \            /
                                                   v          v
                                              9. Late Fusion /
                                                 Stacking
                                                     |
                                                     v
                                         10. Application Classification
                                           Application label / UNKNOWN
```

**Diễn giải đánh số:** khối 6 là nhánh ML trong flow tổng thể. Các khối 7–9 là các công đoạn bên trong nhánh ML để chuẩn bị dữ liệu, chạy hai classifier và hợp nhất kết quả. Sơ đồ không có nhánh ML chạy song song với DNS/SNI.

## 2. Bảng chuyển trạng thái

| Giai đoạn | Điều kiện | Hành động tiếp theo |
|---|---|---|
| DNS identification | Mapping hợp lệ, domain đã xác minh, không ambiguous | `DNS_IDENTIFIED`; trả Application; dừng |
| DNS identification | Không có evidence hoặc evidence ambiguous | `DNS_UNRESOLVED`; gọi TLS/SNI |
| SNI identification | SNI hợp lệ và mapping đã xác minh | `SNI_IDENTIFIED`; trả Application; dừng |
| SNI identification | Không có SNI hoặc mapping chưa xác minh | `SNI_UNRESOLVED`; gọi Burst ML |
| Burst ML | Đủ packet sequence và feature hợp lệ | Reconstruction → Segmentation → hai model |
| Application classification | Fusion đủ độ tin cậy | Trả application label |
| Application classification | Thiếu dữ liệu, model lỗi hoặc confidence dưới threshold | Trả `UNKNOWN` |

## 3. Module và trách nhiệm

| Module | Trách nhiệm | Không làm |
|---|---|---|
| Packet Capture | Cung cấp packet và timestamp | Không nhận diện app |
| Packet Parser | Parse header/protocol | Không quyết định app |
| Flow Tracker | Gom packet, xác định direction và Flow ID | Không chạy classifier |
| DNS Parser/Cache | Tạo DNS observation còn TTL | Không tự kết luận nếu mapping ambiguous |
| DNS Identifier | Map DNS evidence sang application | Không gọi ML |
| TLS/SNI Parser | Trích xuất ClientHello/SNI | Không tự map app nếu chưa qua mapping rules |
| SNI Identifier | Map SNI sang application | Không gọi ML |
| Bidirectional Reconstruction | Tạo chuỗi packet hai chiều theo Flow | Không thay đổi packet payload |
| Burst Segmenter | Chia packet sequence thành Burst | Không dự đoán app |
| CatBoost Branch | Dự đoán từ Burst Statistics | Không xử lý PCAP trực tiếp |
| 1D-CNN Branch | Dự đoán từ Burst Sequence | Không xử lý PCAP trực tiếp |
| Late Fusion | Hợp nhất output hai nhánh | Không tự tạo feature |
| Application Classifier | Áp dụng threshold/reject policy và trả kết quả | Không thay đổi evidence gốc |

## 4. Offline và runtime

Offline preparation tạo dataset và model artifacts. Runtime nhận packet, áp dụng cùng feature contract và nạp model artifacts đã huấn luyện. Dataset builder và runtime phải dùng cùng định nghĩa Flow/Burst/features.

## 5. Quy tắc nghiệp vụ

- BR-01: DNS luôn được đánh giá trước SNI.
- BR-02: SNI chỉ được đánh giá sau DNS unresolved.
- BR-03: ML chỉ nhận Flow unresolved sau cả DNS và SNI.
- BR-04: DNS/SNI identified kết thúc đường nhận diện của Flow.
- BR-05: Hai ML branch nhận dữ liệu được tạo từ cùng Flow/Burst observation.
- BR-06: Late Fusion chỉ chạy khi output của các branch đáp ứng input contract.
- BR-07: Kết quả cuối có thể là `UNKNOWN`.

## 6. Open decisions

Các thông số sau chưa được xác định trong sơ đồ và không được tự đặt:
- DNS/SNI confidence hoặc điều kiện mapping cụ thể ngoài tài liệu DNS.
- Burst idle-gap threshold và cách xử lý đổi direction.
- Chiều dài sequence, padding/truncation và tensor shape cho 1D-CNN.
- CatBoost feature schema chính thức.
- Fusion algorithm, calibration và threshold.
- Thời điểm phát prediction: sau N packet, T giây hay khi Flow đóng.

## 7. Tiêu chí nghiệm thu

- [ ] Test chứng minh DNS được gọi trước SNI.
- [ ] Test chứng minh DNS identified không gọi SNI/ML.
- [ ] Test chứng minh SNI identified không gọi ML.
- [ ] Test unresolved cả hai mới gọi Burst ML.
- [ ] Test hai nhánh và fusion có thể truy vết theo cùng Flow ID.
- [ ] Test trả `UNKNOWN` khi thiếu input hoặc confidence không đạt.
