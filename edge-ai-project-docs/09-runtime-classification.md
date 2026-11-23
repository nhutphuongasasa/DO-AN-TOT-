# 09 — Runtime Application Classification

## 1. Mục đích

Điều phối quyết định cuối cùng theo thứ tự DNS → SNI → Burst-based ML và trả application label hoặc `UNKNOWN`.

## 2. Phạm vi

**Làm**
- Quản lý state nhận diện của Flow.
- Gọi DNS Identifier trước.
- Gọi SNI Identifier khi DNS unresolved.
- Gọi Burst ML khi SNI unresolved.
- Lưu method, evidence, confidence và lý do unknown.

**Không làm**
- Không gọi ML trước DNS/SNI.
- Không ghi đè kết quả rule bằng ML sau khi đã identified.
- Không ép application khi confidence/evidence không đạt.

## 3. Phụ thuộc

- DNS Parser/Cache/Identifier.
- TLS Parser và SNI Mapping.
- Flow Tracker, Burst pipeline, CatBoost, 1D-CNN và Fusion.
- Output/logging module.

## 4. Luồng xử lý

1. Nhận Flow đủ metadata để đánh giá.
2. Gọi DNS-based Application Identification.
3. Nếu DNS identified: trả application, source `dns`, dừng.
4. Nếu DNS unresolved: gọi TLS Parser/SNI Mapping.
5. Nếu SNI identified: trả application, source `sni`, dừng.
6. Nếu SNI unresolved: gửi Flow vào Burst ML.
7. Reconstruction và segmentation tạo hai loại input.
8. CatBoost và 1D-CNN inference.
9. Late Fusion / Stacking hợp nhất output.
10. Application Classifier áp dụng threshold/reject policy.
11. Trả application hoặc `UNKNOWN`.

## 5. Input / Output

**Input**
- `flow_id`
- Flow metadata và packet sequence
- DNS result
- SNI result
- Model outputs khi ML được gọi

**Output logic**

```json
{
  "flow_id": "flow_001",
  "application": "youtube",
  "status": "CLASSIFIED",
  "method": "burst_fusion",
  "confidence": 0.91,
  "evidence": []
}
```

Ví dụ schema minh họa; output contract thực tế cần được khóa trong implementation. `confidence` chỉ xuất khi model/policy cung cấp giá trị có ý nghĩa.

## 6. Quy tắc nghiệp vụ

- BR-01: DNS là tầng identification đầu tiên.
- BR-02: DNS identified trả kết quả ngay và không gọi SNI/ML.
- BR-03: DNS unresolved mới gọi SNI.
- BR-04: SNI identified trả kết quả ngay và không gọi ML.
- BR-05: SNI unresolved mới gọi Burst ML.
- BR-06: ML prediction dùng kết quả Late Fusion / Stacking.
- BR-07: Confidence dưới threshold trả `UNKNOWN`.
- BR-08: Thiếu model, feature hoặc evidence không được giả thành classification thành công.
- BR-09: Mỗi output lưu method và evidence source.
- BR-10: Không gộp device-level app list thành một nhãn duy nhất nếu thiết bị có nhiều app đồng thời.

## 7. Lỗi và trường hợp biên

| Tình huống | Hành vi |
|---|---|
| DNS parser/cache unavailable | DNS unresolved; tiếp tục SNI |
| SNI không có/ECH | SNI unresolved; tiếp tục ML |
| ML input chưa đủ | UNKNOWN/insufficient-data |
| Một model không load | Không chạy fusion đủ hai nhánh; theo policy đã cấu hình hoặc UNKNOWN |
| Hai nhánh conflict | Ghi conflict và áp dụng fusion policy |
| Confidence thấp | UNKNOWN |
| Flow chưa đóng nhưng cần dự đoán | Chỉ dự đoán khi observation criteria đã được định nghĩa |

## 8. File/hàm chính

- `rules.yaml`: rule configuration hiện có; kiểm tra thứ tự/domain mapping thực tế.
- `ml/predictor.py`: predictor có trong snapshot; xác minh model type và API hiện tại.
- Runtime orchestrator: chưa xác định path trong snapshot; tìm call graph thực tế trước khi thêm.

## 9. Tiêu chí nghiệm thu

- [ ] DNS identified không gọi SNI và ML.
- [ ] DNS unresolved gọi SNI.
- [ ] SNI identified không gọi ML.
- [ ] DNS + SNI unresolved mới gọi ML.
- [ ] ML result đến từ Late Fusion / Stacking.
- [ ] Unknown có reason code.
- [ ] Mỗi kết quả truy vết được tới Flow ID và evidence.

## 10. Ví dụ

Flow có DNS mapping đã xác minh được trả application ngay tại bước DNS. Flow không có DNS evidence được thử SNI. Nếu SNI cũng không nhận diện được, Flow mới đi qua reconstruction, segmentation, CatBoost, 1D-CNN và fusion.
