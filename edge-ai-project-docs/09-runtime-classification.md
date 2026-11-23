# 09 – Phân loại runtime: Rule Engine + ML

## 1. Hai nguồn quyết định

### Rule Engine
README mô tả các lớp:
1. SNI;
2. DNS cache;
3. JA3/JA4;
4. Port/protocol;
5. IP/ASN.

Mỗi lớp có độ tin cậy khác nhau. Các con số confidence trong README là cấu hình/ước lượng được mô tả, không nên xem là xác suất đã hiệu chuẩn nếu chưa kiểm tra.

### ML
ML nhận feature vector từ flow/window hoặc Burst sequence và trả dự đoán cùng confidence.

## 2. Quy tắc phối hợp

Rule và ML không nên ghi đè lẫn nhau một cách im lặng. Mỗi kết quả cần lưu:
- rule app/confidence/source/evidence;
- ML app/confidence/model version;
- final app/confidence/source;
- conflict status và quyết định xử lý.

## 3. State machine đề xuất

```text
NEW
 |
 v
COLLECTING
 |
 | đủ dữ liệu để đánh giá?
 +---- No ----> tiếp tục thu thập
 |
 Yes
 |
 v
RULE_EVALUATED
 |
 +---- rule đủ tin cậy, evidence hợp lệ ---> CLASSIFIED_BY_RULE
 |
 +---- rule yếu / thiếu metadata ----------> ML_PENDING
                                                 |
                                      đủ feature/model?
                                       /          \
                                     No            Yes
                                     |              |
                                  UNKNOWN      ML_INFERENCE
                                                    |
                                      confidence đủ? |
                                        /            \
                                      No              Yes
                                      |                |
                                   UNKNOWN       CLASSIFIED_BY_ML
```

Đây là state machine thiết kế. Cần điều chỉnh theo API thực tế của pipeline.

## 4. Không gọi ML quá sớm

Không nên gọi ML trên từng packet nếu feature vector còn quá ít dữ liệu. Cần điều kiện rõ:
- tối thiểu packet count;
- tối thiểu thời gian quan sát;
- feature vector hợp lệ;
- model đã load và schema khớp;
- không gọi lặp lại không cần thiết cho cùng observation.

Có thể dự đoán lại khi cửa sổ mới có đủ dữ liệu, nhưng cần kiểm soát tần suất.

## 5. Conflict policy

Ví dụ:
- SNI độc quyền, hợp lệ, không ambiguous có thể là evidence mạnh.
- DNS shared-IP không nên thắng một evidence SNI mạnh.
- ML và rule khác nhau: lưu conflict, áp dụng policy được định nghĩa trước; không tự động chọn ML chỉ vì confidence số học lớn hơn nếu hai confidence không cùng calibration.
- Nếu cả hai yếu hoặc metadata mơ hồ: `unknown`.

## 6. Device aggregation

Một thiết bị có thể chạy nhiều app cùng lúc. Không nên luôn ép một nhãn duy nhất cho thiết bị nếu các flow thể hiện nhiều ứng dụng. Có thể hiển thị danh sách app hoạt động, bytes/flow theo app và thời điểm quan sát.

## 7. Truy vết

Dashboard phải phân biệt:
- `source=rule_sni`;
- `source=rule_dns`;
- `source=ml_flow`;
- `source=ml_burst`;
- `source=unknown`.

Tên source là đề xuất; thống nhất với schema log thực tế.
