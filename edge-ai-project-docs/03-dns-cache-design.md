# 03 — DNS Parser, DNS Cache và DNS Application Identification

## 1. Mục đích

DNS Parser trích xuất DNS Response. DNS Cache lưu quan hệ client-domain-IP theo TTL để DNS Identifier có thể nhận diện application trước khi thử SNI.

## 2. Phạm vi

**Làm**
- Parse DNS Response hợp lệ.
- Lưu A/AAAA/CNAME observation, client IP, domain, TTL và thời điểm.
- Tra DNS Cache theo client và destination IP.
- Map domain đã xác minh sang application.
- Trả `DNS_IDENTIFIED` hoặc `DNS_UNRESOLVED`.

**Không làm**
- Không coi một IP chỉ thuộc một domain.
- Không kết luận từ shared-IP khi candidate mơ hồ.
- Không gọi SNI hoặc ML bên trong DNS module.

## 3. Phụ thuộc

- Input: DNS packet từ Packet Parsing.
- DNS Cache cung cấp evidence cho DNS Identifier.
- Application Domain Mapping chứa domain chính/phụ đã xác minh.
- DNS Identifier được gọi ở bước 4, trước TLS/SNI.

## 4. Luồng xử lý

1. Xác định DNS Response (`QR=1`).
2. Parse RCODE, question, answer và record A/AAAA/CNAME.
3. Kiểm tra record hợp lệ và correlation nếu có.
4. Lưu mapping kèm client scope và TTL.
5. Khi Flow xuất hiện, lookup theo client IP + destination IP + timestamp.
6. Lấy candidate domain còn TTL.
7. Đối chiếu Application Domain Mapping.
8. Nếu chỉ có một application hợp lệ và evidence không ambiguous, trả `DNS_IDENTIFIED`.
9. Nếu không đủ điều kiện, trả `DNS_UNRESOLVED` để pipeline gọi SNI.

## 5. Input / Output

**DNS observation mẫu**

```json
{
  "client_ip": "192.168.1.10",
  "domain": "chatgpt.com",
  "resolved_ip": "104.0.0.1",
  "record_type": "A",
  "ttl": 300,
  "observed_at": "2026-11-23T10:00:00"
}
```

**DNS identification result mẫu**

```json
{
  "status": "DNS_IDENTIFIED",
  "application": "chatgpt",
  "matched_domain": "chatgpt.com",
  "evidence": "dns_cache"
}
```

Các giá trị IP/domain trong ví dụ chỉ minh họa schema, không phải endpoint cố định.

## 6. Quy tắc nghiệp vụ

- BR-01: Chỉ xử lý DNS Response (`QR=1`) để tạo mapping.
- BR-02: Response lỗi hoặc Answer rỗng không tạo IP mapping hợp lệ.
- BR-03: Hỗ trợ A/AAAA và giữ quan hệ CNAME.
- BR-04: Entry hết TTL không được dùng để identify.
- BR-05: Cache phải hỗ trợ nhiều domain candidate trên một IP.
- BR-06: Mapping phải gắn client IP khi client quan sát được.
- BR-07: Domain phải thuộc danh sách đã xác minh.
- BR-08: Nhiều candidate dẫn đến nhiều application thì trả `DNS_UNRESOLVED`.
- BR-09: DNS identified kết thúc nhận diện Flow; không gọi SNI/ML.
- BR-10: DNS unresolved chuyển sang TLS/SNI, không nhảy thẳng vào ML.

## 7. Lỗi và trường hợp biên

| Tình huống | Hành vi |
|---|---|
| NXDOMAIN/SERVFAIL/REFUSED | Không tạo mapping |
| Answer rỗng | Không tạo IP mapping |
| TTL hết hạn | Bỏ candidate khỏi lookup |
| Shared IP nhiều domain | Giữ nhiều candidate; unresolved nếu ambiguous |
| CNAME loop | Dừng theo giới hạn depth; không tạo mapping sai |
| DoH/DoT/VPN | Không có DNS evidence; chuyển SNI |
| Không xác định client | Đánh dấu scope không xác định; không giả lập client |
| Cache miss | `DNS_UNRESOLVED` |

## 8. File/hàm chính

- `rules.yaml`: cần kiểm tra phần domain mapping hiện hữu trước khi sửa.
- DNS parser/cache implementation path: chưa xác định từ danh sách source snapshot; tìm implementation hiện hữu trước khi tạo file.
- DNS Identifier: cần tách trách nhiệm khỏi parser/cache nếu source hiện tại đang gộp các phần này.

## 9. Tiêu chí nghiệm thu

- [ ] DNS Response hợp lệ tạo observation.
- [ ] DNS Query không tạo mapping.
- [ ] TTL hết hạn làm lookup miss.
- [ ] Một IP lưu được nhiều domain.
- [ ] Client A không dùng mapping riêng của Client B.
- [ ] Shared-IP ambiguity trả `DNS_UNRESOLVED`.
- [ ] DNS identified không kích hoạt SNI hoặc ML.

## 10. Ví dụ

Client `192.168.1.10` truy vấn domain đã xác minh và nhận A record còn TTL. Flow từ client này đến IP tương ứng được map sang application. Nếu cùng IP có candidate domain thuộc application khác và không có evidence phân biệt, DNS Identifier trả unresolved.
