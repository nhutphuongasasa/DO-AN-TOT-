# 03 – DNS Parser và DNS Cache

## 1. Vai trò

DNS cache giúp liên hệ một IP đích với domain đã được thiết bị truy vấn trước đó. Đây là tín hiệu phụ trợ khi flow không có SNI, ví dụ QUIC parser thất bại hoặc ECH che SNI.

**DNS không phải bằng chứng chắc chắn rằng một flow tới IP đó thuộc domain đó.**

## 2. Luồng DNS

```text
Client LAN -- DNS Query --> Resolver
Client LAN <-- DNS Response -- Resolver
                       |
                       v
              DNS response parser
                       |
        validate response + parse records
                       |
                       v
              DNS cache with TTL
                       |
        flow to destination IP arrives
                       |
                       v
             candidate domain(s)
```

## 3. Điều kiện xử lý response

Parser/cache cần xác minh:
- Packet thực sự là DNS response (QR=1), không phải query.
- Response có liên quan đến query phù hợp khi thông tin đó có thể xác minh.
- QNAME, record type, answer section và RCODE được đọc đúng.
- Chỉ lưu record có dữ liệu hợp lệ; không coi response lỗi hoặc answer rỗng là mapping hợp lệ.
- Hỗ trợ A/AAAA và CNAME theo đúng quan hệ record.
- TTL được tôn trọng; entry hết hạn phải bị loại khỏi lookup.

Chỉ kiểm tra `src_port == 53` là chưa đủ để chứng minh đây là response hợp lệ.

## 4. Không dùng ánh xạ một IP – một domain

CDN và shared hosting thường phục vụ nhiều domain trên cùng IP. Một IP có thể có nhiều candidate domain cùng thời điểm.

Không nên thiết kế kiểu:

```python
dns_cache[dest_ip] = domain
```

vì domain đến sau có thể ghi đè domain trước. Thiết kế cần giữ nhiều candidate record, có TTL và nguồn gốc truy vấn.

Một record có thể cần các trường:
- `client_ip`;
- `domain` / `qname`;
- `resolved_ip`;
- `record_type`;
- `cname_chain`;
- `ttl`;
- `inserted_at` / `expires_at`;
- `query_id` hoặc thông tin correlation nếu có.

Đây là cấu trúc thiết kế gợi ý; cần đối chiếu với kiểu dữ liệu thực tế trong code.

## 5. Client scoping và độ mơ hồ

Nên gắn DNS observation với client LAN để tránh thiết bị A truy vấn domain rồi làm nhiễm kết quả của thiết bị B.

Tuy nhiên, client scoping **không giải quyết hoàn toàn** shared IP: cùng một client có thể truy cập nhiều domain cùng CDN. Nếu một IP có nhiều candidate domain hợp lệ và không có thông tin đủ để liên kết flow với một domain cụ thể, kết quả phải được đánh dấu ambiguous hoặc giảm confidence.

## 6. TTL và CNAME

- Entry hết TTL không được dùng như mapping còn hiệu lực.
- CNAME chain cần có giới hạn độ sâu và chống vòng lặp.
- TTL hiệu lực cần tuân theo record liên quan, không kéo dài tùy tiện.
- Cần xử lý nhiều A/AAAA records cho một domain.

## 7. DNS không quan sát được

DoH/DoT, cache nội bộ của OS/browser, VPN hoặc DNS mã hóa có thể khiến hệ thống không thấy response trên port 53. Đây là giới hạn quan sát, không phải lỗi làm dừng pipeline.

Khi không có DNS evidence:
- không tự tạo mapping;
- không tái sử dụng mapping hết TTL;
- chuyển sang SNI/fingerprint/flow features;
- nếu thiếu tín hiệu thì giữ `unknown`.

## 8. Bộ test bắt buộc

| Test | Kết quả mong đợi |
|---|---|
| Một domain resolve một IP | Có một candidate hợp lệ |
| Một domain resolve nhiều IP | Lưu đủ IP |
| Nhiều domain cùng IP | Không ghi đè candidate |
| Client A và B cùng IP đích | Không trộn cache giữa client |
| TTL hết hạn | Lookup không trả entry hết hạn |
| DNS query không có response | Không tạo mapping |
| Response RCODE lỗi / answer rỗng | Không tạo mapping hợp lệ |
| CNAME chain | Resolve theo chain hợp lệ, có giới hạn |
| DoH không quan sát được | Pipeline tiếp tục, không crash |

## 9. Nguyên tắc phân loại từ DNS

DNS chỉ tạo candidate evidence. Không nên tự động kết luận ứng dụng từ IP đích nếu IP dùng chung. Cần cân nhắc thời gian giữa DNS response và flow, client, domain candidate và các evidence khác.
