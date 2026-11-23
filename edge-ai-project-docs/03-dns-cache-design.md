# 03 -- DNS Parser và DNS Cache

## 1. Vai trò của DNS Parser và DNS Cache

DNS Parser và DNS Cache là thành phần hỗ trợ nhận diện ứng dụng thông qua thông tin phân giải tên miền.

Trong hệ thống Edge AI, không phải mọi traffic đều cần đưa qua Machine Learning. Nếu project đã thu thập được DNS Response hợp lệ, xác định được domain và domain đó thuộc một ứng dụng đã được xác minh, hệ thống có thể nhận diện ứng dụng trực tiếp.

DNS Cache tồn tại nhằm giải quyết trường hợp project không bắt được DNS Query/Response mới tại thời điểm flow xuất hiện, nhưng trước đó đã quan sát được thông tin phân giải domain tương ứng.

Hai thành phần có vai trò:

- **DNS Parser:** Phân tích DNS Query/Response để lấy domain, IP, CNAME, TTL và các thông tin liên quan.
- **DNS Cache:** Lưu trữ các mapping domain -- IP đã quan sát được để tái sử dụng khi phân tích những flow xuất hiện sau đó.
- **Application Domain Mapping:** Đối chiếu domain với danh sách domain chính và domain phụ đã xác minh của từng ứng dụng.
- **Flow Enrichment:** Bổ sung domain context vào flow dựa trên DNS Cache.

DNS là nguồn bằng chứng hỗ trợ nhận diện ứng dụng, không phải lúc nào cũng đủ để xác định chính xác ứng dụng.

## 2. Luồng xử lý DNS

```text
Client LAN
    |
    | DNS Query
    v
DNS Resolver
    |
    | DNS Response
    v
DNS Response Parser
    |
    | Validate + Parse Records
    v
DNS Cache
    |
    | Store Domain - IP Mapping
    | Store TTL + Client + Timestamp
    v
Application Domain Mapping
    |
    | Match domain with known applications
    v
Verified Application Domains
```

Khi flow mới xuất hiện:

```text
New Flow
    |
    v
Get Source IP + Destination IP
    |
    v
DNS Cache Lookup
    |
    v
Get Candidate Domain(s)
    |
    v
Application Domain Mapping
    |
    v
Check identification conditions
```

## 3. Điều kiện xử lý DNS Response

Parser/Cache cần xác minh:

- Packet thực sự là DNS Response (`QR=1`), không phải DNS Query.
- Response có liên quan đến query phù hợp khi thông tin correlation có thể xác minh.
- QNAME, record type, answer section và RCODE được đọc đúng.
- Chỉ lưu record có dữ liệu hợp lệ.
- Không coi response lỗi hoặc answer rỗng là mapping IP hợp lệ.
- Hỗ trợ A/AAAA và CNAME theo đúng quan hệ record.
- TTL được tôn trọng; entry hết hạn phải bị loại khỏi lookup.
- Gắn DNS observation với thiết bị gửi truy vấn nếu xác định được client IP.

Chỉ kiểm tra `src_port == 53` là chưa đủ để chứng minh đây là DNS Response hợp lệ.

## 4. Cấu trúc DNS Cache

Không nên sử dụng cấu trúc một IP chỉ ánh xạ đến một domain:

```python
dns_cache[dest_ip] = domain
```

Vì CDN và shared hosting có thể phục vụ nhiều domain trên cùng IP. Domain mới có thể ghi đè domain cũ.

Nên sử dụng cấu trúc có thể lưu nhiều candidate:

```python
dns_cache = {
    "142.x.x.x": [
        {
            "client_ip": "192.168.1.10",
            "domain": "youtube.com",
            "resolved_ip": "142.x.x.x",
            "record_type": "A",
            "ttl": 300,
            "inserted_at": "...",
            "expires_at": "..."
        }
    ]
}
```

Các trường dữ liệu nên lưu:

- `client_ip`: Thiết bị gửi DNS Query.
- `domain` / `qname`: Tên miền được truy vấn.
- `resolved_ip`: IP được DNS Response trả về.
- `record_type`: A, AAAA, CNAME...
- `cname_chain`: Chuỗi CNAME nếu có.
- `ttl`: Thời gian hiệu lực của record.
- `inserted_at`: Thời điểm lưu cache.
- `expires_at`: Thời điểm hết hạn.
- `query_id`: Transaction ID hoặc thông tin correlation nếu có.

Đây là cấu trúc thiết kế đề xuất, cần đối chiếu với implementation thực tế.

## 5. Client Scoping và DNS Mapping

DNS Cache nên gắn thông tin phân giải với client LAN.

Ví dụ:

```text
Device A: 192.168.1.10
    |
    | Query youtube.com
    v
DNS Response: 142.x.x.x

Device B: 192.168.1.20
    |
    | Query chatgpt.com
    v
DNS Response: 104.x.x.x
```

Khi flow xuất hiện, project sử dụng:

- Source IP để xác định thiết bị.
- Destination IP để tra DNS Cache.
- Timestamp để kiểm tra mapping còn hiệu lực.
- Domain để đối chiếu Application Domain Mapping.

Client scoping giúp tránh sử dụng nhầm DNS observation của thiết bị khác.

Tuy nhiên, client scoping không giải quyết hoàn toàn trường hợp một thiết bị truy cập nhiều domain cùng sử dụng một IP CDN. Khi đó cần kiểm tra tính mơ hồ của mapping.

## 6. TTL và CNAME

- Entry hết TTL không được sử dụng như mapping còn hiệu lực.
- CNAME chain cần có giới hạn độ sâu và cơ chế chống vòng lặp.
- TTL hiệu lực cần tuân theo record liên quan.
- Cần hỗ trợ nhiều A/AAAA record cho một domain.
- CNAME chỉ thể hiện quan hệ bí danh, không mặc định domain đích là ứng dụng cuối cùng.
- Khi CNAME được phân giải thành A/AAAA, cần giữ cả domain ban đầu và các record liên quan.

## 7. Phân loại kết quả DNS

| Trường hợp | Ví dụ | Cách xử lý |
| :--- | :--- | :--- |
| Domain chính của ứng dụng | `chatgpt.com` | Đối chiếu Application Domain Mapping |
| Domain API/phụ đã xác minh | `api.openai.com` | Có thể nhận diện ứng dụng tương ứng |
| Domain CDN dùng chung | CDN phục vụ nhiều ứng dụng | Không kết luận chỉ từ domain |
| CNAME | `app.example.com` $\rightarrow$ `edge.cdn.net` | Lưu chuỗi CNAME và tiếp tục đối chiếu |
| NOERROR nhưng Answer rỗng | Không có record phù hợp | Không tạo IP mapping |
| NXDOMAIN / SERVFAIL / REFUSED | DNS thất bại | Không tạo mapping hợp lệ |
| DNS Response không parse được | Packet thiếu hoặc không hợp lệ | Đánh dấu DNS unavailable |
| Không quan sát được DNS | DoH, DoT, VPN, OS cache... | Không có DNS evidence mới |

## 8. Điều kiện kết luận ứng dụng trực tiếp từ DNS

Project có thể nhận diện ứng dụng trực tiếp bằng DNS trong **2 trường hợp**. Cả hai đều phải thỏa mãn các điều kiện chung dưới đây.

### Điều kiện chung

1. **Domain đã xác minh:** Domain thuộc danh sách domain chính hoặc domain phụ/API đã xác minh của một ứng dụng.
2. **DNS Response hợp lệ:** Response được parse đúng, có Answer hợp lệ và xác định được quan hệ domain -- IP thông qua A/AAAA hoặc CNAME hợp lệ.
3. **IP khớp với flow:**
   - Source IP của flow khớp với Client IP đã gửi DNS Query.
   - Destination IP của flow khớp với IP được DNS Response phân giải.
4. **Không mơ hồ:** Các candidate mapping phù hợp không dẫn đến những ứng dụng khác nhau. Nếu IP dùng chung khiến không thể phân biệt ứng dụng, không kết luận trực tiếp.

### Trường hợp 1: Flow đầu tiên -- sử dụng DNS Response mới

Project đang capture và quan sát được DNS Response khi thiết bị truy cập ứng dụng lần đầu.

Ví dụ:

```text
DNS Response:
Client IP:   192.168.1.10
Domain:      chatgpt.com
Resolved IP: 104.x.x.x

Flow:
Source IP:      192.168.1.10
Destination IP: 104.x.x.x
```

Nếu tất cả **điều kiện chung** đều đạt, project có thể kết luận:

```text
Application: ChatGPT
Identification Method: DNS
Status: DNS_IDENTIFIED
```

Không cần có DNS Cache từ lần truy cập trước và không cần đưa flow qua ML chỉ để nhận diện ứng dụng.

### Trường hợp 2: Flow tiếp theo -- sử dụng DNS Cache

Project không bắt được DNS Response mới tại thời điểm flow xuất hiện, nhưng đã lưu mapping từ DNS Response hợp lệ trước đó.

Ngoài việc thỏa mãn **tất cả điều kiện chung**, cần thêm:

- DNS Cache có mapping tương ứng với client IP và destination IP của flow.
- Mapping vẫn còn hiệu lực TTL tại thời điểm flow xuất hiện.

Ví dụ:

```text
DNS Cache đã lưu:
192.168.1.10
chatgpt.com -> 104.x.x.x
TTL: 300 seconds

Flow tiếp theo:
Source IP:      192.168.1.10
Destination IP: 104.x.x.x
```

Nếu mapping còn TTL và các điều kiện chung đều đạt, project có thể kết luận ChatGPT mà không cần DNS Query/Response mới hoặc ML.

### Tóm tắt

| Trường hợp | Điều kiện |
| :--- | :--- |
| **Flow đầu tiên** | Domain đã xác minh + DNS Response hợp lệ + Source/Destination IP khớp + mapping không mơ hồ |
| **Flow tiếp theo** | Tất cả điều kiện của flow đầu tiên + có DNS Cache tương ứng + mapping còn TTL |

Nếu một trong các điều kiện không đạt, project không kết luận ứng dụng trực tiếp bằng DNS mà chuyển flow sang ML hoặc UNKNOWN tùy kết quả phân loại.

## 9. Tại sao DNS Cache cần tồn tại?

DNS Cache giải quyết vấn đề DNS Query/Response không xuất hiện ở mỗi lần thiết bị tạo kết nối.

Ví dụ:

**08:00 -- Thiết bị truy cập YouTube**

```text
DNS Response:
youtube.com -> 142.x.x.x

Project lưu:
142.x.x.x -> youtube.com
```

**08:05 -- Thiết bị tiếp tục xem YouTube**

Do hệ điều hành đã có DNS cache, thiết bị có thể không gửi DNS Query mới.

Tuy nhiên, project vẫn bắt được traffic:

```text
Source IP:      192.168.1.10
Destination IP: 142.x.x.x
Port:           443
```

Project tra DNS Cache:

```text
142.x.x.x -> youtube.com
```

Nếu mapping còn hiệu lực và đáp ứng các điều kiện nhận diện, project có thể nhận diện YouTube mà không cần chờ DNS Query mới.

### Những vấn đề DNS Cache giải quyết

1. **Tái sử dụng DNS observation:** Không phải chờ DNS Query mới mỗi khi có flow.
2. **Hỗ trợ Flow Enrichment:** Bổ sung domain context cho flow chỉ có thông tin IP.
3. **Hạn chế phụ thuộc vào DNS realtime:** Có thể sử dụng thông tin DNS đã quan sát trước đó trong thời hạn TTL.
4. **Hỗ trợ nhận diện ứng dụng:** Cung cấp domain để đối chiếu với danh sách domain chính và domain phụ đã xác minh.
5. **Hỗ trợ ML:** Cung cấp thêm ngữ cảnh domain cho quá trình phân tích và đánh giá kết quả phân loại.
6. **Quản lý lịch sử mapping:** Lưu thông tin domain, IP, client và thời gian để hỗ trợ truy vết.

DNS Cache không giải quyết được trường hợp project chưa từng quan sát DNS, DNS mã hóa hoặc mapping IP không đủ rõ ràng.

## 10. Giới hạn của DNS Parser và DNS Cache

- Không phải mọi ứng dụng đều có một domain duy nhất.
- Một ứng dụng có thể sử dụng nhiều domain, API và CDN.
- Một IP có thể được nhiều domain hoặc ứng dụng cùng sử dụng.
- DNS Cache không tự biết domain nếu project chưa từng quan sát được DNS mapping.
- DNS observation không chứng minh thiết bị đang chủ động sử dụng ứng dụng tại thời điểm đó nếu không có flow tương ứng.
- DNS chỉ cung cấp thông tin tên miền và phân giải địa chỉ, không giải mã nội dung traffic HTTPS/QUIC.

Do đó, DNS được sử dụng làm nguồn bằng chứng nhận diện ứng dụng khi đủ điều kiện, còn ML xử lý những trường hợp DNS không cung cấp đủ thông tin.

## 11. Kết luận

DNS Parser và DNS Cache đóng vai trò bổ trợ trong kiến trúc Hybrid DNS + Edge AI.

Nguyên tắc xử lý:

| Điều kiện | Hành động |
| :--- | :--- |
| Domain chính/phụ đã xác minh, flow khớp và mapping đáng tin cậy | Kết luận ứng dụng bằng DNS |
| Domain CDN hoặc shared infrastructure | Không kết luận chỉ từ DNS |
| DNS Cache có nhiều candidate mơ hồ | Tiếp tục xử lý bằng ML hoặc giữ Unknown |
| Không có DNS mapping | Sử dụng ML |
| ML không đủ confidence | Trả về Unknown |

**Mục tiêu cuối cùng:** Tận dụng DNS để nhận diện ứng dụng khi có đủ bằng chứng, đồng thời sử dụng Machine Learning để phân loại traffic mã hóa trong những trường hợp DNS không thể đưa ra kết luận đáng tin cậy.
