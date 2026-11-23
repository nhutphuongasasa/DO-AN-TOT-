# 03 -- DNS Parser và DNS Cache

## 1. Vai trò của DNS Parser và DNS Cache

DNS Parser và DNS Cache là thành phần hỗ trợ nhận diện ứng dụng thông
qua thông tin phân giải tên miền.

Trong hệ thống Edge AI, không phải mọi traffic đều cần đưa qua Machine
Learning. Nếu project đã thu thập được DNS Response hợp lệ, xác định
được domain và domain đó thuộc một ứng dụng đã được xác minh, hệ thống
có thể nhận diện ứng dụng trực tiếp.

DNS Cache tồn tại nhằm giải quyết trường hợp project không bắt được DNS
Query/Response mới tại thời điểm flow xuất hiện, nhưng trước đó đã quan
sát được thông tin phân giải domain tương ứng.

Hai thành phần có vai trò:

-   **DNS Parser:** Phân tích DNS Query/Response để lấy domain, IP,
    CNAME, TTL và các thông tin liên quan.
-   **DNS Cache:** Lưu trữ các mapping domain -- IP đã quan sát được để
    tái sử dụng khi phân tích những flow xuất hiện sau đó.
-   **Application Domain Mapping:** Đối chiếu domain với danh sách
    domain chính và domain phụ đã xác minh của từng ứng dụng.
-   **Flow Enrichment:** Bổ sung domain context vào flow dựa trên DNS
    Cache.

DNS là nguồn bằng chứng hỗ trợ nhận diện ứng dụng, không phải lúc nào
cũng đủ để xác định chính xác ứng dụng.

## 2. Luồng xử lý DNS

``` text
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

``` text
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

-   Packet thực sự là DNS Response (`QR=1`), không phải DNS Query.
-   Response có liên quan đến query phù hợp khi thông tin correlation có
    thể xác minh.
-   QNAME, record type, answer section và RCODE được đọc đúng.
-   Chỉ lưu record có dữ liệu hợp lệ.
-   Không coi response lỗi hoặc answer rỗng là mapping IP hợp lệ.
-   Hỗ trợ A/AAAA và CNAME theo đúng quan hệ record.
-   TTL được tôn trọng; entry hết hạn phải bị loại khỏi lookup.
-   Gắn DNS observation với thiết bị gửi truy vấn nếu xác định được
    client IP.

Chỉ kiểm tra `src_port == 53` là chưa đủ để chứng minh đây là DNS
Response hợp lệ.

## 4. Cấu trúc DNS Cache

Không nên sử dụng cấu trúc một IP chỉ ánh xạ đến một domain:

``` python
dns_cache[dest_ip] = domain
```

Vì CDN và shared hosting có thể phục vụ nhiều domain trên cùng IP.
Domain mới có thể ghi đè domain cũ.

Nên sử dụng cấu trúc có thể lưu nhiều candidate:

``` python
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

-   `client_ip`: Thiết bị gửi DNS Query.
-   `domain` / `qname`: Tên miền được truy vấn.
-   `resolved_ip`: IP được DNS Response trả về.
-   `record_type`: A, AAAA, CNAME...
-   `cname_chain`: Chuỗi CNAME nếu có.
-   `ttl`: Thời gian hiệu lực của record.
-   `inserted_at`: Thời điểm lưu cache.
-   `expires_at`: Thời điểm hết hạn.
-   `query_id`: Transaction ID hoặc thông tin correlation nếu có.

Đây là cấu trúc thiết kế đề xuất, cần đối chiếu với implementation thực
tế.

## 5. Client Scoping và DNS Mapping

DNS Cache nên gắn thông tin phân giải với client LAN.

Ví dụ:

``` text
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

-   Source IP để xác định thiết bị.
-   Destination IP để tra DNS Cache.
-   Timestamp để kiểm tra mapping còn hiệu lực.
-   Domain để đối chiếu Application Domain Mapping.

Client scoping giúp tránh sử dụng nhầm DNS observation của thiết bị
khác.

Tuy nhiên, client scoping không giải quyết hoàn toàn trường hợp một
thiết bị truy cập nhiều domain cùng sử dụng một IP CDN. Khi đó cần kiểm
tra tính mơ hồ của mapping.

## 6. TTL và CNAME

-   Entry hết TTL không được sử dụng như mapping còn hiệu lực.
-   CNAME chain cần có giới hạn độ sâu và cơ chế chống vòng lặp.
-   TTL hiệu lực cần tuân theo record liên quan.
-   Cần hỗ trợ nhiều A/AAAA record cho một domain.
-   CNAME chỉ thể hiện quan hệ bí danh, không mặc định domain đích là
    ứng dụng cuối cùng.
-   Khi CNAME được phân giải thành A/AAAA, cần giữ cả domain ban đầu và
    các record liên quan.

## 7. Phân loại kết quả DNS

  -----------------------------------------------------------------------
  Trường hợp              Ví dụ                   Cách xử lý
  ----------------------- ----------------------- -----------------------
  Domain chính của ứng    `chatgpt.com`           Đối chiếu Application
  dụng                                            Domain Mapping

  Domain API/phụ đã xác   `api.openai.com`        Có thể nhận diện ứng
  minh                                            dụng tương ứng

  Domain CDN dùng chung   CDN phục vụ nhiều ứng   Không kết luận chỉ từ
                          dụng                    domain

  CNAME                   `app.example.com` →     Lưu chuỗi CNAME và tiếp
                          `edge.cdn.net`          tục đối chiếu

  NOERROR nhưng Answer    Không có record phù hợp Không tạo IP mapping
  rỗng                                            

  NXDOMAIN / SERVFAIL /   DNS thất bại            Không tạo mapping hợp
  REFUSED                                         lệ

  DNS Response không      Packet thiếu hoặc không Đánh dấu DNS
  parse được              hợp lệ                  unavailable

  Không quan sát được DNS DoH, DoT, VPN, OS       Không có DNS evidence
                          cache...                mới
  -----------------------------------------------------------------------

## 8. Điều kiện kết luận ứng dụng trực tiếp từ DNS

Đây là nhánh xử lý quan trọng của hệ thống. DNS có thể nhận diện ứng
dụng ngay cả ở flow đầu tiên mà project quan sát được, không cần đợi
thiết bị truy cập ứng dụng lần thứ hai.

Tuy nhiên, **domain thuộc ứng dụng mới chỉ là một phần bằng chứng**.
Project chỉ được kết luận ứng dụng khi DNS observation được liên kết
đáng tin cậy với flow đang xét.

### Điều kiện 1: DNS Response hợp lệ

-   Packet thực sự là DNS Response (`QR=1`), không phải DNS Query.
-   Response có `RCODE` phù hợp và có Answer hợp lệ.
-   QNAME, record type, answer section và các record liên quan được
    parse đúng.
-   Có thể xác minh quan hệ giữa domain được truy vấn và IP thông qua
    A/AAAA hoặc chuỗi CNAME hợp lệ.
-   Không tạo IP mapping từ response lỗi hoặc Answer rỗng.
-   Khi có đủ thông tin, cần correlation DNS Response với Query tương
    ứng; không chỉ dựa vào `src_port == 53`.

### Điều kiện 2: Domain đã được xác minh thuộc ứng dụng

Project cần có Application Domain Mapping được kiểm chứng.

Ví dụ minh họa:

``` python
APPLICATION_DOMAINS = {
    "ChatGPT": [
        "chatgpt.com",
        "api.openai.com"
    ],
    "YouTube": [
        "youtube.com",
        "googlevideo.com",
        "ytimg.com"
    ]
}
```

Danh sách trên chỉ mang tính minh họa. Khi triển khai cần xác minh từng
domain, đặc biệt là domain API, domain phụ, CDN và domain dùng chung.
Không được mặc định một domain thuộc ứng dụng chỉ vì tên miền có chứa
tên thương hiệu hoặc từ `api`.

### Điều kiện 3: Flow khớp với DNS observation

Khi flow xuất hiện, cần kiểm tra:

-   Source IP của flow khớp với `client_ip` của DNS observation.
-   Destination IP của flow khớp với IP được DNS Response phân giải.
-   DNS mapping còn thời hạn hiệu lực theo TTL tại thời điểm flow xuất
    hiện.
-   Thời điểm DNS observation phù hợp với flow; không sử dụng một
    observation không liên quan hoặc đã hết hạn.
-   Quan hệ CNAME/A/AAAA được giữ đúng, không tự suy diễn domain đích từ
    một record không liên quan.

### Điều kiện 4: Không có mâu thuẫn về ứng dụng

Nếu một IP có nhiều candidate domain:

-   Nếu tất cả candidate hợp lệ, còn hiệu lực và đều ánh xạ đến cùng một
    ứng dụng đã xác minh, có thể kết luận **ứng dụng**. Không nhất thiết
    phải khẳng định chính xác domain nào tạo ra flow.
-   Nếu candidate thuộc nhiều ứng dụng khác nhau, mapping được xem là
    ambiguous.
-   Nếu IP thuộc CDN/shared infrastructure và không có đủ bằng chứng
    phân biệt, không được kết luận ứng dụng chỉ từ IP.
-   Nếu domain chưa được xác minh hoặc có mâu thuẫn trong mapping,
    chuyển sang ML hoặc giữ UNKNOWN tùy chính sách của hệ thống.

### Flow đầu tiên truy cập ứng dụng có thể được nhận diện như thế nào?

Ví dụ: thiết bị lần đầu truy cập ChatGPT trong thời gian project đang
capture.

**Bước 1 -- Project quan sát DNS Response**

``` text
Client IP:  192.168.1.10
QNAME:      chatgpt.com
RCODE:      NOERROR
Answer:
    chatgpt.com → 104.x.x.x
TTL:        300 seconds
```

Parser xác minh response và lưu mapping vào DNS Cache, gắn với client IP
và thời điểm quan sát.

**Bước 2 -- Flow tương ứng xuất hiện**

``` text
Source IP:       192.168.1.10
Destination IP:  104.x.x.x
Destination Port: 443
Timestamp:       08:02:00
```

**Bước 3 -- Đối chiếu DNS Cache và Application Domain Mapping**

``` text
Flow source IP      == DNS client IP
Flow destination IP == DNS resolved IP
Flow timestamp      nằm trong thời hạn mapping
chatgpt.com         thuộc domain ChatGPT đã xác minh
Candidate mapping   không mơ hồ
```

Nếu tất cả điều kiện đều đạt, project có thể kết luận:

``` text
Application: ChatGPT
Identification Method: DNS
Status: DNS_IDENTIFIED
```

Project không cần chờ thiết bị truy cập ChatGPT lần thứ hai và cũng
không cần đưa flow qua ML chỉ để nhận diện ứng dụng.

Điều này chỉ đúng khi project quan sát được DNS Response và flow tương
ứng. Nếu DNS đã nằm trong cache của hệ điều hành, được phân giải trước
khi capture bắt đầu, hoặc sử dụng DoH/DoT/VPN khiến project không quan
sát được DNS, project không có bằng chứng DNS mới để thực hiện kết luận
này.

### Domain chính và domain phụ/API

Cả domain chính và domain phụ/API đã xác minh đều có thể dùng để nhận
diện ứng dụng. Ví dụ, nếu `api.openai.com` đã được xác minh thuộc
ChatGPT, DNS Response phân giải domain này thành IP hợp lệ và flow từ
đúng client đến đúng IP trong thời hạn mapping, project có thể kết luận
ChatGPT.

Không cần bắt buộc flow phải truy cập domain chính. Điều quan trọng là
domain đã được xác minh và flow khớp với DNS observation.

### Kết quả

Nếu tất cả điều kiện trên được đáp ứng:

``` text
Flow
  |
  v
DNS Cache Lookup
  |
  v
Valid DNS Observation
  |
  v
Verified Application Domain
  |
  v
Flow / Client / IP / Time Match
  |
  v
No Cross-Application Ambiguity
  |
  v
Application Identified by DNS
```

Lưu ý: Kết luận này dựa trên bằng chứng domain và flow tương ứng, không
phải chỉ vì thiết bị đã từng truy vấn domain đó.

## 9. Khi nào cần chuyển sang Machine Learning?

Nếu không thể nhận diện ứng dụng đáng tin cậy từ DNS, flow sẽ tiếp tục
qua pipeline phân loại traffic.

Các trường hợp bao gồm:

-   Không tìm thấy DNS mapping.
-   DNS Response không được quan sát.
-   DNS Cache không có entry tương ứng.
-   Mapping đã hết TTL.
-   Domain chưa có trong Application Domain Mapping.
-   Domain thuộc CDN/shared infrastructure.
-   Có nhiều candidate thuộc các ứng dụng khác nhau.
-   Không đủ thông tin để liên kết DNS observation với flow.
-   Flow đầu tiên xuất hiện nhưng project không quan sát được DNS
    Response tương ứng (ví dụ DNS đã có trong OS cache hoặc DNS được mã
    hóa).

Luồng xử lý:

``` text
New Flow / Burst
      |
      v
DNS Cache Lookup
      |
      v
Application Domain Mapping
      |
      v
Reliable Application Evidence?
      |
      +-------------------+
      |                   |
     YES                  NO
      |                   |
      v                   v
Identify App         Feature Extraction
Directly                  |
      |                   v
      |               ML Model
      |                   |
      |                   v
      |             Application Prediction
      |                   |
      +---------+---------+
                |
                v
        Device Application Tracking
                |
                v
             Dashboard
```

Nếu ML confidence không đủ cao, kết quả cần được đánh dấu `UNKNOWN` hoặc
`LOW_CONFIDENCE`, không tự động kết luận ứng dụng.

## 10. Tại sao DNS Cache cần tồn tại?

DNS Cache giải quyết vấn đề DNS Query/Response không xuất hiện ở mỗi lần
thiết bị tạo kết nối.

Ví dụ:

**08:00 -- Thiết bị truy cập YouTube**

``` text
DNS Response:
youtube.com → 142.x.x.x

Project lưu:
142.x.x.x → youtube.com
```

**08:05 -- Thiết bị tiếp tục xem YouTube**

Do hệ điều hành đã có DNS cache, thiết bị có thể không gửi DNS Query
mới.

Tuy nhiên, project vẫn bắt được traffic:

``` text
Source IP:      192.168.1.10
Destination IP: 142.x.x.x
Port:           443
```

Project tra DNS Cache:

``` text
142.x.x.x → youtube.com
```

Nếu mapping còn hiệu lực và đáp ứng các điều kiện nhận diện, project có
thể nhận diện YouTube mà không cần chờ DNS Query mới.

### Những vấn đề DNS Cache giải quyết

1.  **Tái sử dụng DNS observation:** Không phải chờ DNS Query mới mỗi
    khi có flow.
2.  **Hỗ trợ Flow Enrichment:** Bổ sung domain context cho flow chỉ có
    thông tin IP.
3.  **Hạn chế phụ thuộc vào DNS realtime:** Có thể sử dụng thông tin DNS
    đã quan sát trước đó trong thời hạn TTL.
4.  **Hỗ trợ nhận diện ứng dụng:** Cung cấp domain để đối chiếu với danh
    sách domain chính và domain phụ đã xác minh.
5.  **Hỗ trợ ML:** Cung cấp thêm ngữ cảnh domain cho quá trình phân tích
    và đánh giá kết quả phân loại.
6.  **Quản lý lịch sử mapping:** Lưu thông tin domain, IP, client và
    thời gian để hỗ trợ truy vết.

DNS Cache không giải quyết được trường hợp project chưa từng quan sát
DNS, DNS mã hóa hoặc mapping IP không đủ rõ ràng.

## 11. Giới hạn của DNS Parser và DNS Cache

-   Không phải mọi ứng dụng đều có một domain duy nhất.
-   Một ứng dụng có thể sử dụng nhiều domain, API và CDN.
-   Một IP có thể được nhiều domain hoặc ứng dụng cùng sử dụng.
-   DNS Cache không tự biết domain nếu project chưa từng quan sát được
    DNS mapping.
-   DNS observation không chứng minh thiết bị đang chủ động sử dụng ứng
    dụng tại thời điểm đó nếu không có flow tương ứng.
-   DNS chỉ cung cấp thông tin tên miền và phân giải địa chỉ, không giải
    mã nội dung traffic HTTPS/QUIC.

Do đó, DNS được sử dụng làm nguồn bằng chứng nhận diện ứng dụng khi đủ
điều kiện, còn ML xử lý những trường hợp DNS không cung cấp đủ thông
tin.

## 12. Kết luận

DNS Parser và DNS Cache đóng vai trò bổ trợ trong kiến trúc Hybrid DNS +
Edge AI.

Nguyên tắc xử lý:

  -----------------------------------------------------------------------
  Điều kiện                           Hành động
  ----------------------------------- -----------------------------------
  Domain chính/phụ đã xác minh, flow  Kết luận ứng dụng bằng DNS
  khớp và mapping đáng tin cậy        

  Domain CDN hoặc shared              Không kết luận chỉ từ DNS
  infrastructure                      

  DNS Cache có nhiều candidate mơ hồ  Tiếp tục xử lý bằng ML hoặc giữ
                                      Unknown

  Không có DNS mapping                Sử dụng ML

  ML không đủ confidence              Trả về Unknown
  -----------------------------------------------------------------------

**Mục tiêu cuối cùng:** Tận dụng DNS để nhận diện ứng dụng khi có đủ
bằng chứng, đồng thời sử dụng Machine Learning để phân loại traffic mã
hóa trong những trường hợp DNS không thể đưa ra kết luận đáng tin cậy.
