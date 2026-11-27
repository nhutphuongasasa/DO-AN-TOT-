# 03 — DNS Parser, DNS Cache và DNS Application Identification

## 1. Mục đích và vị trí trong kiến trúc

Module DNS là tầng nhận diện Application đầu tiên trong runtime Hybrid:

`Capture → Packet/Flow → DNS Parser + DNS Cache → DNS Application Identification → SNI fallback → Burst-based ML fallback`.

DNS Cache là kho **bằng chứng DNS được quan sát**, không phải bảng ánh xạ IP → Application một-một và không tự quyết định Application. DNS Parser tạo observation; DNS Cache quản lý observation theo client, domain, IP và TTL; DNS Application Identifier đối chiếu các candidate còn hiệu lực với Application Domain Rules để trả `DNS_IDENTIFIED` hoặc `DNS_UNRESOLVED`.

DNS Cache được cập nhật liên tục trong capture/replay. Mỗi Flow được đánh giá ở tầng DNS trước khi được phép đi tiếp SNI. Khi Flow đã có kết quả nhận diện cuối cùng, kết quả đó được giữ ở cấp Flow; TTL hết hạn ngăn việc dùng mapping cho lần nhận diện Flow mới, không tự xóa bằng chứng lịch sử của Flow đã được nhận diện.

## 2. Phạm vi

**Làm**
- Parse DNS message từ raw packet/transport-payload view tạm thời (PacketRecord metadata-only không đủ), quan sát trong UDP/TCP; ưu tiên DNS Response để tạo IP mapping.
- Correlate response với query khi query được quan sát; lưu client scope khi xác định được.
- Parse question và Answer records A, AAAA, CNAME; giữ record type, owner name, value, TTL và timestamp.
- Quản lý CNAME chain, expiry và nhiều domain candidate cùng một IP.
- Tra cứu theo `client_ip + destination_ip + flow_timestamp`.
- Đối chiếu domain candidate với Application Domain Rules đã xác minh.
- Early-exit ngay khi DNS kết luận duy nhất một Application.

**Không làm**
- Không coi IP là định danh Application.
- Không suy ra Application từ CNAME/CDN provider domain nếu domain đó không có rule xác minh.
- Không chọn candidate theo thứ tự đến, TTL lớn nhất, domain mới nhất hoặc tần suất packet.
- Không gọi TLS/SNI hoặc ML bên trong DNS module.
- Không giải mã DoH/DoT/VPN tunnel; nếu DNS evidence không quan sát được thì DNS unresolved.

## 3. Ranh giới module

| Thành phần | Trách nhiệm | Không chịu trách nhiệm |
|---|---|---|
| DNS Parser | Parse DNS header, question, RCODE, answer; tạo DNS observations | Không lưu cache dài hạn; không map Application |
| DNS Cache | Lưu observation theo client/domain/IP/CNAME/TTL; expiry và lookup | Không quyết định Application |
| Application Domain Rules | Khai báo domain đã xác minh thuộc Application nào | Không học domain tự động từ traffic |
| DNS Application Identifier | Lấy candidate từ cache, match rules, xử lý ambiguity, trả status/evidence | Không parse packet; không gọi SNI/ML |
| Runtime Orchestrator | Gọi DNS trước; DNS unresolved mới gọi SNI; SNI unresolved mới gọi ML | Không bỏ qua thứ tự kiến trúc |

## 4. DNS observation và cache model

Một DNS observation logic tối thiểu giữ:

- `session_id`, `observed_at`, `packet_index`.
- `client_ip` nếu xác định được; nếu không xác định thì scope là unknown và không được dùng để kết luận cho một client cụ thể.
- `transaction_id`, `transport`, query/response endpoints để correlation khi có.
- `query_name`, `query_type`, `response_code`, `is_response`.
- Answer records: `owner_name`, `record_type`, `value`, `ttl_seconds`.

Một cache binding logic giữ:

- `client_ip`, `queried_domain` (QNAME gốc), `resolved_ip` (A/AAAA), `cname_chain`.
- `record_expiry` / `binding_expiry` và `observed_at`.
- `session_id` hoặc capture scope để tránh trộn evidence giữa các session không liên quan.

Cache key không được chỉ là IP. Lookup phải giới hạn theo client scope; nếu client không xác định hoặc chỉ có global/unscoped observation thì không dùng observation đó làm bằng chứng đủ để DNS-identify một Flow cụ thể.

## 5. Parse và cập nhật cache

1. Chỉ DNS Response (`QR=1`) mới có thể tạo positive mapping.
2. DNS Query (`QR=0`) có thể được giữ tạm để correlation, nhưng không tạo Domain↔IP mapping.
3. Correlate response với query bằng transaction ID và endpoint/transport tuple khi query đã được quan sát; `client_ip` lấy từ source IP của DNS Query gốc. Điều này đặc biệt quan trọng khi DNS resolver/router cũng nằm trong LAN subnet, khiến cả hai endpoint của DNS Flow đều thuộc LAN và Flow direction không đủ để suy ra client. Nếu capture bắt đầu giữa phiên và không có query, chỉ gán client scope khi response có đúng một endpoint thuộc selected LAN subnet và endpoint đó là destination/client; nếu không, observation không đủ điều kiện để nhận diện theo client.
4. Chỉ chấp nhận response thành công (`RCODE=NOERROR`) có Answer phù hợp. NXDOMAIN, SERVFAIL, REFUSED, malformed response hoặc Answer rỗng không tạo positive IP mapping.
5. Parse A và AAAA; hỗ trợ IPv4 và IPv6.
6. Parse CNAME theo owner-name → target-name; giữ QNAME gốc và toàn bộ alias chain. Chặn loop và giới hạn độ sâu theo cấu hình an toàn; chain lỗi không được dùng để tạo binding suy diễn.
7. Chỉ liên kết IP với QNAME khi có chuỗi record CNAME/A/AAAA liên tục, cùng response và cùng owner/target tương ứng. Không ghép các record rời rạc chỉ vì xuất hiện trong cùng packet.
8. Cache được cập nhật theo timestamp quan sát. Record TTL là thời hạn tối đa; TTL=0 không được giữ làm positive cache entry.

## 6. TTL và expiry

- Mỗi record có expiry riêng: `observed_at + ttl_seconds`.
- Binding qua CNAME chain chỉ còn hiệu lực đến thời điểm sớm nhất trong các record cần thiết để tạo binding (minimum expiry trên chain và terminal A/AAAA record).
- Lookup tại thời điểm `t` chỉ dùng binding nếu `t < expiry`; tại `t >= expiry`, binding đã hết hạn.
- Không tự đặt TTL mặc định thay cho TTL từ DNS response.
- Khi record được refresh, cập nhật binding theo observation mới; không kéo dài TTL của record cũ bằng một response không liên quan.
- PCAP replay dùng capture timestamp để expiry xác định và tái lập; live runtime dùng clock monotonic cho timer nội bộ nhưng vẫn giữ capture timestamp làm evidence/lineage.

## 7. Domain normalization và Application Domain Rules

Trước khi lưu hoặc match domain:
- chuyển về lowercase;
- bỏ dấu chấm cuối DNS (`trailing dot`);
- chuẩn hóa IDN về dạng ASCII/Punycode thống nhất;
- không so khớp bằng substring tùy tiện.

Application Domain Rules phải là danh sách domain đã xác minh, gắn rõ `application_id`. Hỗ trợ rule exact và suffix theo ranh giới label DNS (ví dụ `example.com` khớp `api.example.com`, nhưng không khớp `notexample.com`). Exact match ưu tiên hơn suffix; trong suffix match, rule cụ thể/ dài nhất ưu tiên. Nếu cùng mức ưu tiên có rule hợp lệ dẫn tới nhiều Application khác nhau thì domain match ambiguous.

Domain gốc được truy vấn và các tên trong CNAME chain đều là evidence candidates, nhưng mỗi tên phải tự match Application Domain Rules. Không mặc định CNAME target của CDN là Application domain. Nếu domain gốc match Application A nhưng CNAME chung không có rule thì giữ A; nếu nhiều candidate đã xác minh dẫn tới nhiều Application khác nhau và không có evidence phân biệt thì unresolved.

Ví dụ cấu hình rule (minh họa schema; domain thực tế phải được xác minh trước khi thêm):

```yaml
version: 1
applications:
  - application_id: app_alpha
    domains:
      - rule_id: alpha-primary
        domain: alpha.example
        match: suffix
      - rule_id: alpha-login-exact
        domain: login.identity.example
        match: exact
  - application_id: app_beta
    domains:
      - rule_id: beta-primary
        domain: beta.example
        match: suffix
```

`match: suffix` chỉ khớp chính domain và subdomain theo ranh giới label. Nếu `login.identity.example` có exact rule, rule exact được ưu tiên hơn một suffix rule rộng hơn. Không tự thêm rule chỉ vì domain xuất hiện trong DNS traffic; danh sách phải được curate/verify theo Application.


## 8. Quy tắc DNS Application Identification

Input tối thiểu: `session_id`, `flow_id`, `client_ip`, `destination_ip`, `flow_timestamp`.

Identifier thực hiện theo thứ tự:
1. Xác nhận Flow có client endpoint xác định. Nếu client role là `UNKNOWN`, DNS không được dùng client-scoped cache để kết luận.
2. Lookup DNS Cache bằng `client_ip + destination_ip` tại timestamp đánh giá.
3. Loại bỏ binding hết TTL hoặc sai session/scope.
4. Lấy toàn bộ domain candidate còn hiệu lực gắn với đúng client và destination IP.
5. Match từng candidate với Application Domain Rules.
6. Hợp nhất candidate theo Application ID:
   - Không có Application candidate hợp lệ → `DNS_UNRESOLVED`.
   - Tất cả candidate hợp lệ cùng dẫn đến đúng một Application ID → `DNS_IDENTIFIED`.
   - Candidate hợp lệ dẫn đến từ hai Application ID trở lên → `DNS_UNRESOLVED`.
7. Khi identified, trả Application ngay và ghi evidence domain, IP, client, TTL/expiry, rule ID và Flow ID. Không chờ packet thứ N và không gọi SNI/ML cho Flow đó.

**Không yêu cầu một Domain duy nhất nếu nhiều Domain candidate đều map tới cùng một Application.** Ngược lại, một IP có nhiều Domain thuộc nhiều Application khác nhau không thể được phân biệt chỉ bằng IP; phải unresolved và chuyển SNI.

## 9. Flow binding và packet N

- DNS Cache cập nhật liên tục độc lập với số packet của Flow.
- Tại lần đánh giá DNS đầu tiên khi Flow đủ metadata theo runtime trigger, Identifier tra cache và kết luận ngay nếu đủ điều kiện; không cần đếm N packet.
- Khi `DNS_IDENTIFIED`, gắn `application_id`, `method=dns` và evidence snapshot vào Flow result. Packet tiếp theo của cùng Flow tái sử dụng kết quả, không lookup DNS cache cho từng packet.
- TTL hết hạn không làm đổi ngược kết quả đã gắn cho Flow đang tồn tại; TTL chỉ ngăn binding cũ được dùng để identify Flow mới/lần đánh giá mới.
- Nếu DNS unresolved, Orchestrator chuyển sang SNI theo sơ đồ. Không được tự ý quay lại ghi đè một kết quả SNI/ML đã hoàn tất bằng DNS observation đến muộn.

Thời điểm Flow đủ điều kiện để phát prediction (số packet/thời gian quan sát) vẫn theo runtime policy và được quản lý riêng; DNS không đặt ngưỡng packet N.

## 10. Shared IP và các tình huống biên

| Tình huống | Hành vi |
|---|---|
| Một client, một IP, một domain đã xác minh → một app | `DNS_IDENTIFIED` |
| Nhiều domain candidate cùng client/IP, tất cả map cùng app | `DNS_IDENTIFIED`; giữ toàn bộ evidence candidates |
| Nhiều domain candidate cùng client/IP map nhiều app | `DNS_UNRESOLVED`; không chọn domain gần nhất/mới nhất |
| Nhiều client dùng chung IP | Cache tách theo client; không chia sẻ mapping giữa client |
| Không xác định được client | Không dùng làm bằng chứng DNS đủ để identify Flow |
| CNAME tới CDN/provider domain không có rule | Không suy app từ provider domain; dùng domain gốc nếu rule match |
| CNAME loop/chain đứt | Không tạo binding suy diễn từ chain lỗi |
| TTL=0 hoặc hết hạn | Không dùng để identify |
| NXDOMAIN/SERVFAIL/REFUSED/Answer rỗng | Không tạo positive mapping |
| DoH/DoT/VPN hoặc DNS không capture được | Cache miss/unresolved; tiếp tục SNI |
| Domain chưa có trong rules | `DNS_UNRESOLVED`; không tự học rule |
| DNS parser/cache lỗi hoặc không khả dụng | DNS unresolved; Orchestrator tiếp tục SNI |

## 11. Output contract

```json
{
  "session_id": "session-id",
  "flow_id": "flow-id",
  "status": "DNS_IDENTIFIED",
  "application_id": "chatgpt",
  "method": "dns",
  "reason_code": "DNS_CLIENT_IP_DOMAIN_MATCH",
  "evidence": {
    "client_ip": "192.168.1.10",
    "destination_ip": "203.0.113.10",
    "matched_domains": ["chatgpt.com"],
    "dns_record_types": ["A"],
    "rule_ids": ["chatgpt-primary-domain"],
    "expires_at": "2026-11-23T10:05:00Z"
  },
  "confidence": null
}
```

`DNS_UNRESOLVED` phải có reason code phù hợp, ví dụ `DNS_CACHE_MISS`, `DNS_CLIENT_UNKNOWN`, `DNS_TTL_EXPIRED`, `DNS_DOMAIN_UNMAPPED`, `DNS_SHARED_IP_AMBIGUOUS`, `DNS_INVALID_RESPONSE` hoặc `DNS_CACHE_UNAVAILABLE`. Rule-based DNS không tự tạo xác suất; `confidence` có thể null.

## 12. Acceptance criteria

- [ ] DNS Query không tạo positive IP mapping.
- [ ] DNS Response hợp lệ tạo observation; response lỗi không tạo positive mapping.
- [ ] Parse A, AAAA và giữ CNAME chain.
- [ ] TTL=0 không cache; TTL hết hạn lookup miss.
- [ ] CNAME binding expiry lấy minimum expiry của chain và terminal IP record.
- [ ] Cache lưu nhiều domain trên cùng IP.
- [ ] Client A không sử dụng mapping riêng của Client B.
- [ ] Domain normalization và exact/suffix rule matching có test ranh giới label, exact-vs-suffix precedence và conflicting-rule ambiguity.
- [ ] DNS response correlation lấy đúng client từ query source kể cả khi DNS resolver nằm trong LAN subnet.
- [ ] Nhiều domain cùng Application vẫn identified.
- [ ] Nhiều domain thuộc nhiều Application trên cùng client/IP trả shared-IP ambiguous.
- [ ] Domain CDN không có rule không tự map Application.
- [ ] DNS identified gắn kết quả vào Flow; packet tiếp theo reuse Flow result.
- [ ] DNS identified không gọi SNI/ML; DNS unresolved mới gọi SNI.
- [ ] Live và PCAP replay dùng cùng logic; replay deterministic theo capture timestamp.

## 13. Source layout mục tiêu cho P0.5

```text
src/appid/dns/
├── __init__.py
├── models.py       # DNS record/observation/cache binding/result types
├── parser.py       # DNS message parsing and response validation
├── cache.py        # client-scoped cache, CNAME chain and TTL expiry
├── domain_rules.py # normalized exact/suffix Application Domain Rules
└── identifier.py   # Flow lookup, ambiguity resolution, DNS result

config/
└── dns_mapping.yaml # verified Application Domain Rules
```

Đây là layout mục tiêu, không phải khẳng định source đã được tạo. Không đưa DNS implementation vào `common/` hoặc gộp Parser, Cache và Identifier thành một module không phân định trách nhiệm.

## Current source implementation — 2026-11-27

### Module name: DNS parser, cache and AppID

**Source files**
- `src/appid/dns/parser.py`
- `src/appid/dns/cache.py`
- `src/appid/dns/identifier.py`
- `src/appid/dns/domain_rules.py`
- `src/appid/dns/models.py`
- `config/dns_mapping.yaml`
- Integration: `src/appid/pipeline/processor.py`

**Implemented**
- Parser correlates query/response using session, transaction ID, transport, endpoint IPs and ports; pending query TTL defaults to 30 seconds.
- Extracts A, AAAA and CNAME answer records. Cache rejects missing client, nonzero response code, invalid/zero TTL, conflicting CNAME targets and loops; effective binding expiry uses the minimum TTL along the CNAME chain.
- Cache key is `(session_id, client_ip, resolved_ip)`, preserving separate clients/sessions and multiple queried domains per IP.
- Identifier maps cached domain candidates through approved suffix rules and rejects shared-IP ambiguity across multiple applications.

**Integrated**
PacketProcessor parses DNS observations from in-LAN packets and updates the cache. For each non-DNS application Flow, DNS lookup is attempted before SNI/QUIC. DNS match attaches `IdentificationResult(method=DNS)` and returns early. DNS transaction Flows (port 53) are not classified as application Flows.

**Tested**
`tests/unit/dns/` including parser, cache/identifier, domain rules, section flattening and PacketProcessor integration. Historical live DNS acceptance is documented in `docs/testing/dns-live-laptop-test.md` and related records. The separate ML live run in the handover recorded zero DNS bindings/identifications and is not DNS acceptance evidence.

**Status**
`DONE` for the implemented DNS-first path.

**Remaining**
Encrypted DNS is outside this parser; DNS visibility and shared-IP ambiguity can leave a Flow UNKNOWN. Do not generalize one successful acceptance run to all traffic.
