# Kiểm thử capture traffic thực tế trên đúng một NIC Linux

Mục tiêu của bài smoke test là chứng minh được cả ba việc, không chỉ thấy log capture:

1. Chương trình chọn đúng một NIC theo `config/network.json`.
2. Scapy chỉ mở capture trên NIC đó (`AsyncSniffer(iface=<selected NIC>)`).
3. Một UDP packet thử nghiệm được phát ra trên chính NIC đó, được capture lại, đi qua `PacketProcessor` và tạo ít nhất một Flow trong `FlowTracker`.

Bài test gửi UDP broadcast trong subnet của NIC đã chọn. Payload có marker ngẫu nhiên riêng cho lần chạy; callback chỉ chuyển packet mang marker này vào pipeline. Vì địa chỉ đích broadcast cũng thuộc subnet LAN, Direction của Flow thường là `UNKNOWN` (điều này không ảnh hưởng đến tiêu chí packet được track).

## 1. Cài đặt

Tại thư mục gốc repository:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## 2. Chọn đúng NIC

Mở `config/network.json`.

Tự động chọn NIC đầu tiên hợp lệ theo thứ tự hệ điều hành liệt kê:

```json
{
  "network": {
    "mode": "auto",
    "interface": null
  }
}
```

Hoặc chỉ định chính xác NIC, ví dụ `enp3s0` (thay bằng tên NIC thật trên máy):

```json
{
  "network": {
    "mode": "manual",
    "interface": "enp3s0"
  }
}
```

Xem tên NIC và địa chỉ:

```bash
ip -br address
ip link show
```

Khuyến nghị dùng `manual` trong lần kiểm thử đầu để biết chắc NIC nào đang được xác minh. NIC phải UP và có IPv4 hợp lệ. Bài smoke test này cần IPv4 để tạo broadcast; runtime capture chính vẫn có parser IPv4/IPv6.

## 3. Chạy smoke test thực tế

Chạy từ repository root:

```bash
sudo .venv/bin/python scripts/verify_live_nic.py --config config/network.json
```

Script thực hiện:

- Đọc config và gọi cùng `select_interface()` như live capture.
- Mở Scapy `AsyncSniffer` với đúng `iface` đã chọn, không dùng `iface=None`.
- Tạo UDP socket, bind vào IP đã chọn và dùng Linux `SO_BINDTODEVICE` để ràng buộc socket gửi vào cùng NIC.
- Gửi ba UDP broadcast có marker duy nhất.
- Chỉ khi packet có marker được thấy trên capture callback, packet mới được đưa vào `PacketProcessor.process()`.
- Kiểm tra `tracked_packets > 0` và Flow xuất hiện trong `FlowTracker`.
- In NIC, subnet, số packet, Flow ID và packet count.

Kết quả thành công có dạng:

```text
[PASS] Real NIC capture reached FlowTracker
interface: enp3s0
local_address: 192.168.1.20
subnet: 192.168.1.0/24
marker_frames_seen_on_selected_nic: 3
tracked_packets: 3
flow_count: 1
flow_ids: ['nic-smoke-...:flow-000001']
flow_packet_counts: [3]
```

Các số liệu trên chỉ là ví dụ; kết quả thực tế phụ thuộc máy và NIC.

## 4. Chạy qua pytest (opt-in)

Test thực tế mặc định bị skip để CI/máy developer không tự ý mở capture hoặc cần quyền root. Bật rõ ràng bằng biến môi trường:

```bash
sudo env APPID_RUN_LIVE_NIC_TEST=1 .venv/bin/pytest -q tests/integration/test_live_nic_linux.py
```

## 5. Chứng minh chỉ một NIC được sử dụng

- Trong code live, `sniff()` nhận `iface=self.interface.name`.
- Trong smoke test, `AsyncSniffer()` cũng nhận đúng một `iface`.
- Socket phát packet được bind vào interface đó bằng `SO_BINDTODEVICE` và source IP của interface đó.
- Không có vòng lặp capture qua danh sách NIC.

Có thể quan sát thêm bằng lệnh sau trong terminal khác, thay `enp3s0` bằng NIC đã chọn:

```bash
sudo tcpdump -ni enp3s0 'udp dst port 49091'
```

Không chạy tcpdump trên `any`, vì mục tiêu là kiểm tra một NIC cụ thể.

## 6. Nếu test thất bại

| Lỗi/hiện tượng | Kiểm tra |
|---|---|
| Permission denied | Chạy bằng `sudo`; kiểm tra quyền raw packet/capture |
| NIC không tồn tại | Kiểm tra `ip -br address` và tên trong config |
| NIC DOWN hoặc không có IPv4 | `sudo ip link set <nic> up`; kiểm tra DHCP/IP trước khi test |
| Không thấy marker packet | Kiểm tra driver/VM/container có cho capture outgoing broadcast không; thử NIC vật lý khác |
| `tracked_packets=0` | Xem subnet và địa chỉ source; packet broadcast phải thuộc subnet được chọn |
| NIC manual sai | Script phải fail; không fallback sang NIC khác |

Lưu ý: smoke test này xác minh đường đi packet do máy local phát ra và capture lại trên NIC đã chọn. Nó không chứng minh mọi inbound/unicast traffic đều được thấy, cũng không đo packet loss/throughput. Muốn kiểm tra inbound thực tế, chạy traffic từ một máy khác trong cùng LAN tới máy đang capture và đối chiếu log/Flow ID.

## 7. Tiêu chí nghiệm thu

- [ ] Log cho biết đúng một interface được chọn.
- [ ] Capture được bind vào đúng interface đó.
- [ ] Marker packet được quan sát trên interface đã chọn.
- [ ] `PacketProcessor.stats.tracked_packets` lớn hơn 0.
- [ ] `FlowTracker.flows` có ít nhất một Flow và Flow ID.
- [ ] Chế độ manual với NIC sai phải fail, không tự đổi NIC.
- [ ] Thực hiện thêm inbound test từ máy khác nếu cần nghiệm thu traffic hai chiều.
