# Hướng Dẫn Cấu Hình Raspberry Pi Làm Gateway

## Mục Tiêu

Pi cần làm **gateway WiFi** cho thiết bị thử: Pi phát WiFi riêng, các thiết bị kết nối vào Pi, Pi chuyển traffic lên uplink (WiFi trường / Ethernet / 4G USB).

```
[Internet]
    │ uplink: WiFi trường (USB WiFi adapter) hoặc Ethernet hoặc 4G USB modem
    │
[Raspberry Pi 4]  ← tcpdump capture tại đây
    │ phát WiFi LAN: wlan0 (card WiFi tích hợp)
    │ SSID: "TestNet-Lab"
    │
[Thiết bị thử: Android, iPhone, Windows...]
```

---

## Phần Cứng Cần Chuẩn Bị

| Kịch bản uplink | Phần cứng cần thêm |
|---|---|
| Ethernet (lab/phòng máy) | Cáp LAN RJ45 → đơn giản nhất |
| WiFi trường | **USB WiFi adapter** (Realtek RTL8812AU hoặc Ralink MT7601U) |
| 4G (đợt ngoài trời) | USB 4G modem hoặc tethering USB từ điện thoại phụ |

> **Lưu ý:** Pi 4 chỉ có 1 card WiFi tích hợp. Vừa phát WiFi vừa nhận WiFi trường **cần 2 card WiFi**.

---

## Bước 1 — Cài Đặt Phần Mềm

```bash
sudo apt update && sudo apt install -y \
    hostapd dnsmasq iptables-persistent \
    tcpdump ethtool ntp \
    python3 python3-pip

# Cho USB WiFi adapter (nếu dùng):
sudo apt install -y firmware-realtek  # hoặc firmware-ralink
```

---

## Bước 2 — Cấu Hình Pi Phát WiFi (hostapd)

```bash
# Xác định interface:
# - wlan0: card WiFi tích hợp Pi → dùng làm AP (phát WiFi cho thiết bị thử)
# - wlan1: USB WiFi adapter → uplink WiFi trường  (hoặc eth0 nếu dùng Ethernet)
ip -br link show

# Gán IP tĩnh cho wlan0 (LAN của Pi):
sudo nano /etc/network/interfaces.d/wlan0-static
```

```
auto wlan0
iface wlan0 inet static
    address 192.168.4.1
    netmask 255.255.255.0
```

```bash
# Cấu hình hostapd:
sudo nano /etc/hostapd/hostapd.conf
```

```
interface=wlan0
driver=nl80211
ssid=TestNet-Lab
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=testlab2024
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
```

```bash
sudo nano /etc/default/hostapd
# Thêm dòng:
DAEMON_CONF="/etc/hostapd/hostapd.conf"

sudo systemctl unmask hostapd
sudo systemctl enable hostapd
sudo systemctl start hostapd
```

---

## Bước 3 — Cấu Hình DHCP (dnsmasq)

```bash
sudo nano /etc/dnsmasq.conf
```

```
interface=wlan0
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
dhcp-option=3,192.168.4.1    # default gateway = Pi
dhcp-option=6,8.8.8.8        # DNS = Google
# Ghi log DHCP lease để biết IP của từng thiết bị:
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
log-dhcp
```

```bash
sudo systemctl enable dnsmasq
sudo systemctl restart dnsmasq
```

---

## Bước 4 — NAT và IP Forwarding

```bash
# Bật IP forwarding:
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# NAT (thay eth0 bằng tên uplink thực tế: eth0, wlan1, usb0...):
UPLINK="eth0"   # ← SỬA ở đây

sudo iptables -t nat -A POSTROUTING -o $UPLINK -j MASQUERADE
sudo iptables -A FORWARD -i wlan0 -o $UPLINK -j ACCEPT
sudo iptables -A FORWARD -i $UPLINK -o wlan0 -m state \
    --state RELATED,ESTABLISHED -j ACCEPT

# Lưu để tự động load sau reboot:
sudo netfilter-persistent save
```

---

## Bước 5 — Tắt Offload (PHẢI Làm Trước Mỗi Lần Thu)

```bash
# Nếu không tắt, tcpdump thấy "gói" lớn hơn MTU do hardware offload gộp
# → đặc trưng kích thước gói bị sai hoàn toàn

sudo ethtool -K wlan0 gro off gso off tso off
sudo ethtool -K eth0  gro off gso off tso off  # nếu dùng Ethernet uplink

# Kiểm tra: không nên thấy gói > 1500 bytes
sudo tcpdump -i wlan0 -c 20 'ip' | grep -E "length [0-9]+"
```

> **Script `capture_session.py` tự động tắt offload khi khởi động.**

---

## Bước 6 — Đồng Bộ Giờ (PHẢI Kiểm Tra Trước Mỗi Đợt)

```bash
# Pi 4 không có RTC pin — mất điện là mất giờ
# Đảm bảo Pi kết nối được internet trước khi thu

timedatectl status          # Kiểm tra NTPSynchronized
sudo ntpdate pool.ntp.org   # Đồng bộ thủ công nếu cần
date                        # Xác nhận giờ đúng

# Script capture_session.py tự kiểm tra và cảnh báo nếu NTP chưa sync
```

---

## Bước 7 — Chạy Thu Thử (Dry Run)

```bash
# Clone project lên Pi (hoặc copy qua scp):
scp -r "DO AN TOT NGHIEP/" pi@<PI_IP>:~/thesis/

# SSH vào Pi:
ssh pi@<PI_IP>
cd ~/thesis

# Cài dependency:
pip3 install scapy pyyaml rich

# Chạy dry run (5 phút/app, kiểm tra toàn bộ pipeline):
sudo python3 tools/capture_session.py \
    --batch dryrun \
    --iface wlan0 \
    --dry-run \
    --shuffle

# Sau khi xong, kiểm tra output:
ls -lh captures/dryrun/
# Phải thấy: capture_dryrun_*.pcap, labels_dryrun_*.jsonl, session_dryrun_*.json

# Kiểm tra kích thước gói (không nên > 1500 bytes):
tcpdump -r captures/dryrun/capture_dryrun_*.pcap -nn | \
    awk '{print $NF}' | sort -rn | head -5
```

---

## Bước 8 — Thu Thật (Sau Khi Dry Run Thành Công)

```bash
# Đợt 1: Android + WiFi nhà, shuffle thứ tự app, lọc IP thiết bị
sudo python3 tools/capture_session.py \
    --batch batch1_android_wifi \
    --iface wlan0 \
    --dur 30 \
    --shuffle \
    --filter "host 192.168.4.2"  # IP của Android trong mạng Pi

# Đợt 4G: USB modem làm uplink
UPLINK="usb0"  # Tên interface của USB 4G modem
sudo iptables -t nat -A POSTROUTING -o $UPLINK -j MASQUERADE
sudo python3 tools/capture_session.py \
    --batch batch5_iphone_4g \
    --iface wlan0 \
    --dur 30 \
    --shuffle \
    --filter "host 192.168.4.3"  # IP của iPhone
```

---

## Checklist Trước Mỗi Đợt Thu

```
□ Đồng bộ NTP (tự động trong script, nhưng kiểm tra thủ công nếu nghi ngờ)
□ Tắt offload: ethtool -K wlan0 gro off gso off tso off (script tự làm)
□ Xác nhận uplink internet hoạt động (ping 8.8.8.8 từ Pi)
□ Thiết bị thử đã kết nối vào "TestNet-Lab" và có internet
□ Đã lên kế hoạch other-update (App Store/Play Store cập nhật)
□ Đã nhờ người thứ hai cho phiên Meet (nếu thu Meet)
□ Ghi chú ChatGPT: dùng web hay app native?
□ Thứ tự app đã shuffle khác với đợt trước
□ Đổi video YouTube và chất lượng khác đợt trước
```

---

## Đọc PCAP — Dùng wirelen Không Phải len

```python
from scapy.all import rdpcap
from scapy.layers.inet import IP

pkts = rdpcap("capture_batch1.pcap")
for pkt in pkts:
    if IP in pkt:
        # wirelen = kích thước gói gốc trên dây (trước khi tcpdump cắt -s 128)
        original_size = pkt.wirelen        # ← ĐÚNG
        captured_size = len(pkt)           # ← SAI (bị cắt còn 128 byte)
        print(f"Original: {original_size}, Captured: {captured_size}")
```

---

## Xem DHCP Lease (Biết IP Của Thiết Bị Nào)

```bash
cat /var/lib/misc/dnsmasq.leases
# Output: <expiry> <mac> <ip> <hostname> <client-id>
# Ví dụ:
# 1728820800 aa:bb:cc:dd:ee:01 192.168.4.2 android-phuong *
# 1728820800 11:22:33:44:55:66 192.168.4.3 iPhone-B *
```
