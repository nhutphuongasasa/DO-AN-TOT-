#!/usr/bin/env bash
set -u

echo '=== Hybrid AppID | Generate DNS test traffic ==='

# Bypass systemd-resolved's loopback stub (127.0.0.53) so DNS packets
# traverse the selected physical LAN interface and can be captured.
DNS_SERVER="${DNS_SERVER:-$(ip route 2>/dev/null | awk '$1 == "default" { for (i=1; i<=NF; i++) if ($i == "via") { print $(i+1); exit } }')}"
if [[ -z "$DNS_SERVER" ]]; then
  DNS_SERVER="$(awk '/^nameserver/ && $2 !~ /^127\./ && $2 != "::1" {print $2; exit}' /etc/resolv.conf 2>/dev/null || true)"
fi
if [[ -n "$DNS_SERVER" ]]; then
  echo "[INFO] DNS server trực tiếp: $DNS_SERVER (bỏ qua resolver stub 127.0.0.53)"
else
  echo '[WARNING] Không tìm thấy DNS server trực tiếp; nslookup sẽ dùng resolver mặc định.'
fi
if ! command -v nslookup >/dev/null 2>&1; then
  echo '[ERROR] Cần nslookup (Ubuntu/Debian: sudo apt install dnsutils)'
  exit 2
fi

probe() {
  local label="$1" host="$2"
  echo
  echo "--- $label : $host ---"
  if [[ -n "$DNS_SERVER" ]]; then nslookup "$host" "$DNS_SERVER" || true; else nslookup "$host" || true; fi
  if command -v curl >/dev/null 2>&1; then
    curl -I -L --max-time 12 --connect-timeout 5 "https://$host" -o /dev/null -sS \
      -w "HTTP %{http_code} | remote=%{remote_ip}\n" || true
  fi
}

probe 'ChatGPT' 'chatgpt.com'
probe 'Facebook' 'www.facebook.com'
probe 'TikTok' 'www.tiktok.com'
probe 'YouTube' 'www.youtube.com'
probe 'Spotify' 'open.spotify.com'
echo
 echo '[DONE] Đã phát sinh DNS lookup và HTTPS request cho 5 ứng dụng.'
echo 'Lưu ý: curl có thể dùng cache DNS; nslookup được gửi trực tiếp tới DNS server đã chọn để capture trên NIC.'
echo 'Nếu DNS server không phản hồi trực tiếp, hãy chạy: DNS_SERVER=<IP-router-DNS> ./generate_dns_test_traffic.sh'
