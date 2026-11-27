#!/usr/bin/env bash
# Generate HTTPS requests explicitly over TCP using HTTP/1.1 (never HTTP/3).
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v curl >/dev/null 2>&1; then
  echo "[ERROR] curl is required." >&2
  exit 2
fi
if ! curl --help all 2>/dev/null | grep -q -- '--http1.1'; then
  echo "[ERROR] Installed curl does not expose --http1.1." >&2
  exit 2
fi

OUT="${1:-tcp-traffic-report.tsv}"
: > "$OUT"
printf 'app\texpected_sni\thttp_status\tcurl_exit\tresult\n' >> "$OUT"

declare -a APPS=(chatgpt facebook tiktok youtube spotify)
declare -a HOSTS=(chatgpt.com www.facebook.com www.tiktok.com www.youtube.com open.spotify.com)
declare -a URLS=(https://chatgpt.com/ https://www.facebook.com/ https://www.tiktok.com/ https://www.youtube.com/ https://open.spotify.com/)

printf '%-10s %-28s %s\n' APP EXPECTED_SNI RESULT
for i in "${!APPS[@]}"; do
  status_file="$(mktemp)"
  set +e
  curl --http1.1 --noproxy '*' -sS -o /dev/null \
    --connect-timeout 10 --max-time 30 --max-redirs 0 \
    -w '%{http_code}' "${URLS[$i]}" >"$status_file"
  curl_exit=$?
  set -e
  status="$(cat "$status_file")"
  rm -f "$status_file"
  [[ -n "$status" ]] || status='000'
  if [[ "$curl_exit" -eq 0 ]]; then result='TCP_HTTP1_REQUEST_COMPLETED'; else result='TCP_REQUEST_FAILED'; fi
  printf '%s\t%s\t%s\t%s\t%s\n' "${APPS[$i]}" "${HOSTS[$i]}" "$status" "$curl_exit" "$result" >> "$OUT"
  printf '%-10s %-28s HTTP=%s curl_exit=%s %s\n' "${APPS[$i]}" "${HOSTS[$i]}" "$status" "$curl_exit" "$result"
done

printf '\nReport: %s\n' "$OUT"
printf 'Transport forced by curl --http1.1; --noproxy prevents an HTTPS proxy from hiding the target SNI.\n'
printf 'A completed HTTP request is not itself proof of AppID; inspect the PCAP and replay it.\n'
