#!/usr/bin/env bash
# Capture five forced-HTTP/1.1 probes, then replay the PCAP through PacketProcessor.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

IFACE="${1:-}"
if [[ -z "$IFACE" ]]; then
  echo "Usage: $0 <interface> [pcap-path]" >&2
  exit 2
fi
PCAP_INPUT="${2:-p075-tcp-five-apps.pcap}"
if [[ "$PCAP_INPUT" = /* ]]; then
  PCAP="$PCAP_INPUT"
else
  PCAP="$ROOT/$PCAP_INPUT"
fi
REPORT_INPUT="${PCAP_INPUT%.*}-traffic-report.tsv"
if [[ "$REPORT_INPUT" = /* ]]; then REPORT="$REPORT_INPUT"; else REPORT="$ROOT/$REPORT_INPUT"; fi
CAPTURE_MAX_SECONDS="${CAPTURE_MAX_SECONDS:-180}"

for tool in dumpcap curl ip; do
  command -v "$tool" >/dev/null 2>&1 || { echo "[ERROR] Missing required command: $tool" >&2; exit 2; }
done
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[ERROR] Run the complete capture script with sudo: sudo $0 $IFACE [pcap-path]" >&2
  exit 2
fi
if ! [[ "$CAPTURE_MAX_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
  echo "[ERROR] CAPTURE_MAX_SECONDS must be a positive integer." >&2
  exit 2
fi

LAN_CIDR="$(ip -o -f inet addr show dev "$IFACE" | awk 'NR==1 {print $4}')"
if [[ -z "$LAN_CIDR" ]]; then
  echo "[ERROR] Could not determine IPv4 subnet on interface $IFACE." >&2
  exit 2
fi

# Keep the in-progress capture outside the project tree. The private temporary
# directory makes the filename unique and keeps dumpcap's output isolated.
CAPTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/p075-tcp-capture-$$.XXXXXX")"
TEMP_PCAP="$CAPTURE_DIR/capture.pcap"
CAPTURE_LOG="$CAPTURE_DIR/dumpcap.log"
CAP_PID=''
CAP_STATUS=0

stop_capture() {
  if [[ -n "$CAP_PID" ]]; then
    # SIGINT asks dumpcap to flush and close its PCAP cleanly. Always wait so
    # no capture process is left behind when this script returns.
    if kill -0 "$CAP_PID" 2>/dev/null; then
      kill -INT "$CAP_PID" 2>/dev/null || true
    fi
    if wait "$CAP_PID"; then CAP_STATUS=0; else CAP_STATUS=$?; fi
    CAP_PID=''
  fi
}

cleanup() {
  local original_status=$?
  trap - EXIT INT TERM
  stop_capture || true
  if [[ -n "${CAPTURE_DIR:-}" && -d "$CAPTURE_DIR" ]]; then
    rm -rf -- "$CAPTURE_DIR"
  fi
  exit "$original_status"
}
on_signal() { exit "$1"; }
trap cleanup EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

mkdir -p -- "$(dirname -- "$PCAP")" "$(dirname -- "$REPORT")"
echo "[INFO] Capturing TCP/443 on $IFACE (hard limit: ${CAPTURE_MAX_SECONDS}s)."
echo "[INFO] Temporary PCAP: $TEMP_PCAP"
dumpcap -q -i "$IFACE" -f 'tcp port 443' -s 0 \
  -a "duration:${CAPTURE_MAX_SECONDS}" -w "$TEMP_PCAP" >"$CAPTURE_LOG" 2>&1 &
CAP_PID=$!
sleep 2
if ! kill -0 "$CAP_PID" 2>/dev/null; then
  if wait "$CAP_PID"; then CAP_STATUS=0; else CAP_STATUS=$?; fi
  CAP_PID=''
  cat "$CAPTURE_LOG" >&2
  echo "[ERROR] dumpcap did not remain running after startup (status $CAP_STATUS)." >&2
  exit 1
fi

"$ROOT/scripts/generate_tcp_test_traffic.sh" "$REPORT"
sleep 2
stop_capture
if [[ "$CAP_STATUS" -ne 0 ]]; then
  cat "$CAPTURE_LOG" >&2
  echo "[ERROR] dumpcap exited with status $CAP_STATUS." >&2
  exit "$CAP_STATUS"
fi
cat "$CAPTURE_LOG"

# Never publish a partial/empty capture. Move only after dumpcap has exited.
if [[ ! -f "$TEMP_PCAP" || ! -s "$TEMP_PCAP" ]]; then
  echo "[ERROR] Temporary capture is missing or empty: $TEMP_PCAP" >&2
  exit 1
fi
mv -f -- "$TEMP_PCAP" "$PCAP"
chmod 0644 "$PCAP"
if [[ ! -s "$PCAP" ]]; then
  echo "[ERROR] Final capture is missing or empty: $PCAP" >&2
  exit 1
fi
echo "[INFO] PCAP finalized after dumpcap exit: $PCAP ($(stat -c '%s bytes' "$PCAP")); mode=$(stat -c '%a' "$PCAP")."

if command -v tshark >/dev/null 2>&1; then
  printf '\n=== TCP TLS SNI observed in PCAP (tshark) ===\n'
  tshark -r "$PCAP" -Y 'tcp && tls.handshake.extensions_server_name' \
    -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
    -e tls.handshake.extensions_server_name | sort -u
else
  echo "[INFO] tshark not installed; PacketProcessor replay remains the AppID check."
fi

printf '\n=== Strict PacketProcessor TCP/SNI acceptance ===\n'
PYTHON="$ROOT/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then PYTHON="$(command -v python3 || true)"; fi
if [[ -z "$PYTHON" || ! -x "$PYTHON" ]]; then
  echo "[ERROR] Python interpreter not found." >&2
  exit 2
fi
LAN_SUBNET="$("$PYTHON" -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$LAN_CIDR")"
PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON" \
  "$ROOT/scripts/verify_tcp_appid_acceptance.py" \
  "$PCAP" --lan-subnet "$LAN_SUBNET" --report "$REPORT"
