#!/usr/bin/env bash
# Prepare a reproducible Python environment for Hybrid AppID on Debian/Ubuntu.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

log() { printf '\n[%s] %s\n' "$1" "$2"; }
die() { printf '\n[ERROR] %s\n' "$1" >&2; exit 1; }

if [[ "$(uname -s)" != "Linux" ]]; then
  die "Script này dành cho Linux (Debian/Ubuntu)."
fi

if ! command -v apt-get >/dev/null 2>&1; then
  die "Chưa hỗ trợ trình quản lý gói này. Script hiện hỗ trợ Ubuntu/Debian dùng apt."
fi

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=()
elif command -v sudo >/dev/null 2>&1; then
  SUDO=(sudo)
else
  die "Cần sudo hoặc chạy script bằng tài khoản root để cài các gói hệ thống."
fi

log SYSTEM "Cài Python 3, venv, pip và thư viện build/capture cần thiết..."
"${SUDO[@]}" apt-get update
DEBIAN_FRONTEND=noninteractive "${SUDO[@]}" apt-get install -y \
  python3 python3-venv python3-pip build-essential libpcap-dev

PYTHON="$(command -v python3 || true)"
[[ -n "$PYTHON" ]] || die "Không tìm thấy python3 sau khi cài đặt."

PY_VERSION="$($PYTHON -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
  die "Project yêu cầu Python >= 3.10; hệ thống hiện có Python $PY_VERSION. Hãy nâng cấp Python trước."
fi

log VENV "Tạo môi trường ảo tại $ROOT/.venv ..."
if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  "$PYTHON" -m venv "$ROOT/.venv"
fi
VENV_PY="$ROOT/.venv/bin/python"

log PIP "Nâng cấp pip/setuptools/wheel trong môi trường ảo..."
"$VENV_PY" -m pip install --upgrade pip setuptools wheel

log PROJECT "Cài project cùng dependencies và công cụ test..."
"$VENV_PY" -m pip install -e '.[dev]'

log VERIFY "Kiểm tra Python và các thư viện bắt buộc..."
"$VENV_PY" - <<'PY'
import sys
import scapy
import yaml
import psutil
import pytest
import cryptography
import aioquic
print(f"Python : {sys.version.split()[0]}")
print(f"Scapy  : {scapy.__version__}")
print(f"PyYAML : {yaml.__version__}")
print(f"psutil : {psutil.__version__}")
print(f"pytest : {pytest.__version__}")
print(f"crypto : {cryptography.__version__}")
print(f"aioquic : {aioquic.__version__}")
PY

log DONE "Môi trường đã sẵn sàng. Không cần gõ lệnh python (không có trên một số Ubuntu)."
printf '\nCác lệnh sử dụng tiếp theo:\n'
printf '  ./run_tests.sh                         # chạy toàn bộ unit tests\n'
printf '  ./run_dns_test.sh --interface <NIC>   # DNS acceptance + live capture\n'
printf '  .venv/bin/python -m appid.capture.live --config config/network.json\n'
printf '\nCó thể kích hoạt môi trường bằng:\n'
printf '  source .venv/bin/activate\n'
printf 'Sau đó dùng python3 hoặc python; hoặc luôn gọi .venv/bin/python.\n'
