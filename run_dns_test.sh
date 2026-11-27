#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
VENV="$ROOT/.venv"
PYTHON="${PYTHON:-python3}"

echo "=== Hybrid AppID | DNS laptop test ==="
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "[ERROR] Không tìm thấy $PYTHON. Hãy cài Python 3.10+." >&2
  exit 2
fi
if [[ ! -x "$VENV/bin/python" ]]; then
  echo "[SETUP] Tạo môi trường Python..."
  "$PYTHON" -m venv "$VENV"
fi
if ! "$VENV/bin/python" -c 'import scapy, yaml, psutil, pytest' >/dev/null 2>&1; then
  echo "[SETUP] Cài dependencies (chỉ cần ở lần chạy đầu)..."
  "$VENV/bin/python" -m pip install --upgrade pip
  "$VENV/bin/python" -m pip install -e '.[dev]'
fi
if ! "$VENV/bin/python" -c 'import appid' >/dev/null 2>&1; then
  "$VENV/bin/python" -m pip install -e .
fi

echo
echo "[CHECK] Chạy DNS acceptance scenarios (không cần mạng)..."
"$VENV/bin/python" "$ROOT/scripts/test_dns_scenarios.py" --config "$ROOT/config/dns_mapping.yaml"
echo
echo "[CHECK] Chạy unit tests..."
"$VENV/bin/python" -m pytest -q

echo
echo "[INFO] Các card mạng đang hoạt động:"
ip -br addr 2>/dev/null || true
echo
if [[ "${EUID}" -ne 0 ]]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "[ERROR] Cần quyền root để capture. Hãy chạy bằng tài khoản có sudo." >&2
    exit 3
  fi
  echo "[PERMISSION] Cần quyền capture mạng; sẽ yêu cầu mật khẩu sudo."
  exec sudo "$VENV/bin/python" "$ROOT/scripts/test_dns_live.py" --config "$ROOT/config/network.json" "$@"
fi
exec "$VENV/bin/python" "$ROOT/scripts/test_dns_live.py" --config "$ROOT/config/network.json" "$@"
