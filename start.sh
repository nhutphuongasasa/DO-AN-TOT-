#!/usr/bin/env bash
# One-command setup, verification and automated test entry point.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

RUN_SETUP=1
RUN_LIVE=0
for arg in "$@"; do
  case "$arg" in
    --no-setup) RUN_SETUP=0 ;;
    --live) RUN_LIVE=1 ;;
    -h|--help)
      cat <<'HELP'
Hybrid AppID – one-command bootstrap and validation

Usage:
  ./start.sh                 Setup dependencies, then run all safe tests
  ./start.sh --no-setup      Reuse the existing .venv and run tests
  ./start.sh --live          Setup, run all tests, then opt-in live-NIC test
  ./start.sh --no-setup --live

The live-NIC test is opt-in. It requires sudo/root and a suitable interface
configured in config/network.json. Normal test runs do not capture live traffic.
Logs are written to logs/start-<timestamp>.log.
HELP
      exit 0
      ;;
    *) echo "[ERROR] Tham số không được hỗ trợ: $arg" >&2; exit 2 ;;
  esac
done

mkdir -p "$ROOT/logs"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_FILE="$ROOT/logs/start-${STAMP}.log"
exec > >(tee -a "$LOG_FILE") 2>&1

log() { printf '\n[%s] %s\n' "$1" "$2"; }
die() { log ERROR "$1"; exit 1; }

log START "Hybrid AppID validation started"
log INFO "Log file: ${LOG_FILE#$ROOT/}"

if [[ "$RUN_SETUP" -eq 1 ]]; then
  log SETUP "Installing system/project dependencies and preparing .venv"
  "$ROOT/setup_linux.sh"
else
  log SETUP "Skipped by --no-setup"
fi

PYTHON="$ROOT/.venv/bin/python"
[[ -x "$PYTHON" ]] || die "Không tìm thấy .venv/bin/python. Hãy bỏ --no-setup hoặc chạy setup_linux.sh."

log VERIFY "Checking required runtime modules"
"$PYTHON" - <<'PY'
import importlib
import sys
modules = ("scapy", "yaml", "psutil", "cryptography", "aioquic", "pytest")
missing = []
for name in modules:
    try:
        module = importlib.import_module(name)
        print(f"  {name}: {getattr(module, '__version__', 'available')}")
    except Exception as exc:
        missing.append(f"{name}: {exc}")
if missing:
    print("Missing modules:", *missing, sep="\n  ", file=sys.stderr)
    raise SystemExit(1)
PY

log COMPILE "Compiling Python source and tests"
"$PYTHON" -m compileall -q src tests

log LINT "Checking changed ML feature modules with Ruff"
if "$PYTHON" -m ruff --version >/dev/null 2>&1; then
  "$PYTHON" -m ruff check \
    src/appid/ml/burst_statistics.py \
    src/appid/ml/sequence.py \
    src/appid/ml/schemas.py \
    src/appid/ml/feature_extraction.py \
    tests/unit/ml/test_burst_statistics.py \
    tests/unit/ml/test_burst_sequence.py \
    tests/unit/ml/test_feature_extraction.py
else
  log WARN "Ruff is not installed; lint check skipped"
fi

log TEST "Running complete automated test suite (unit + integration + PCAP where dependencies permit)"
"$PYTHON" -m pytest -q -rs

if [[ "$RUN_LIVE" -eq 1 ]]; then
  log LIVE "Running explicitly requested live-NIC acceptance test"
  if [[ "$EUID" -eq 0 ]]; then
    APPID_RUN_LIVE_NIC_TEST=1 "$PYTHON" -m pytest -q -rs tests/integration/test_live_nic_linux.py
  elif command -v sudo >/dev/null 2>&1; then
    sudo env APPID_RUN_LIVE_NIC_TEST=1 "$PYTHON" -m pytest -q -rs tests/integration/test_live_nic_linux.py
  else
    die "Live-NIC test requires sudo/root; install sudo or run the live phase as root."
  fi
else
  log LIVE "Skipped (opt-in only). Use ./start.sh --live when ready to capture on the configured NIC."
fi

log DONE "All requested setup and validation steps completed successfully."
log INFO "Full output saved to ${LOG_FILE#$ROOT/}"
