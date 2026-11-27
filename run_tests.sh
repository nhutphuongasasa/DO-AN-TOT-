#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
PYTHON="$ROOT/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  echo "[ERROR] Chưa có môi trường .venv. Hãy chạy ./setup_linux.sh trước." >&2
  exit 2
fi
exec "$PYTHON" -m pytest -q "$@"
