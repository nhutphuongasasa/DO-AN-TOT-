#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PYTHON="$ROOT/.venv/bin/python"
else
  PYTHON="$(command -v python3 || true)"
fi
if [[ -z "$PYTHON" ]]; then
  echo "ERROR: python3 not found. Run ./setup_linux.sh first." >&2
  exit 2
fi
exec "$PYTHON" "$ROOT/scripts/generate_quic_test_traffic.py" "$@"
