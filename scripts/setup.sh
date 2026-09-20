#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "[setup] Project: $ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[setup] ERROR: python3 is required." >&2
  exit 1
fi

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest -q

echo
echo "[setup] Python environment ready."
echo "[setup] Zeek will be checked/installed automatically by app.py."
echo "[setup] Start with:"
echo "        source .venv/bin/activate"
echo "        sudo -E .venv/bin/python app.py"
