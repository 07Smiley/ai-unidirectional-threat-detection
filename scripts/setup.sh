#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MIN_PY_MAJOR=3
MIN_PY_MINOR=10

echo "[setup] Project: $ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[setup] ERROR: python3 is required." >&2
  exit 1
fi

if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= ($MIN_PY_MAJOR, $MIN_PY_MINOR) else 1)"; then
  echo "[setup] ERROR: Python >= $MIN_PY_MAJOR.$MIN_PY_MINOR is required (found $(python3 --version 2>&1))." >&2
  exit 1
fi

if [ ! -f requirements.txt ]; then
  echo "[setup] ERROR: requirements.txt not found in $ROOT." >&2
  exit 1
fi

# Recreate a broken venv (e.g. interrupted earlier run) instead of reusing it.
if [ -d .venv ] && [ ! -x .venv/bin/python ]; then
  echo "[setup] Removing broken .venv"
  rm -rf .venv
fi

if [ ! -d .venv ]; then
  if ! python3 -m venv .venv; then
    echo "[setup] ERROR: could not create a virtualenv." >&2
    echo "[setup] On Debian/Ubuntu run: sudo apt install python3-venv" >&2
    exit 1
  fi
fi

# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if python -c "import pytest" >/dev/null 2>&1; then
  python -m pytest -q
else
  echo "[setup] WARNING: pytest not installed (add it to requirements.txt); skipping tests." >&2
fi

echo
echo "[setup] Python environment ready."
echo "[setup] Zeek will be checked/installed automatically by app.py."
echo "[setup] Start with:"
echo "        source .venv/bin/activate"
echo "        sudo -E .venv/bin/python app.py"