#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

missing=()
for package in python3 python3-venv python3-pip nodejs npm; do
  if ! dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null | rg -q '^installed$'; then
    missing+=("$package")
  fi
done
if ((${#missing[@]})); then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "Missing required packages: ${missing[*]}. Install them with your distribution package manager." >&2
    exit 1
  fi
  echo "Installing system packages with apt: ${missing[*]} (sudo may prompt for your password)."
  sudo apt-get update
  sudo apt-get install -y "${missing[@]}"
fi

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
npm --prefix frontend install
npm --prefix frontend run build
echo "PhishLens v0.2 is ready. Start it with ./scripts/run.sh"
