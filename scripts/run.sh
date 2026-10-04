#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"
if [[ ! -x .venv/bin/uvicorn || ! -f frontend/dist/index.html ]]; then
  echo "PhishLens is not installed yet. Run ./scripts/install.sh first." >&2
  exit 1
fi
exec .venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 7834
