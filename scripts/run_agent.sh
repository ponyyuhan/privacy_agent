#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT"

if [[ -z "${POLICY0_URL:-}" || -z "${POLICY1_URL:-}" ]]; then
  echo "Missing POLICY0_URL/POLICY1_URL"
  exit 2
fi

echo "[run_agent] POLICY0_URL=${POLICY0_URL}"
echo "[run_agent] POLICY1_URL=${POLICY1_URL}"
echo "[run_agent] EXECUTOR_URL=${EXECUTOR_URL:-}"
echo "[run_agent] DLP_MODE=${DLP_MODE:-fourgram}"
echo "[run_agent] SIGNED_PIR=${SIGNED_PIR:-0}"

python -m agent.nanoclaw_agent benign
python -m agent.nanoclaw_agent malicious

