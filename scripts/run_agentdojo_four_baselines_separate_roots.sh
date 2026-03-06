#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RUN_TAG="${RUN_TAG:-$(date +%Y%m%d_%H%M%S)_agentdojo_four_separate_roots}"
MODEL="${MODEL:-gpt-4o-mini-2024-07-18}"
BENCHMARK_VERSION="${BENCHMARK_VERSION:-v1.1.2}"
ATTACK_NAME="${ATTACK_NAME:-important_instructions}"

OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifact_out_external_runtime/external_runs/${RUN_TAG}}"
OUT_ROOT="$(python - "${OUT_ROOT}" <<'PY'
import os,sys
print(os.path.abspath(os.path.expanduser(sys.argv[1])))
PY
)"

PLAIN_ROOT="${PLAIN_ROOT:-${OUT_ROOT}/agentdojo_plain_only}"
SECURECLAW_ROOT="${SECURECLAW_ROOT:-${OUT_ROOT}/agentdojo_secureclaw_only}"
DRIFT_ROOT="${DRIFT_ROOT:-${OUT_ROOT}/agentdojo_drift_only}"
IPIGUARD_ROOT="${IPIGUARD_ROOT:-${OUT_ROOT}/agentdojo_ipiguard_only}"
LOG_DIR="${OUT_ROOT}/logs"
mkdir -p "${LOG_DIR}"

RUN_PLAIN="${RUN_PLAIN:-1}"
RUN_SECURECLAW="${RUN_SECURECLAW:-1}"
RUN_DRIFT="${RUN_DRIFT:-1}"
RUN_IPIGUARD="${RUN_IPIGUARD:-1}"

# Generic anti-rate-limit knobs (can be overridden from env)
export IPIGUARD_OPENAI_TIMEOUT_S="${IPIGUARD_OPENAI_TIMEOUT_S:-120}"
export IPIGUARD_OPENAI_MAX_RETRIES="${IPIGUARD_OPENAI_MAX_RETRIES:-0}"
export IPIGUARD_LLM_RETRY_ATTEMPTS="${IPIGUARD_LLM_RETRY_ATTEMPTS:-60}"
export IPIGUARD_LLM_RETRY_MAX_WAIT_S="${IPIGUARD_LLM_RETRY_MAX_WAIT_S:-90}"
export IPIGUARD_LLM_RETRY_BACKOFF_S="${IPIGUARD_LLM_RETRY_BACKOFF_S:-2}"
export IPIGUARD_LLM_RETRY_HINT_SCALE="${IPIGUARD_LLM_RETRY_HINT_SCALE:-2.5}"
export IPIGUARD_LLM_RETRY_HINT_JITTER_S="${IPIGUARD_LLM_RETRY_HINT_JITTER_S:-0.5}"
export IPIGUARD_LLM_LOG_RETRIES="${IPIGUARD_LLM_LOG_RETRIES:-1}"
export IPIGUARD_RETRY_HINT_SCALE="${IPIGUARD_RETRY_HINT_SCALE:-1.0}"
export IPIGUARD_RETRY_HINT_JITTER_S="${IPIGUARD_RETRY_HINT_JITTER_S:-0.5}"
export DRIFT_OPENAI_MAX_RETRIES="${DRIFT_OPENAI_MAX_RETRIES:-8}"
export DRIFT_CHAT_RETRIES="${DRIFT_CHAT_RETRIES:-8}"
export DRIFT_CHAT_RETRY_BACKOFF_S="${DRIFT_CHAT_RETRY_BACKOFF_S:-1.5}"

echo "[start] RUN_TAG=${RUN_TAG}"
echo "[config] model=${MODEL} benchmark=${BENCHMARK_VERSION} attack=${ATTACK_NAME}"
echo "[roots] plain=${PLAIN_ROOT} secureclaw=${SECURECLAW_ROOT} drift=${DRIFT_ROOT} ipiguard=${IPIGUARD_ROOT}"

if [[ "${RUN_PLAIN}" == "1" ]]; then
  echo "[phase] plain (under_attack + benign)"
  OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://api.openai.com/v1}" \
  OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
  python "${REPO_ROOT}/scripts/run_agentdojo_native_plain_secureclaw.py" \
    --out-root "${PLAIN_ROOT}" \
    --model "${MODEL}" \
    --benchmark-version "${BENCHMARK_VERSION}" \
    --attack-name "${ATTACK_NAME}" \
    --modes "under_attack,benign" \
    --run-plain 1 \
    --run-secureclaw 0 \
    > "${LOG_DIR}/plain.log" 2>&1
else
  echo "[skip] plain"
fi

if [[ "${RUN_SECURECLAW}" == "1" ]]; then
  echo "[phase] secureclaw (under_attack + benign)"
  OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://api.openai.com/v1}" \
  OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
  python "${REPO_ROOT}/scripts/run_agentdojo_native_plain_secureclaw.py" \
    --out-root "${SECURECLAW_ROOT}" \
    --model "${MODEL}" \
    --benchmark-version "${BENCHMARK_VERSION}" \
    --attack-name "${ATTACK_NAME}" \
    --modes "under_attack,benign" \
    --run-plain 0 \
    --run-secureclaw 1 \
    > "${LOG_DIR}/secureclaw.log" 2>&1
else
  echo "[skip] secureclaw"
fi

if [[ "${RUN_DRIFT}" == "1" ]]; then
  echo "[phase] drift (benign + attack)"
  OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://api.openai.com/v1}" \
  OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
  RUN_TAG="${RUN_TAG}_drift" \
  OUT_ROOT="${DRIFT_ROOT}" \
  MODEL="${MODEL}" \
  ATTACK_NAME="${ATTACK_NAME}" \
  BENCHMARK_VERSION="${BENCHMARK_VERSION}" \
  IPIGUARD_BENCHMARK_VERSION="${BENCHMARK_VERSION}" \
  DRIFT_MODES="benign,attack" \
  RUN_DRIFT=1 \
  RUN_IPIGUARD=0 \
  bash "${REPO_ROOT}/scripts/run_drift_ipiguard_full_lowmem.sh" \
    > "${LOG_DIR}/drift.log" 2>&1
else
  echo "[skip] drift"
fi

if [[ "${RUN_IPIGUARD}" == "1" ]]; then
  echo "[phase] ipiguard (benign + under_attack)"
  OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://api.openai.com/v1}" \
  OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
  RUN_TAG="${RUN_TAG}_ipiguard" \
  OUT_ROOT="${IPIGUARD_ROOT}" \
  MODEL="${MODEL}" \
  ATTACK_NAME="${ATTACK_NAME}" \
  BENCHMARK_VERSION="${BENCHMARK_VERSION}" \
  IPIGUARD_BENCHMARK_VERSION="${BENCHMARK_VERSION}" \
  DRIFT_MODES="benign,attack" \
  RUN_DRIFT=0 \
  RUN_IPIGUARD=1 \
  bash "${REPO_ROOT}/scripts/run_drift_ipiguard_full_lowmem.sh" \
    > "${LOG_DIR}/ipiguard.log" 2>&1
else
  echo "[skip] ipiguard"
fi

REPORT_JSON="${OUT_ROOT}/agentdojo_four_baseline_final_report.json"
REPORT_MD="${OUT_ROOT}/agentdojo_four_baseline_final_report.md"

echo "[phase] final report"
python "${REPO_ROOT}/scripts/agentdojo_four_baseline_fair_report.py" \
  --plain-root "${PLAIN_ROOT}/plain" \
  --secureclaw-root "${SECURECLAW_ROOT}/secureclaw" \
  --ipiguard-root "${IPIGUARD_ROOT}/ipiguard" \
  --drift-run-root "${DRIFT_ROOT}" \
  --model "${MODEL}" \
  --attack-name "${ATTACK_NAME}" \
  --benchmark-version "${BENCHMARK_VERSION}" \
  --require-equal-attacks 1 \
  --require-equal-benign 1 \
  --output-json "${REPORT_JSON}" \
  --output-md "${REPORT_MD}"

echo "[done] ${REPORT_JSON}"
echo "[done] ${REPORT_MD}"
