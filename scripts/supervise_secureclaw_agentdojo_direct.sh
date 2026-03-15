#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifact_out_external_runtime/external_runs/20260312_agentdojo_secureclaw_full_rerun_afterfix}"
MODEL="${MODEL:-gpt-4o-mini-2024-07-18}"
BENCHMARK_VERSION="${BENCHMARK_VERSION:-v1.1.2}"
ATTACK_NAME="${ATTACK_NAME:-important_instructions}"
SUITES="${SUITES:-banking,slack,travel,workspace}"
MODES="${MODES:-benign,under_attack}"
STATUS_JSON="${STATUS_JSON:-${OUT_ROOT}/secureclaw_live_status.json}"
STATUS_MD="${STATUS_MD:-${OUT_ROOT}/secureclaw_live_status.md}"
LOG_DIR="${OUT_ROOT}/logs"
RUN_BACKOFF_S="${RUN_BACKOFF_S:-120}"
RUN_IDLE_S="${RUN_IDLE_S:-2400}"
CURRENT_PID=0

mkdir -p "${OUT_ROOT}" "${LOG_DIR}"

export SECURECLAW_TASK_INTENT_GATE="${SECURECLAW_TASK_INTENT_GATE:-1}"
export SECURECLAW_HANDLEIZE_READ_OUTPUT="${SECURECLAW_HANDLEIZE_READ_OUTPUT:-1}"
export SECURECLAW_READ_OUTPUT_MODE="${SECURECLAW_READ_OUTPUT_MODE:-sanitized_summary}"
export SECURECLAW_ALLOW_LOCAL_STATE_EFFECTS="${SECURECLAW_ALLOW_LOCAL_STATE_EFFECTS:-1}"
export SECURECLAW_DENY_UNMAPPED_EFFECT="${SECURECLAW_DENY_UNMAPPED_EFFECT:-0}"
export SECURECLAW_MAX_TOOL_ITERS="${SECURECLAW_MAX_TOOL_ITERS:-35}"
export SECURECLAW_AUTO_USER_CONFIRM="${SECURECLAW_AUTO_USER_CONFIRM:-1}"
export SECURECLAW_POLICY_DISCOVERY="${SECURECLAW_POLICY_DISCOVERY:-off}"
export MIRAGE_SESSION_ID="${MIRAGE_SESSION_ID:-agentdojo-secureclaw-supervisor}"

update_status() {
  local current_suite="${1:-}"
  local pid="${2:-0}"
  python "${REPO_ROOT}/scripts/secureclaw_agentdojo_status.py" \
    --run-root "${OUT_ROOT}" \
    --benchmark-version "${BENCHMARK_VERSION}" \
    --current-suite "${current_suite}" \
    --pid "${pid}" \
    --output-json "${STATUS_JSON}" \
    --output-md "${STATUS_MD}" >/dev/null 2>&1 || true
}

all_complete() {
  python - "${STATUS_JSON}" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
if not path.exists():
    raise SystemExit(1)
doc = json.loads(path.read_text())
for rec in (doc.get("suites") or {}).values():
    if not bool((rec.get("benign") or {}).get("complete")):
        raise SystemExit(1)
    if not bool((rec.get("under_attack") or {}).get("complete")):
        raise SystemExit(1)
raise SystemExit(0)
PY
}

first_incomplete_suite() {
  python - "${STATUS_JSON}" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
if not path.exists():
    print("banking")
    raise SystemExit(0)
doc = json.loads(path.read_text())
for suite in ("banking", "slack", "travel", "workspace"):
    rec = (doc.get("suites") or {}).get(suite) or {}
    if not bool((rec.get("benign") or {}).get("complete")):
        print(suite)
        raise SystemExit(0)
    if not bool((rec.get("under_attack") or {}).get("complete")):
        print(suite)
        raise SystemExit(0)
print("complete")
PY
}

cleanup() {
  local pid="${CURRENT_PID:-0}"
  if [[ "${pid}" =~ ^[0-9]+$ ]] && [ "${pid}" -gt 1 ]; then
    kill -TERM "${pid}" >/dev/null 2>&1 || true
    sleep 2
    kill -KILL "${pid}" >/dev/null 2>&1 || true
  fi
  CURRENT_PID=0
}

trap cleanup EXIT INT TERM

update_status "" 0
while ! all_complete; do
  if [ -z "${OPENAI_API_KEY:-}" ]; then
    echo "[supervisor] OPENAI_API_KEY missing; sleeping ${RUN_BACKOFF_S}s" >> "${LOG_DIR}/secureclaw_supervisor.log"
    update_status "waiting_for_key" 0
    sleep "${RUN_BACKOFF_S}"
    continue
  fi

  current_suite="$(first_incomplete_suite)"
  ts="$(date +%Y%m%d_%H%M%S)"
  log_path="${LOG_DIR}/secureclaw_direct_${ts}.log"
  python "${REPO_ROOT}/scripts/run_agentdojo_native_plain_secureclaw.py" \
    --out-root "${OUT_ROOT}" \
    --model "${MODEL}" \
    --benchmark-version "${BENCHMARK_VERSION}" \
    --attack-name "${ATTACK_NAME}" \
    --suites "${SUITES}" \
    --modes "${MODES}" \
    --run-plain 0 \
    --run-secureclaw 1 \
    >"${log_path}" 2>&1 &
  CURRENT_PID=$!
  last_touch="$(date +%s)"

  while kill -0 "${CURRENT_PID}" >/dev/null 2>&1; do
    update_status "${current_suite}" "${CURRENT_PID}"
    newest=0
    while IFS= read -r f; do
      [ -n "${f}" ] || continue
      mt="$(stat -f %m "${f}" 2>/dev/null || stat -c %Y "${f}" 2>/dev/null || echo 0)"
      if [ "${mt}" -gt "${newest}" ]; then
        newest="${mt}"
      fi
    done < <(find "${OUT_ROOT}/secureclaw" -path '*/results.jsonl' -type f 2>/dev/null)
    if [ "${newest}" -gt 0 ]; then
      last_touch="${newest}"
    fi
    now="$(date +%s)"
    if [ $((now - last_touch)) -gt "${RUN_IDLE_S}" ]; then
      echo "[supervisor] stale pid=${CURRENT_PID} idle=$((now - last_touch))s" >> "${log_path}"
      kill -TERM "${CURRENT_PID}" >/dev/null 2>&1 || true
      sleep 5
      kill -KILL "${CURRENT_PID}" >/dev/null 2>&1 || true
      break
    fi
    sleep 20
  done

  rc=0
  wait "${CURRENT_PID}" || rc=$?
  CURRENT_PID=0
  update_status "" 0
  if all_complete; then
    break
  fi
  echo "[supervisor] runner_exit rc=${rc}; sleeping ${RUN_BACKOFF_S}s" >> "${LOG_DIR}/secureclaw_supervisor.log"
  sleep "${RUN_BACKOFF_S}"
done

update_status "complete" 0
