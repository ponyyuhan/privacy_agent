#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifact_out_external_runtime/external_runs/20260312_agentdojo_secureclaw_live}"
MODEL="${MODEL:-gpt-4o-mini-2024-07-18}"
BENCHMARK_VERSION="${BENCHMARK_VERSION:-v1.1.2}"
ATTACK_NAME="${ATTACK_NAME:-important_instructions}"
SUITES="${SUITES:-banking,slack,travel,workspace}"
MODES="${MODES:-benign,under_attack}"
STATUS_JSON="${STATUS_JSON:-${OUT_ROOT}/secureclaw_live_status.json}"
STATUS_MD="${STATUS_MD:-${OUT_ROOT}/secureclaw_live_status.md}"
LOG_DIR="${OUT_ROOT}/logs"
WATCHDOG_IDLE_S="${WATCHDOG_IDLE_S:-2400}"
RUN_FAILURE_BACKOFF_S="${RUN_FAILURE_BACKOFF_S:-60}"
MISSING_KEY_BACKOFF_S="${MISSING_KEY_BACKOFF_S:-300}"
CURRENT_RUN_PID=0

mkdir -p "${OUT_ROOT}" "${LOG_DIR}"

export SECURECLAW_TASK_INTENT_GATE="${SECURECLAW_TASK_INTENT_GATE:-1}"
export SECURECLAW_HANDLEIZE_READ_OUTPUT="${SECURECLAW_HANDLEIZE_READ_OUTPUT:-1}"
export SECURECLAW_READ_OUTPUT_MODE="${SECURECLAW_READ_OUTPUT_MODE:-sanitized_summary}"
export SECURECLAW_ALLOW_LOCAL_STATE_EFFECTS="${SECURECLAW_ALLOW_LOCAL_STATE_EFFECTS:-1}"
export SECURECLAW_DENY_UNMAPPED_EFFECT="${SECURECLAW_DENY_UNMAPPED_EFFECT:-0}"
export SECURECLAW_MAX_TOOL_ITERS="${SECURECLAW_MAX_TOOL_ITERS:-35}"
export SECURECLAW_AUTO_USER_CONFIRM="${SECURECLAW_AUTO_USER_CONFIRM:-1}"
export SECURECLAW_POLICY_DISCOVERY="${SECURECLAW_POLICY_DISCOVERY:-off}"
export MIRAGE_SESSION_ID="${MIRAGE_SESSION_ID:-agentdojo-secureclaw-live}"

kill_process_tree() {
  local root="${1:-0}"
  local sig="${2:-TERM}"
  [[ "${root}" =~ ^[0-9]+$ ]] || return 0
  [ "${root}" -gt 1 ] || return 0
  local kids
  kids="$(pgrep -P "${root}" 2>/dev/null || true)"
  local kid
  for kid in ${kids}; do
    kill_process_tree "${kid}" "${sig}"
  done
  kill "-${sig}" "${root}" >/dev/null 2>&1 || true
}

cleanup_current_run() {
  local root="${CURRENT_RUN_PID:-0}"
  [[ "${root}" =~ ^[0-9]+$ ]] || return 0
  [ "${root}" -gt 1 ] || return 0
  kill_process_tree "${root}" TERM
  sleep 2
  if kill -0 "${root}" >/dev/null 2>&1; then
    kill_process_tree "${root}" KILL
  fi
  CURRENT_RUN_PID=0
}

on_exit() {
  cleanup_current_run
}

trap on_exit EXIT INT TERM

status_update() {
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

suite_complete() {
  local suite="$1"
  python - "${OUT_ROOT}" "${suite}" <<'PY'
import json, sys
from pathlib import Path
run_root = Path(sys.argv[1])
suite = sys.argv[2]
status_path = run_root / "secureclaw_live_status.json"
if not status_path.exists():
    raise SystemExit(1)
doc = json.loads(status_path.read_text())
rec = (doc.get("suites") or {}).get(suite) or {}
ok = bool((rec.get("benign") or {}).get("complete")) and bool((rec.get("under_attack") or {}).get("complete"))
raise SystemExit(0 if ok else 1)
PY
}

run_suite_once() {
  local suite="$1"
  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  local log_path="${LOG_DIR}/secureclaw_${suite}_${ts}.log"
  python "${REPO_ROOT}/scripts/run_agentdojo_native_plain_secureclaw.py" \
    --out-root "${OUT_ROOT}" \
    --model "${MODEL}" \
    --benchmark-version "${BENCHMARK_VERSION}" \
    --attack-name "${ATTACK_NAME}" \
    --suites "${suite}" \
    --modes "${MODES}" \
    --run-plain 0 \
    --run-secureclaw 1 \
    >"${log_path}" 2>&1 &
  local pid=$!
  CURRENT_RUN_PID="${pid}"
  local last_touch
  last_touch="$(date +%s)"
  while kill -0 "${pid}" >/dev/null 2>&1; do
    status_update "${suite}" "${pid}"
    local newest=0
    while IFS= read -r f; do
      [ -n "${f}" ] || continue
      local mt
      mt="$(stat -f %m "${f}" 2>/dev/null || stat -c %Y "${f}" 2>/dev/null || echo 0)"
      if [ "${mt}" -gt "${newest}" ]; then newest="${mt}"; fi
    done < <(find "${OUT_ROOT}/secureclaw" -path "*/${suite}/results.jsonl" -o -path "*/${suite}" -type f 2>/dev/null)
    if [ "${newest}" -gt 0 ]; then
      last_touch="${newest}"
    fi
    local now
    now="$(date +%s)"
    if [ $((now - last_touch)) -gt "${WATCHDOG_IDLE_S}" ]; then
      echo "[watchdog] stale suite=${suite} pid=${pid} idle=$((now - last_touch))s" >> "${log_path}"
      kill_process_tree "${pid}" TERM
      sleep 5
      if kill -0 "${pid}" >/dev/null 2>&1; then
        kill_process_tree "${pid}" KILL
      fi
      break
    fi
    sleep 20
  done
  local rc=0
  wait "${pid}" || rc=$?
  CURRENT_RUN_PID=0
  status_update "${suite}" 0
  if [ "${rc}" -ne 0 ]; then
    echo "[watchdog] runner_exit suite=${suite} rc=${rc}; backoff=${RUN_FAILURE_BACKOFF_S}s" >> "${log_path}"
    sleep "${RUN_FAILURE_BACKOFF_S}"
  fi
  return "${rc}"
}

status_update "" 0
IFS=',' read -r -a SUITE_ARR <<< "${SUITES}"
for suite in "${SUITE_ARR[@]}"; do
  suite="$(echo "${suite}" | xargs)"
  [ -n "${suite}" ] || continue
  until suite_complete "${suite}"; do
    if [ -z "${OPENAI_API_KEY:-}" ]; then
      echo "[watchdog] OPENAI_API_KEY missing; suite=${suite}; sleeping ${MISSING_KEY_BACKOFF_S}s" >> "${LOG_DIR}/secureclaw_watch_runtime.log"
      status_update "${suite}" 0
      sleep "${MISSING_KEY_BACKOFF_S}"
      continue
    fi
    run_suite_once "${suite}"
  done
done
status_update "complete" 0
