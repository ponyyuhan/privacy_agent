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
RUN_FAILURE_BACKOFF_S="${RUN_FAILURE_BACKOFF_S:-90}"
MISSING_KEY_BACKOFF_S="${MISSING_KEY_BACKOFF_S:-300}"
SECURECLAW_BENIGN_GATE_FIRST="${SECURECLAW_BENIGN_GATE_FIRST:-1}"
SECURECLAW_BENIGN_MIN_UTILITY="${SECURECLAW_BENIGN_MIN_UTILITY:-50}"
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

trap cleanup_current_run EXIT INT TERM

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

all_complete() {
  python - "${STATUS_JSON}" "${SUITES}" <<'PY'
import json, sys
from pathlib import Path
status_path = Path(sys.argv[1])
suites = [s.strip() for s in sys.argv[2].split(",") if s.strip()]
if not status_path.exists():
    raise SystemExit(1)
doc = json.loads(status_path.read_text())
suite_map = doc.get("suites") or {}
for suite in suites:
    rec = suite_map.get(suite) or {}
    if not bool((rec.get("benign") or {}).get("complete")):
        raise SystemExit(1)
    if not bool((rec.get("under_attack") or {}).get("complete")):
        raise SystemExit(1)
raise SystemExit(0)
PY
}

benign_complete() {
  python - "${STATUS_JSON}" "${SUITES}" <<'PY'
import json, sys
from pathlib import Path
status_path = Path(sys.argv[1])
suites = [s.strip() for s in sys.argv[2].split(",") if s.strip()]
if not status_path.exists():
    raise SystemExit(1)
doc = json.loads(status_path.read_text())
suite_map = doc.get("suites") or {}
for suite in suites:
    rec = suite_map.get(suite) or {}
    if not bool((rec.get("benign") or {}).get("complete")):
        raise SystemExit(1)
raise SystemExit(0)
PY
}

under_attack_complete() {
  python - "${STATUS_JSON}" "${SUITES}" <<'PY'
import json, sys
from pathlib import Path
status_path = Path(sys.argv[1])
suites = [s.strip() for s in sys.argv[2].split(",") if s.strip()]
if not status_path.exists():
    raise SystemExit(1)
doc = json.loads(status_path.read_text())
suite_map = doc.get("suites") or {}
for suite in suites:
    rec = suite_map.get(suite) or {}
    if not bool((rec.get("under_attack") or {}).get("complete")):
        raise SystemExit(1)
raise SystemExit(0)
PY
}

benign_threshold_passed() {
  python - "${STATUS_JSON}" "${SUITES}" "${SECURECLAW_BENIGN_MIN_UTILITY}" <<'PY'
import json, sys
from pathlib import Path
status_path = Path(sys.argv[1])
suites = [s.strip() for s in sys.argv[2].split(",") if s.strip()]
threshold = float(sys.argv[3])
if not status_path.exists():
    raise SystemExit(1)
doc = json.loads(status_path.read_text())
suite_map = doc.get("suites") or {}
for suite in suites:
    benign = (suite_map.get(suite) or {}).get("benign") or {}
    if not bool(benign.get("complete")):
        raise SystemExit(1)
    utility = benign.get("utility")
    if utility is None or float(utility) < threshold:
        raise SystemExit(2)
raise SystemExit(0)
PY
}

latest_results_mtime() {
  local newest=0
  while IFS= read -r f; do
    [ -n "${f}" ] || continue
    local mt
    mt="$(stat -f %m "${f}" 2>/dev/null || stat -c %Y "${f}" 2>/dev/null || echo 0)"
    if [ "${mt}" -gt "${newest}" ]; then newest="${mt}"; fi
  done < <(find "${OUT_ROOT}/secureclaw" -type f -name 'results.jsonl' 2>/dev/null)
  echo "${newest}"
}

run_once() {
  local modes_to_run="${1:-${MODES}}"
  local ts log_path
  ts="$(date +%Y%m%d_%H%M%S)"
  log_path="${LOG_DIR}/secureclaw_direct_${ts}.log"
  python "${REPO_ROOT}/scripts/run_agentdojo_native_plain_secureclaw.py" \
    --out-root "${OUT_ROOT}" \
    --model "${MODEL}" \
    --benchmark-version "${BENCHMARK_VERSION}" \
    --attack-name "${ATTACK_NAME}" \
    --suites "${SUITES}" \
    --modes "${modes_to_run}" \
    --run-plain 0 \
    --run-secureclaw 1 \
    >"${log_path}" 2>&1 &
  local pid=$!
  CURRENT_RUN_PID="${pid}"
  local last_touch
  last_touch="$(date +%s)"
  while kill -0 "${pid}" >/dev/null 2>&1; do
    status_update "direct-runner" "${pid}"
    local newest
    newest="$(latest_results_mtime)"
    if [ "${newest}" -gt 0 ]; then
      last_touch="${newest}"
    fi
    local now
    now="$(date +%s)"
    if [ $((now - last_touch)) -gt "${WATCHDOG_IDLE_S}" ]; then
      echo "[direct-watchdog] stale pid=${pid} idle=$((now - last_touch))s" >> "${LOG_DIR}/secureclaw_direct_watch_runtime.log"
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
  status_update "direct-runner" 0
  return "${rc}"
}

status_update "" 0
until all_complete; do
  if [ -z "${OPENAI_API_KEY:-}" ]; then
    echo "[direct-watchdog] OPENAI_API_KEY missing; sleeping ${MISSING_KEY_BACKOFF_S}s" >> "${LOG_DIR}/secureclaw_direct_watch_runtime.log"
    status_update "direct-runner" 0
    sleep "${MISSING_KEY_BACKOFF_S}"
    continue
  fi
  modes_to_run="${MODES}"
  if [ "${SECURECLAW_BENIGN_GATE_FIRST}" = "1" ]; then
    if ! benign_complete; then
      modes_to_run="benign"
    elif ! under_attack_complete; then
      gate_rc=0
      benign_threshold_passed || gate_rc=$?
      if [ "${gate_rc}" -eq 2 ]; then
        echo "[direct-watchdog] benign gate failed: utility threshold ${SECURECLAW_BENIGN_MIN_UTILITY} not met for all suites; stopping before under_attack" >> "${LOG_DIR}/secureclaw_direct_watch_runtime.log"
        status_update "benign-gate-failed" 0
        exit 2
      fi
      modes_to_run="under_attack"
    fi
  fi
  rc=0
  run_once "${modes_to_run}" || rc=$?
  if all_complete; then
    break
  fi
  echo "[direct-watchdog] runner_exit rc=${rc}; backoff=${RUN_FAILURE_BACKOFF_S}s" >> "${LOG_DIR}/secureclaw_direct_watch_runtime.log"
  sleep "${RUN_FAILURE_BACKOFF_S}"
done
status_update "complete" 0
