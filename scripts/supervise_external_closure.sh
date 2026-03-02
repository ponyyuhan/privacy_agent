#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

RUN_TAG="${RUN_TAG:-20260220_fullpipeline}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifact_out_external_runtime/external_runs/${RUN_TAG}}"
LOG_DIR="${OUT_ROOT}/logs"

PORT="${PORT:-18007}"
SHIM_MODEL="${SHIM_MODEL:-gpt-5.1-codex-mini}"
TARGET_MODEL="${TARGET_MODEL:-gpt-4o-mini-2024-07-18}"
API_KEY="${OPENAI_API_KEY:-dummy}"

SHIM_TIMEOUT_S="${SHIM_TIMEOUT_S:-240}"
SHIM_CODEX_MAX_RETRIES="${SHIM_CODEX_MAX_RETRIES:-0}"
SHIM_CODEX_RETRY_BACKOFF_S="${SHIM_CODEX_RETRY_BACKOFF_S:-1.0}"

POLL_S="${POLL_S:-60}"
STALE_RESTART_S="${STALE_RESTART_S:-900}"

ASB_RUN_TAG="${ASB_RUN_TAG:-20260220_official}"

DRIFT_OPENAI_TIMEOUT_S="${DRIFT_OPENAI_TIMEOUT_S:-180}"
DRIFT_OPENAI_MAX_RETRIES="${DRIFT_OPENAI_MAX_RETRIES:-0}"
DRIFT_CHAT_RETRIES="${DRIFT_CHAT_RETRIES:-0}"
DRIFT_CHAT_RETRY_BACKOFF_S="${DRIFT_CHAT_RETRY_BACKOFF_S:-0.5}"

STATUS_FILE="${LOG_DIR}/closure_supervisor_latest.txt"
SUP_LOG="${LOG_DIR}/closure_supervisor_$(date +%Y%m%d_%H%M%S).log"

mkdir -p "${LOG_DIR}"

log() {
  local msg="[$(date +"%F %T %Z")] $*"
  echo "${msg}" | tee -a "${SUP_LOG}"
}

get_pending_suites_csv() {
  python3 - <<'PY'
import os

base = "artifact_out_external_runtime/external_runs/20260220_fullpipeline/drift_workspace/runs/gpt-4o-mini-2024-07-18"
suites = ["slack", "travel", "workspace"]
pending = []
for s in suites:
    sdir = os.path.join(base, s)
    if not os.path.isdir(sdir):
        pending.append(s)
        continue
    tasks = [d for d in os.listdir(sdir) if d.startswith("user_task_") and os.path.isdir(os.path.join(sdir, d))]
    done = 0
    for t in tasks:
        tdir = os.path.join(sdir, t)
        subs = [d for d in os.listdir(tdir) if os.path.isdir(os.path.join(tdir, d)) and d != "none"]
        if subs:
            done += 1
    if done != len(tasks):
        pending.append(s)
print(",".join(pending))
PY
}

ipiguard_workspace_done() {
  python3 - <<'PY'
import json
from pathlib import Path

p = Path("artifact_out_external_runtime/external_runs/20260220_fullpipeline/ipiguard/under_attack/workspace/results.jsonl")
if not p.exists():
    print("0")
    raise SystemExit
txt = p.read_text(encoding="utf-8", errors="replace")
dec = json.JSONDecoder()
i = 0
n = len(txt)
done = False
while i < n:
    while i < n and txt[i].isspace():
        i += 1
    if i >= n:
        break
    try:
        obj, j = dec.raw_decode(txt, i)
        i = j
    except json.JSONDecodeError:
        i += 1
        continue
    if isinstance(obj, dict) and obj.get("Suite") == "workspace" and "ASR" in obj:
        done = True
        break
print("1" if done else "0")
PY
}

current_drift_pid() {
  pgrep -f "python .*third_party/DRIFT/pipeline_main.py --benchmark_version v1.2.2 --model ${TARGET_MODEL} --suites" | head -n 1 || true
}

current_drift_suite() {
  local pid="$1"
  if [[ -z "${pid}" ]]; then
    echo ""
    return 0
  fi
  ps -p "${pid}" -o command= | sed -n 's/.*--suites \([^ ]*\).*/\1/p'
}

log_age_s() {
  local file="$1"
  python3 - "$file" <<'PY'
import os
import sys
import time

f = sys.argv[1]
if not os.path.exists(f):
    print(-1)
else:
    print(int(time.time() - os.path.getmtime(f)))
PY
}

stop_drift_and_shim() {
  local pid
  pid="$(current_drift_pid)"
  if [[ -n "${pid}" ]]; then
    log "Stopping stale DRIFT pipeline pid=${pid}"
    kill -TERM "${pid}" >/dev/null 2>&1 || true
    sleep 2
    kill -KILL "${pid}" >/dev/null 2>&1 || true
  fi

  local shim_pid
  shim_pid="$(pgrep -f "python scripts/codex_chat_shim.py --host 127.0.0.1 --port ${PORT}" | head -n 1 || true)"
  if [[ -n "${shim_pid}" ]]; then
    log "Stopping shim pid=${shim_pid} on port ${PORT}"
    kill -TERM "${shim_pid}" >/dev/null 2>&1 || true
    sleep 1
    kill -KILL "${shim_pid}" >/dev/null 2>&1 || true
  fi
}

start_drift_for_pending() {
  local pending_csv="$1"
  if [[ -z "${pending_csv}" ]]; then
    return 0
  fi

  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  local run_log="${LOG_DIR}/drift_resume_attack_${pending_csv//,/_}_${ts}.log"
  local shim_log="${LOG_DIR}/codex_chat_shim_${PORT}.log"
  local launcher_log="${LOG_DIR}/drift_supervisor_launcher_${ts}.log"

  log "Starting DRIFT for suites=${pending_csv}; run_log=${run_log}"

  nohup bash -lc "
set -euo pipefail
cd '${REPO_ROOT}'
cleanup() {
  if [ -n \"\${shim_pid:-}\" ]; then
    kill \"\${shim_pid}\" >/dev/null 2>&1 || true
    wait \"\${shim_pid}\" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

PYTHONUNBUFFERED=1 python scripts/codex_chat_shim.py \
  --host 127.0.0.1 \
  --port ${PORT} \
  --model ${SHIM_MODEL} \
  --reasoning-effort low \
  --ignore-request-model 1 \
  --timeout-s ${SHIM_TIMEOUT_S} \
  --workers 1 \
  --api-key '${API_KEY}' \
  --codex-max-retries ${SHIM_CODEX_MAX_RETRIES} \
  --codex-retry-backoff-s ${SHIM_CODEX_RETRY_BACKOFF_S} \
  --workdir '${OUT_ROOT}/shim_workdir_${PORT}' >'${shim_log}' 2>&1 &
shim_pid=\$!

for i in \$(seq 1 120); do
  if curl -sf -H 'Authorization: Bearer ${API_KEY}' 'http://127.0.0.1:${PORT}/v1/models' >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
  if [ \"\$i\" = \"120\" ]; then
    echo 'shim_not_ready'
    exit 2
  fi
done

RUN_TAG='${RUN_TAG}' \
OUT_ROOT='${OUT_ROOT}' \
RUN_DRIFT=1 \
RUN_IPIGUARD=0 \
DRIFT_SUITES='${pending_csv}' \
DRIFT_MODES=attack \
OPENAI_BASE_URL='http://127.0.0.1:${PORT}/v1' \
OPENAI_API_KEY='${API_KEY}' \
MODEL='${TARGET_MODEL}' \
DRIFT_OPENAI_TIMEOUT_S='${DRIFT_OPENAI_TIMEOUT_S}' \
DRIFT_OPENAI_MAX_RETRIES='${DRIFT_OPENAI_MAX_RETRIES}' \
DRIFT_CHAT_RETRIES='${DRIFT_CHAT_RETRIES}' \
DRIFT_CHAT_RETRY_BACKOFF_S='${DRIFT_CHAT_RETRY_BACKOFF_S}' \
bash scripts/run_drift_ipiguard_full_lowmem.sh >'${run_log}' 2>&1
" >"${launcher_log}" 2>&1 &
  log "Started DRIFT launcher pid=$! log=${launcher_log}"
}

run_finalize() {
  log "Running strict closure finalize pipeline"
  python scripts/external_benchmark_unified_summary.py \
    --asb-dir third_party/ASB/logs/direct_prompt_injection/gpt-4o-mini/no_memory \
    --asb-run-tag "${ASB_RUN_TAG}" \
    --drift-runs-dir "${OUT_ROOT}/drift_workspace/runs/${TARGET_MODEL}" \
    --drift-attack-name important_instructions \
    --ipiguard-root "${OUT_ROOT}/ipiguard" \
    --output-json "${OUT_ROOT}/external_benchmark_unified_report.json" \
    --output-md "${OUT_ROOT}/external_benchmark_unified_report.md" \
    --external-run-tag "${RUN_TAG}" \
    --external-out-root "${OUT_ROOT}" \
    --enforce-run-scope 1

  python scripts/multi_track_eval.py \
    --out-dir artifact_out_compare_noprompt \
    --force-refresh-fair 1 \
    --run-protocol-tests 0 \
    --external-report "${OUT_ROOT}/external_benchmark_unified_report.json" \
    --external-run-tag "${RUN_TAG}" \
    --asb-run-tag "${ASB_RUN_TAG}" \
    --require-external-real-run 1 \
    --out artifact_out_compare_noprompt/multi_track_eval.json

  STRICT_REAL_DEFENSE_BASELINES=1 python scripts/fair_full_compare.py
  log "Strict closure finalize completed"
}

log "Supervisor started: run_tag=${RUN_TAG}, out_root=${OUT_ROOT}"
while true; do
  local_pending="$(get_pending_suites_csv)"
  ip_done="$(ipiguard_workspace_done)"
  {
    echo "===== $(date +"%F %T %Z") ====="
    echo "ip_done ${ip_done}"
    echo "drift_pending ${local_pending}"
  } > "${STATUS_FILE}"

  if [[ "${ip_done}" == "1" && -z "${local_pending}" ]]; then
    log "Completion condition satisfied; entering finalize"
    run_finalize
    break
  fi

  drift_pid="$(current_drift_pid)"
  if [[ -z "${drift_pid}" ]]; then
    if [[ -n "${local_pending}" ]]; then
      start_drift_for_pending "${local_pending}"
    fi
  else
    suite="$(current_drift_suite "${drift_pid}")"
    if [[ -n "${suite}" ]]; then
      suite_log="${LOG_DIR}/drift_attack_${suite}.log"
      age_s="$(log_age_s "${suite_log}")"
      log "DRIFT running pid=${drift_pid} suite=${suite} log_age_s=${age_s}"
      if [[ "${age_s}" -ge "${STALE_RESTART_S}" ]]; then
        log "Detected stale DRIFT (suite=${suite}, age=${age_s}s), restarting"
        stop_drift_and_shim
        # Start from current pending suites after restart.
        local_pending="$(get_pending_suites_csv)"
        if [[ -n "${local_pending}" ]]; then
          start_drift_for_pending "${local_pending}"
        fi
      fi
    fi
  fi

  sleep "${POLL_S}"
done

log "Supervisor exited"
DRIFT_OPENAI_TIMEOUT_S="${DRIFT_OPENAI_TIMEOUT_S:-180}"
DRIFT_OPENAI_MAX_RETRIES="${DRIFT_OPENAI_MAX_RETRIES:-0}"
DRIFT_CHAT_RETRIES="${DRIFT_CHAT_RETRIES:-0}"
DRIFT_CHAT_RETRY_BACKOFF_S="${DRIFT_CHAT_RETRY_BACKOFF_S:-0.5}"
