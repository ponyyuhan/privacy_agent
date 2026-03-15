#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ROOT="${RUN_ROOT:-${REPO_ROOT}/artifact_out_external_runtime/external_runs/20260304_agentdojo_four_parallel_rerun_v1}"
SEQ_STATUS_MD="${SEQ_STATUS_MD:-${RUN_ROOT}/drift_ipiguard_seq_resume_status.md}"
SEQ_STATUS_JSON="${SEQ_STATUS_JSON:-${RUN_ROOT}/drift_ipiguard_seq_resume_status.json}"
FOLLOWUP_STATUS_MD="${FOLLOWUP_STATUS_MD:-${RUN_ROOT}/drift_ipiguard_faramesh_followup_status.md}"
FOLLOWUP_STATUS_JSON="${FOLLOWUP_STATUS_JSON:-${RUN_ROOT}/drift_ipiguard_faramesh_followup_status.json}"
WATCHDOG_LOG="${WATCHDOG_LOG:-${RUN_ROOT}/logs/drift_ipiguard_faramesh_watchdog.log}"
SUPERVISOR_STDOUT_LOG="${SUPERVISOR_STDOUT_LOG:-${RUN_ROOT}/logs/watchdog_spawn_supervisor.log}"
FOLLOWUP_STDOUT_LOG="${FOLLOWUP_STDOUT_LOG:-${RUN_ROOT}/logs/watchdog_spawn_followup.log}"
QUOTA_FLAG="${QUOTA_FLAG:-${RUN_ROOT}/fatal_insufficient_quota.flag}"
CHECK_INTERVAL_S="${CHECK_INTERVAL_S:-60}"
STALL_SECS_IPIGUARD="${STALL_SECS_IPIGUARD:-1800}"
STALL_SECS_FARAMESH="${STALL_SECS_FARAMESH:-10800}"
MPLCONFIGDIR="${MPLCONFIGDIR:-${RUN_ROOT}/tmp/mplconfig}"

mkdir -p "$(dirname "${WATCHDOG_LOG}")" "${MPLCONFIGDIR}"

supervisor_pid=""
followup_pid=""

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')" "$1" | tee -a "${WATCHDOG_LOG}"
}

md_field() {
  local file="$1"
  local key="$2"
  sed -n "s#^- ${key}: ##p" "${file}" 2>/dev/null | head -n 1
}

json_flag() {
  local file="$1"
  local key="$2"
  python - "${file}" "${key}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
key = sys.argv[2]
if not path.exists():
    print("")
    raise SystemExit(0)
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    print("")
    raise SystemExit(0)
value = payload.get(key)
print("" if value is None else str(value))
PY
}

pid_alive() {
  local pid="${1:-}"
  [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null
}

kill_process_tree() {
  local root_pid="$1"
  python - "${root_pid}" <<'PY'
import os
import signal
import sys
import time

pid = int(sys.argv[1])

def kill_if_alive(target_pid: int, sig: int) -> None:
    try:
        os.kill(target_pid, sig)
    except ProcessLookupError:
        pass
    except Exception:
        pass

try:
    pgid = os.getpgid(pid)
except ProcessLookupError:
    raise SystemExit(0)
except Exception:
    pgid = None

if pgid is not None:
    try:
        os.killpg(pgid, signal.SIGTERM)
    except Exception:
        kill_if_alive(pid, signal.SIGTERM)
else:
    kill_if_alive(pid, signal.SIGTERM)

time.sleep(10)

try:
    os.kill(pid, 0)
except ProcessLookupError:
    raise SystemExit(0)
except Exception:
    pass

if pgid is not None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except Exception:
        kill_if_alive(pid, signal.SIGKILL)
else:
    kill_if_alive(pid, signal.SIGKILL)
PY
}

progress_epoch() {
  local kind="$1"
  local status_json="$2"
  local current_log="$3"
  python - "${kind}" "${status_json}" "${RUN_ROOT}" "${current_log}" <<'PY'
import json
import os
import sys
from pathlib import Path

kind = sys.argv[1]
status_json = Path(sys.argv[2])
run_root = Path(sys.argv[3])
current_log = sys.argv[4]

if not status_json.exists():
    print(0)
    raise SystemExit(0)

try:
    payload = json.loads(status_json.read_text(encoding="utf-8"))
except Exception:
    print(0)
    raise SystemExit(0)

epochs = []
log_path = Path(current_log) if current_log and current_log != "-" else None
if log_path and log_path.exists():
    epochs.append(log_path.stat().st_mtime)

if kind == "ipiguard":
    root = run_root / "agentdojo_ipiguard_only" / "ipiguard"
    groups = payload.get("ipiguard", {})
elif kind == "faramesh":
    root = run_root / "agentdojo_faramesh_only" / "faramesh"
    groups = payload.get("faramesh", {})
else:
    print(int(max(epochs) if epochs else 0))
    raise SystemExit(0)

for mode, suites in groups.items():
    if not isinstance(suites, dict):
        continue
    for suite, info in suites.items():
        if not isinstance(info, dict):
            continue
        rows = int(info.get("rows", 0))
        expected = int(info.get("expected", 0))
        summary = bool(info.get("summary", False))
        if rows == expected and summary:
            continue
        results_path = root / mode / suite / "results.jsonl"
        if results_path.exists():
            epochs.append(results_path.stat().st_mtime)

print(int(max(epochs) if epochs else 0))
PY
}

kill_if_stale() {
  local phase="$1"
  local active_pid="$2"
  local active_log="$3"
  local status_json="$4"
  local stall_secs="$5"
  if [[ -z "${active_pid}" || "${active_pid}" == "-" ]]; then
    return 0
  fi
  if ! kill -0 "${active_pid}" 2>/dev/null; then
    return 0
  fi
  local last_epoch now age
  last_epoch="$(progress_epoch "${phase}" "${status_json}" "${active_log}")"
  now="$(date +%s)"
  if [[ -z "${last_epoch}" || "${last_epoch}" == "0" ]]; then
    return 0
  fi
  age=$((now - last_epoch))
  log "Check ${phase}: pid=${active_pid} age=${age}s threshold=${stall_secs}s log=${active_log}"
  if (( age < stall_secs )); then
    return 0
  fi
  log "Stale ${phase} child detected: pid=${active_pid} no_progress_for=${age}s log=${active_log}; terminating process tree."
  kill_process_tree "${active_pid}"
}

ensure_supervisor() {
  local drift_complete ipiguard_complete
  if [[ -f "${QUOTA_FLAG}" ]]; then
    log "Quota flag present; supervisor relaunch paused: ${QUOTA_FLAG}"
    return 0
  fi
  drift_complete="$(json_flag "${SEQ_STATUS_JSON}" "drift_complete")"
  ipiguard_complete="$(json_flag "${SEQ_STATUS_JSON}" "ipiguard_complete")"
  if [[ "${drift_complete}" == "True" && "${ipiguard_complete}" == "True" ]]; then
    return 0
  fi
  if pid_alive "${supervisor_pid}"; then
    return 0
  fi
  log "Supervisor missing; relaunching."
  (
    cd "${REPO_ROOT}"
    env \
      OPENAI_API_KEY="${OPENAI_API_KEY:?OPENAI_API_KEY missing}" \
      OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://api.openai.com/v1}" \
      MPLCONFIGDIR="${MPLCONFIGDIR}" \
      bash scripts/supervise_drift_ipiguard_seq_resume.sh
  ) >> "${SUPERVISOR_STDOUT_LOG}" 2>&1 &
  supervisor_pid="$!"
  log "Supervisor relaunched: pid=${supervisor_pid}"
}

ensure_followup() {
  local far_complete
  if [[ -f "${QUOTA_FLAG}" ]]; then
    return 0
  fi
  far_complete="$(json_flag "${FOLLOWUP_STATUS_JSON}" "faramesh_complete")"
  if [[ "${far_complete}" == "True" ]]; then
    return 0
  fi
  if pid_alive "${followup_pid}"; then
    return 0
  fi
  log "Follow-up watcher missing; relaunching."
  (
    cd "${REPO_ROOT}"
    env \
      OPENAI_API_KEY="${OPENAI_API_KEY:?OPENAI_API_KEY missing}" \
      OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://api.openai.com/v1}" \
      MPLCONFIGDIR="${MPLCONFIGDIR}" \
      bash scripts/continue_after_ipiguard_with_faramesh.sh
  ) >> "${FOLLOWUP_STDOUT_LOG}" 2>&1 &
  followup_pid="$!"
  log "Follow-up watcher relaunched: pid=${followup_pid}"
}

log "Watchdog starting."
trap 'kill ${supervisor_pid:-} ${followup_pid:-} 2>/dev/null || true; exit 0' INT TERM
while true; do
  ensure_supervisor
  ensure_followup

  seq_phase="$(md_field "${SEQ_STATUS_MD}" "phase")"
  seq_pid="$(md_field "${SEQ_STATUS_MD}" "active_pid")"
  seq_log="$(md_field "${SEQ_STATUS_MD}" "current_pass_log")"
  log "Heartbeat seq_phase=${seq_phase} seq_pid=${seq_pid}"
  if [[ "${seq_phase}" == "ipiguard" ]]; then
    kill_if_stale "ipiguard" "${seq_pid}" "${seq_log}" "${SEQ_STATUS_JSON}" "${STALL_SECS_IPIGUARD}"
  fi

  far_phase="$(md_field "${FOLLOWUP_STATUS_MD}" "phase")"
  far_pid="$(md_field "${FOLLOWUP_STATUS_MD}" "active_pid")"
  far_log="$(md_field "${FOLLOWUP_STATUS_MD}" "current_log")"
  log "Heartbeat far_phase=${far_phase} far_pid=${far_pid}"
  if [[ "${far_phase}" == "faramesh" ]]; then
    kill_if_stale "faramesh" "${far_pid}" "${far_log}" "${FOLLOWUP_STATUS_JSON}" "${STALL_SECS_FARAMESH}"
  fi

  sleep "${CHECK_INTERVAL_S}"
done
