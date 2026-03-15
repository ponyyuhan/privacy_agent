#!/usr/bin/env bash
set -euo pipefail

RUN_DIR_INPUT="${1:?usage: watch_agentleak_parity_seq.sh RUN_DIR [POLL_SECONDS] [STALE_SECONDS]}"
RUN_DIR="$(cd "${RUN_DIR_INPUT}" && pwd)"
POLL_SECONDS="${2:-60}"
STALE_SECONDS="${3:-900}"

LOG_PATH="${RUN_DIR}/seq.log"
ROWS_DIR="${RUN_DIR}/paper_parity_agentleak_eval"
STATUS_PATH="${RUN_DIR}/live_status.md"
REPORT_PATH="${ROWS_DIR}/paper_parity_report.json"

mkdir -p "${ROWS_DIR}"

find_pid() {
  ps ax -o pid= -o command= | awk -v run_dir="${RUN_DIR}" -v run_dir_input="${RUN_DIR_INPUT}" '
    index($0, "paper_parity_agentleak_eval.py") &&
    (index($0, run_dir) || index($0, run_dir_input)) &&
    $2 == "python" { print $1; exit }
  '
}

file_mtime_epoch() {
  local path="$1"
  if [[ -f "${path}" ]]; then
    stat -f '%m' "${path}"
  else
    echo 0
  fi
}

rows_count() {
  local mode="$1"
  local path="${ROWS_DIR}/rows_${mode}.jsonl"
  if [[ -f "${path}" ]]; then
    wc -l < "${path}" | tr -d ' '
  else
    echo 0
  fi
}

latest_count() {
  local mode="$1"
  local path="${ROWS_DIR}/rows_${mode}.jsonl"
  if [[ ! -f "${path}" ]]; then
    echo 0
    return
  fi
  python - "$path" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
latest = {}
for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
    s = ln.strip()
    if not s:
        continue
    try:
        d = json.loads(s)
    except Exception:
        continue
    sid = str(d.get("scenario_id") or "")
    if sid:
        latest[sid] = d
print(len(latest))
PY
}

schema_v2_count() {
  local mode="$1"
  local path="${ROWS_DIR}/rows_${mode}.jsonl"
  if [[ ! -f "${path}" ]]; then
    echo 0
    return
  fi
  python - "$path" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
latest = {}
for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
    s = ln.strip()
    if not s:
        continue
    try:
        d = json.loads(s)
    except Exception:
        continue
    sid = str(d.get("scenario_id") or "")
    if sid:
        latest[sid] = d
count = 0
for d in latest.values():
    try:
        if int(d.get("row_schema_version") or 0) >= 2:
            count += 1
    except Exception:
        pass
print(count)
PY
}

extract_current_mode() {
  if [[ -f "${LOG_PATH}" ]]; then
    grep -E '^\[start\] mode=' "${LOG_PATH}" 2>/dev/null | tail -n 1 | sed -E 's/^\[start\] mode=([^ ]+).*/\1/' || true
  else
    echo "unknown"
  fi
}

extract_completed_modes() {
  if [[ -f "${LOG_PATH}" ]]; then
    grep -E '^\[done\] mode=' "${LOG_PATH}" 2>/dev/null | sed -E 's/^\[done\] mode=([^ ]+).*/\1/' | paste -sd ',' - || true
  fi
}

while true; do
  NOW_EPOCH="$(date +%s)"
  NOW_HUMAN="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  PID="$(find_pid || true)"
  ALIVE="false"
  if [[ -n "${PID}" ]] && kill -0 "${PID}" 2>/dev/null; then
    ALIVE="true"
  fi

  LOG_MTIME="$(file_mtime_epoch "${LOG_PATH}")"
  PLAIN_MTIME="$(file_mtime_epoch "${ROWS_DIR}/rows_plain.jsonl")"
  IPIGUARD_MTIME="$(file_mtime_epoch "${ROWS_DIR}/rows_ipiguard.jsonl")"
  DRIFT_MTIME="$(file_mtime_epoch "${ROWS_DIR}/rows_drift.jsonl")"
  FARAMESH_MTIME="$(file_mtime_epoch "${ROWS_DIR}/rows_faramesh.jsonl")"
  SECURECLAW_MTIME="$(file_mtime_epoch "${ROWS_DIR}/rows_secureclaw.jsonl")"
  LATEST_MTIME="${LOG_MTIME}"
  for ts in "${PLAIN_MTIME}" "${IPIGUARD_MTIME}" "${DRIFT_MTIME}" "${FARAMESH_MTIME}" "${SECURECLAW_MTIME}"; do
    if [[ "${ts}" -gt "${LATEST_MTIME}" ]]; then
      LATEST_MTIME="${ts}"
    fi
  done

  STALE_SECONDS_NOW=$(( NOW_EPOCH - LATEST_MTIME ))
  STALE_FLAG="false"
  if [[ "${LATEST_MTIME}" -gt 0 ]] && [[ "${STALE_SECONDS_NOW}" -ge "${STALE_SECONDS}" ]]; then
    STALE_FLAG="true"
  fi

  CURRENT_MODE="$(extract_current_mode)"
  COMPLETED_MODES="$(extract_completed_modes)"
  [[ -n "${COMPLETED_MODES}" ]] || COMPLETED_MODES="(none)"

  {
    echo "# AgentLeak Parity Live Status"
    echo
    echo "- updated_at: ${NOW_HUMAN}"
    echo "- run_dir: \`${RUN_DIR}\`"
    echo "- alive: ${ALIVE}"
    echo "- pid: ${PID:-none}"
    echo "- current_mode: ${CURRENT_MODE}"
    echo "- completed_modes: ${COMPLETED_MODES}"
    echo "- stale: ${STALE_FLAG}"
    echo "- stale_seconds: ${STALE_SECONDS_NOW}"
    echo "- report_exists: $([[ -f "${REPORT_PATH}" ]] && echo true || echo false)"
    echo
    echo "## Row Counts"
    echo
    echo "- plain_latest: $(latest_count plain)"
    echo "- ipiguard_latest: $(latest_count ipiguard)"
    echo "- drift_latest: $(latest_count drift)"
    echo "- faramesh_latest: $(latest_count faramesh)"
    echo "- secureclaw_latest: $(latest_count secureclaw)"
    echo "- plain_v2: $(schema_v2_count plain)"
    echo "- ipiguard_v2: $(schema_v2_count ipiguard)"
    echo "- drift_v2: $(schema_v2_count drift)"
    echo "- faramesh_v2: $(schema_v2_count faramesh)"
    echo "- secureclaw_v2: $(schema_v2_count secureclaw)"
    echo "- topology_cache: $(find "${ROWS_DIR}/topology_outputs" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')"
    echo
    echo "## Log Tail"
    echo
    echo '```'
    if [[ -f "${LOG_PATH}" ]]; then
      tail -n 20 "${LOG_PATH}"
    fi
    echo '```'
  } > "${STATUS_PATH}.tmp"

  mv "${STATUS_PATH}.tmp" "${STATUS_PATH}"

  if [[ "${ALIVE}" != "true" ]]; then
    break
  fi

  sleep "${POLL_SECONDS}"
done
