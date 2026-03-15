#!/usr/bin/env bash
set -euo pipefail

RUN_ROOT_INPUT="${1:?usage: watch_agentleak_channel_baseline_compare.sh RUN_ROOT [POLL_SECONDS] [STALE_SECONDS]}"
RUN_ROOT="$(cd "${RUN_ROOT_INPUT}" && pwd)"
POLL_SECONDS="${2:-60}"
STALE_SECONDS="${3:-900}"

LOG_PATH="${RUN_ROOT}/run.log"
REPORT_PATH="${RUN_ROOT}/report.json"
EVAL_DIR="${RUN_ROOT}/compare"
STATUS_PATH="${RUN_ROOT}/live_status.md"

find_pid() {
  local rel
  rel="$(python - <<'PY' "${RUN_ROOT}"
import os, sys
print(os.path.relpath(sys.argv[1], os.getcwd()))
PY
)"
  ps ax -o pid= -o command= | grep "agentleak_channel_baseline_compare.py" | grep -v "watch_agentleak_channel_baseline_compare.sh" | grep -F -- "${rel}" | awk 'NR==1{print $1}'
}

file_mtime_epoch() {
  local path="$1"
  if [[ -f "${path}" ]]; then
    stat -f '%m' "${path}"
  else
    echo 0
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
  REPORT_MTIME="$(file_mtime_epoch "${REPORT_PATH}")"
  ROWS_MTIME=0
  if [[ -d "${EVAL_DIR}" ]]; then
    latest_rows="$(find "${EVAL_DIR}" -name 'rows.jsonl' -type f -exec stat -f '%m' {} \; 2>/dev/null | sort -nr | head -n 1)"
    if [[ -n "${latest_rows}" ]]; then
      ROWS_MTIME="${latest_rows}"
    fi
  fi
  LATEST_MTIME="${LOG_MTIME}"
  for ts in "${REPORT_MTIME}" "${ROWS_MTIME}"; do
    if [[ "${ts}" -gt "${LATEST_MTIME}" ]]; then
      LATEST_MTIME="${ts}"
    fi
  done
  STALE_SECONDS_NOW=$(( NOW_EPOCH - LATEST_MTIME ))
  STALE_FLAG="false"
  if [[ "${LATEST_MTIME}" -gt 0 ]] && [[ "${STALE_SECONDS_NOW}" -ge "${STALE_SECONDS}" ]]; then
    STALE_FLAG="true"
  fi

  {
    echo "# AgentLeak Channel Baseline Compare Live Status"
    echo
    echo "- updated_at: ${NOW_HUMAN}"
    echo "- run_root: \`${RUN_ROOT}\`"
    echo "- alive: ${ALIVE}"
    echo "- pid: ${PID:-none}"
    echo "- stale: ${STALE_FLAG}"
    echo "- stale_seconds: ${STALE_SECONDS_NOW}"
    echo "- report_exists: $([[ -f "${REPORT_PATH}" ]] && echo true || echo false)"
    echo
    echo "## Mode Rows"
    echo
    if [[ -d "${EVAL_DIR}" ]]; then
      for mode_dir in "${EVAL_DIR}"/*; do
        [[ -d "${mode_dir}" ]] || continue
        mode="$(basename "${mode_dir}")"
        rows_path="${mode_dir}/rows.jsonl"
        summary_path="${mode_dir}/summary.json"
        rows=0
        [[ -f "${rows_path}" ]] && rows="$(wc -l < "${rows_path}" | tr -d ' ')"
        echo "- ${mode}: rows=${rows}, summary=$([[ -f "${summary_path}" ]] && echo ready || echo pending)"
      done
    fi
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
