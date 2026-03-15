#!/usr/bin/env bash
set -euo pipefail

RUN_ROOT_INPUT="${1:?usage: watch_agentleak_channel_eval.sh RUN_ROOT [POLL_SECONDS] [STALE_SECONDS]}"
RUN_ROOT="$(cd "${RUN_ROOT_INPUT}" && pwd)"
POLL_SECONDS="${2:-60}"
STALE_SECONDS="${3:-900}"

EVAL_DIR="${RUN_ROOT}/agentleak_eval"
LOG_PATH="${RUN_ROOT}/run.log"
CSV_PATH="${EVAL_DIR}/agentleak_eval_rows.csv"
SUMMARY_PATH="${EVAL_DIR}/agentleak_channel_summary.json"
STATUS_PATH="${RUN_ROOT}/live_status.md"

find_pid() {
  ps ax -o pid= -o command= | grep "agentleak_channel_eval.py" | grep -F -- "${RUN_ROOT}" | grep -v "watch_agentleak_channel_eval.sh" | awk 'NR==1{print $1}'
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
  CSV_MTIME="$(file_mtime_epoch "${CSV_PATH}")"
  SUMMARY_MTIME="$(file_mtime_epoch "${SUMMARY_PATH}")"
  LATEST_MTIME="${LOG_MTIME}"
  for ts in "${CSV_MTIME}" "${SUMMARY_MTIME}"; do
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
    echo "# AgentLeak Channel Eval Live Status"
    echo
    echo "- updated_at: ${NOW_HUMAN}"
    echo "- run_root: \`${RUN_ROOT}\`"
    echo "- alive: ${ALIVE}"
    echo "- pid: ${PID:-none}"
    echo "- stale: ${STALE_FLAG}"
    echo "- stale_seconds: ${STALE_SECONDS_NOW}"
    echo "- csv_exists: $([[ -f "${CSV_PATH}" ]] && echo true || echo false)"
    echo "- summary_exists: $([[ -f "${SUMMARY_PATH}" ]] && echo true || echo false)"
    if [[ -f "${CSV_PATH}" ]]; then
      echo "- csv_rows: $(wc -l < "${CSV_PATH}" | tr -d ' ')"
    else
      echo "- csv_rows: 0"
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
