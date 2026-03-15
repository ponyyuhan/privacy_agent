#!/usr/bin/env bash
set -euo pipefail

RUN_DIR_INPUT="${1:?usage: watch_agentleak_tools_benchmark.sh RUN_DIR [POLL_SECONDS] [STALE_SECONDS]}"
RUN_DIR="$(cd "${RUN_DIR_INPUT}" && pwd)"
POLL_SECONDS="${2:-60}"
STALE_SECONDS="${3:-900}"

LOG_PATH="${RUN_DIR}/run.log"
CLAIMS_PATH="${RUN_DIR}/claims.json"
SCENARIOS_PATH="${RUN_DIR}/scenarios.json"
TRACES_DIR="${RUN_DIR}/traces"
STATUS_PATH="${RUN_DIR}/live_status.md"

find_pid() {
  ps ax -o pid= -o command= | awk -v run_dir="${RUN_DIR}" '
    index($0, "benchmark_tools.py") &&
    index($0, run_dir) &&
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

traces_count() {
  if [[ -d "${TRACES_DIR}" ]]; then
    find "${TRACES_DIR}" -type f | wc -l | tr -d ' '
  else
    echo 0
  fi
}

latest_trace_mtime_epoch() {
  if [[ -d "${TRACES_DIR}" ]]; then
    local latest
    latest="$(find "${TRACES_DIR}" -type f -exec stat -f '%m' {} \; 2>/dev/null | sort -nr | head -n 1)"
    if [[ -n "${latest}" ]]; then
      echo "${latest}"
      return
    fi
  fi
  echo 0
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
  CLAIMS_MTIME="$(file_mtime_epoch "${CLAIMS_PATH}")"
  SCENARIOS_MTIME="$(file_mtime_epoch "${SCENARIOS_PATH}")"
  TRACE_MTIME="$(latest_trace_mtime_epoch)"
  LATEST_MTIME="${LOG_MTIME}"
  for ts in "${CLAIMS_MTIME}" "${SCENARIOS_MTIME}" "${TRACE_MTIME}"; do
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
    echo "# AgentLeak Tools Lane Live Status"
    echo
    echo "- updated_at: ${NOW_HUMAN}"
    echo "- run_dir: \`${RUN_DIR}\`"
    echo "- alive: ${ALIVE}"
    echo "- pid: ${PID:-none}"
    echo "- stale: ${STALE_FLAG}"
    echo "- stale_seconds: ${STALE_SECONDS_NOW}"
    echo "- claims_exists: $([[ -f "${CLAIMS_PATH}" ]] && echo true || echo false)"
    echo "- scenarios_exists: $([[ -f "${SCENARIOS_PATH}" ]] && echo true || echo false)"
    echo "- traces_count: $(traces_count)"
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
