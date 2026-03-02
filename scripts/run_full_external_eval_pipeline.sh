#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

AGENTDOJO_MODEL_DIR="${AGENTDOJO_MODEL_DIR:-third_party/agentdojo/runs/gpt-4o-mini-2024-07-18}"
AGENTDOJO_BENCHMARK_VERSION="${AGENTDOJO_BENCHMARK_VERSION:-v1.2.2}"

OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://127.0.0.1:18000/v1}"
OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"

ASB_RUN_TAG="${ASB_RUN_TAG:-20260220_official}"
ASB_TASK_NUM="${ASB_TASK_NUM:-1}"
ASB_MAX_WORKERS="${ASB_MAX_WORKERS:-auto}"
ASB_MAX_INFLIGHT="${ASB_MAX_INFLIGHT:-auto}"
ASB_MEM_BUDGET_MB="${ASB_MEM_BUDGET_MB:-6144}"
ASB_BASE_MEM_MB="${ASB_BASE_MEM_MB:-2048}"
ASB_PER_WORKER_MEM_MB="${ASB_PER_WORKER_MEM_MB:-512}"
ASB_MAX_WORKERS_CAP="${ASB_MAX_WORKERS_CAP:-12}"

EXTERNAL_RUN_TAG="${EXTERNAL_RUN_TAG:-$(date +%Y%m%d_%H%M%S)}"
EXTERNAL_OUT_ROOT="${EXTERNAL_OUT_ROOT:-${REPO_ROOT}/artifact_out_external_runtime/external_runs/${EXTERNAL_RUN_TAG}}"
START_STAGE="${START_STAGE:-agentdojo}" # agentdojo | asb | drift | summarize

DRIFT_MODEL="${DRIFT_MODEL:-gpt-4o-mini-2024-07-18}"
DRIFT_ATTACK_NAME="${DRIFT_ATTACK_NAME:-important_instructions}"
IPIGUARD_BENCHMARK_VERSION="${IPIGUARD_BENCHMARK_VERSION:-v1.1.2}"
DRIFT_WORKSPACE="${DRIFT_WORKSPACE:-${EXTERNAL_OUT_ROOT}/drift_workspace}"
DRIFT_RUNS_DIR="${DRIFT_RUNS_DIR:-${DRIFT_WORKSPACE}/runs/${DRIFT_MODEL}}"
DRIFT_SUITES="${DRIFT_SUITES:-banking,slack,travel,workspace}"
DRIFT_MODES="${DRIFT_MODES:-benign,attack}"
RUN_IPIGUARD="${RUN_IPIGUARD:-1}"
DRIFT_OPENAI_TIMEOUT_S="${DRIFT_OPENAI_TIMEOUT_S:-300}"
DRIFT_OPENAI_MAX_RETRIES="${DRIFT_OPENAI_MAX_RETRIES:-0}"
DRIFT_CHAT_RETRIES="${DRIFT_CHAT_RETRIES:-0}"
DRIFT_CHAT_RETRY_BACKOFF_S="${DRIFT_CHAT_RETRY_BACKOFF_S:-0.5}"

_ASB_WORKERS_RESOLVED=""
_ASB_INFLIGHT_RESOLVED=""

log() {
  echo "[$(date +"%Y-%m-%d %H:%M:%S %Z")] $*"
}

resolve_asb_concurrency() {
  local workers="${ASB_MAX_WORKERS}"
  local inflight="${ASB_MAX_INFLIGHT}"

  local budget_mb="${ASB_MEM_BUDGET_MB}"
  local base_mb="${ASB_BASE_MEM_MB}"
  local per_worker_mb="${ASB_PER_WORKER_MEM_MB}"
  local cap_workers="${ASB_MAX_WORKERS_CAP}"
  if ! [[ "${budget_mb}" =~ ^[0-9]+$ ]]; then
    budget_mb=6144
  fi
  if ! [[ "${base_mb}" =~ ^[0-9]+$ ]]; then
    base_mb=2048
  fi
  if ! [[ "${per_worker_mb}" =~ ^[0-9]+$ ]] || [[ "${per_worker_mb}" -le 0 ]]; then
    per_worker_mb=512
  fi
  if ! [[ "${cap_workers}" =~ ^[0-9]+$ ]] || [[ "${cap_workers}" -le 0 ]]; then
    cap_workers=12
  fi

  local usable_mb=$((budget_mb - base_mb))
  if [[ "${usable_mb}" -lt "${per_worker_mb}" ]]; then
    usable_mb="${per_worker_mb}"
  fi
  local auto_workers=$((usable_mb / per_worker_mb))
  if [[ "${auto_workers}" -lt 1 ]]; then
    auto_workers=1
  fi
  if [[ "${auto_workers}" -gt "${cap_workers}" ]]; then
    auto_workers="${cap_workers}"
  fi

  if [[ "${workers}" == "auto" ]]; then
    workers="${auto_workers}"
  fi
  if [[ "${inflight}" == "auto" ]]; then
    inflight="${auto_workers}"
  fi

  if ! [[ "${workers}" =~ ^[0-9]+$ ]] || [[ "${workers}" -lt 1 ]]; then
    log "Invalid ASB_MAX_WORKERS=${workers}"
    exit 1
  fi
  if ! [[ "${inflight}" =~ ^[0-9]+$ ]] || [[ "${inflight}" -lt 1 ]]; then
    log "Invalid ASB_MAX_INFLIGHT=${inflight}"
    exit 1
  fi

  local max_by_budget=$((usable_mb / per_worker_mb))
  if [[ "${max_by_budget}" -lt 1 ]]; then
    max_by_budget=1
  fi
  if [[ "${workers}" -gt "${max_by_budget}" ]]; then
    workers="${max_by_budget}"
  fi
  if [[ "${inflight}" -gt "${max_by_budget}" ]]; then
    inflight="${max_by_budget}"
  fi
  if [[ "${inflight}" -gt "${workers}" ]]; then
    inflight="${workers}"
  fi

  _ASB_WORKERS_RESOLVED="${workers}"
  _ASB_INFLIGHT_RESOLVED="${inflight}"
  log "ASB concurrency: workers=${_ASB_WORKERS_RESOLVED} inflight=${_ASB_INFLIGHT_RESOLVED} (budget=${budget_mb}MB base=${base_mb}MB per_worker=${per_worker_mb}MB)"
}

wait_agentdojo_complete() {
  log "Checking AgentDojo completion status"
  while true; do
    read -r missing present <<<"$(PYTHONPATH=third_party/agentdojo/src python scripts/agentdojo_progress.py \
      --model-dir "${AGENTDOJO_MODEL_DIR}" \
      --benchmark-version "${AGENTDOJO_BENCHMARK_VERSION}" \
      | python -c 'import json,sys; d=json.load(sys.stdin); ws=d["suites"]["workspace"]; print(ws["missing"], ws["present"])')"

    log "AgentDojo workspace present=${present} missing=${missing}"
    if [[ "${missing}" -eq 0 ]]; then
      log "AgentDojo workspace complete"
      break
    fi
    sleep 60
  done
}

run_asb_full() {
  log "Starting ASB full run (run_tag=${ASB_RUN_TAG}, task_num=${ASB_TASK_NUM}, workers=${_ASB_WORKERS_RESOLVED}, inflight=${_ASB_INFLIGHT_RESOLVED})"
  RUN_TAG="${ASB_RUN_TAG}" \
  OPENAI_BASE_URL="${OPENAI_BASE_URL}" \
  OPENAI_API_KEY="${OPENAI_API_KEY}" \
  TASK_NUM="${ASB_TASK_NUM}" \
  MAX_WORKERS="${_ASB_WORKERS_RESOLVED}" \
  MAX_INFLIGHT="${_ASB_INFLIGHT_RESOLVED}" \
  ASB_MEM_BUDGET_MB="${ASB_MEM_BUDGET_MB}" \
  ASB_BASE_MEM_MB="${ASB_BASE_MEM_MB}" \
  ASB_PER_WORKER_MEM_MB="${ASB_PER_WORKER_MEM_MB}" \
  ASB_MAX_WORKERS_CAP="${ASB_MAX_WORKERS_CAP}" \
  bash scripts/run_asb_dpi_full_lowmem.sh

  log "ASB full run finished"
}

summarize_asb() {
  local out_dir="third_party/ASB/logs/direct_prompt_injection/gpt-4o-mini/no_memory"
  local c1="${out_dir}/naive-all_lowmem_${ASB_RUN_TAG}.csv"
  local c2="${out_dir}/escape_characters-all_lowmem_${ASB_RUN_TAG}.csv"
  local c3="${out_dir}/fake_completion-all_lowmem_${ASB_RUN_TAG}.csv"

  mkdir -p "${EXTERNAL_OUT_ROOT}"
  python scripts/asb_csv_summary.py "${c1}" "${c2}" "${c3}" > "${EXTERNAL_OUT_ROOT}/asb_summary_${ASB_RUN_TAG}.json"
  log "ASB summary written: ${EXTERNAL_OUT_ROOT}/asb_summary_${ASB_RUN_TAG}.json"
}

run_drift_ipiguard_full() {
  log "Starting DRIFT/IPIGuard full run (out_root=${EXTERNAL_OUT_ROOT})"
  RUN_TAG="${EXTERNAL_RUN_TAG}" \
  OUT_ROOT="${EXTERNAL_OUT_ROOT}" \
  DRIFT_WORKSPACE="${DRIFT_WORKSPACE}" \
  DRIFT_SUITES="${DRIFT_SUITES}" \
  DRIFT_MODES="${DRIFT_MODES}" \
  RUN_IPIGUARD="${RUN_IPIGUARD}" \
  OPENAI_BASE_URL="${OPENAI_BASE_URL}" \
  OPENAI_API_KEY="${OPENAI_API_KEY}" \
  BENCHMARK_VERSION="${AGENTDOJO_BENCHMARK_VERSION}" \
  IPIGUARD_BENCHMARK_VERSION="${IPIGUARD_BENCHMARK_VERSION}" \
  MODEL="${DRIFT_MODEL}" \
  ATTACK_NAME="${DRIFT_ATTACK_NAME}" \
  DRIFT_OPENAI_TIMEOUT_S="${DRIFT_OPENAI_TIMEOUT_S}" \
  DRIFT_OPENAI_MAX_RETRIES="${DRIFT_OPENAI_MAX_RETRIES}" \
  DRIFT_CHAT_RETRIES="${DRIFT_CHAT_RETRIES}" \
  DRIFT_CHAT_RETRY_BACKOFF_S="${DRIFT_CHAT_RETRY_BACKOFF_S}" \
  bash scripts/run_drift_ipiguard_full_lowmem.sh

  log "DRIFT/IPIGuard full run finished"
}

summarize_all() {
  python scripts/external_benchmark_unified_summary.py \
    --agentdojo-model-dir "${AGENTDOJO_MODEL_DIR}" \
    --agentdojo-benchmark-version "${AGENTDOJO_BENCHMARK_VERSION}" \
    --asb-dir "third_party/ASB/logs/direct_prompt_injection/gpt-4o-mini/no_memory" \
    --asb-run-tag "${ASB_RUN_TAG}" \
    --allow-asb-latest-fallback 0 \
    --drift-runs-dir "${DRIFT_RUNS_DIR}" \
    --drift-attack-name "${DRIFT_ATTACK_NAME}" \
    --ipiguard-root "${EXTERNAL_OUT_ROOT}/ipiguard" \
    --external-run-tag "${EXTERNAL_RUN_TAG}" \
    --external-out-root "${EXTERNAL_OUT_ROOT}" \
    --enforce-run-scope 1 \
    --output-json "${EXTERNAL_OUT_ROOT}/external_benchmark_unified_report.json" \
    --output-md "${EXTERNAL_OUT_ROOT}/external_benchmark_unified_report.md"

  log "Unified summary written under ${EXTERNAL_OUT_ROOT}"
}

main() {
  mkdir -p "${EXTERNAL_OUT_ROOT}"
  resolve_asb_concurrency
  log "Pipeline start"

  case "${START_STAGE}" in
    agentdojo)
      wait_agentdojo_complete
      run_asb_full
      summarize_asb
      run_drift_ipiguard_full
      summarize_all
      ;;
    asb)
      run_asb_full
      summarize_asb
      run_drift_ipiguard_full
      summarize_all
      ;;
    drift)
      run_drift_ipiguard_full
      summarize_all
      ;;
    summarize)
      summarize_all
      ;;
    *)
      log "Unknown START_STAGE=${START_STAGE}. Expected: agentdojo|asb|drift|summarize"
      exit 1
      ;;
  esac

  log "Pipeline done"
}

main "$@"
