#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRIFT_DIR="${REPO_ROOT}/third_party/DRIFT"
IPIGUARD_DIR="${REPO_ROOT}/third_party/ipiguard"

RUN_TAG="${RUN_TAG:-$(date +%Y%m%d_%H%M%S)}"
BENCHMARK_VERSION="${BENCHMARK_VERSION:-v1.2.2}"
MODEL="${MODEL:-gpt-4o-mini-2024-07-18}"
ATTACK_NAME="${ATTACK_NAME:-important_instructions}"
IPIGUARD_DEFENSE="${IPIGUARD_DEFENSE:-ipiguard}"
OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://127.0.0.1:18000/v1}"
OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
DRIFT_OPENAI_TIMEOUT_S="${DRIFT_OPENAI_TIMEOUT_S:-300}"
DRIFT_OPENAI_MAX_RETRIES="${DRIFT_OPENAI_MAX_RETRIES:-8}"

OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifact_out_external_runtime/external_runs/${RUN_TAG}}"
LOG_DIR="${OUT_ROOT}/logs"
DRIFT_WORKSPACE="${DRIFT_WORKSPACE:-${OUT_ROOT}/drift_workspace}"
DRIFT_SUITES="${DRIFT_SUITES:-banking,slack,travel,workspace}"
DRIFT_MODES="${DRIFT_MODES:-benign,attack}"
RUN_DRIFT="${RUN_DRIFT:-1}"
RUN_IPIGUARD="${RUN_IPIGUARD:-1}"
mkdir -p "${LOG_DIR}"
mkdir -p "${DRIFT_WORKSPACE}"

run_drift_one() {
  local mode="$1"
  local suite="$2"
  local log_path="${LOG_DIR}/drift_${mode}_${suite}.log"

  echo "[run][DRIFT] mode=${mode} suite=${suite}"
  if [[ "${mode}" == "attack" ]]; then
    (
      cd "${DRIFT_WORKSPACE}"
      OPENAI_BASE_URL="${OPENAI_BASE_URL}" \
      OPENAI_API_KEY="${OPENAI_API_KEY}" \
      DRIFT_OPENAI_TIMEOUT_S="${DRIFT_OPENAI_TIMEOUT_S}" \
      DRIFT_OPENAI_MAX_RETRIES="${DRIFT_OPENAI_MAX_RETRIES}" \
      PYTHONPATH="${DRIFT_DIR}:${REPO_ROOT}/third_party/agentdojo/src" \
      PYTHONUNBUFFERED=1 \
      python "${DRIFT_DIR}/pipeline_main.py" \
        --benchmark_version "${BENCHMARK_VERSION}" \
        --model "${MODEL}" \
        --suites "${suite}" \
        --do_attack \
        --attack_type "${ATTACK_NAME}" \
        --build_constraints \
        --injection_isolation \
        --dynamic_validation
    ) >"${log_path}" 2>&1
  else
    (
      cd "${DRIFT_WORKSPACE}"
      OPENAI_BASE_URL="${OPENAI_BASE_URL}" \
      OPENAI_API_KEY="${OPENAI_API_KEY}" \
      DRIFT_OPENAI_TIMEOUT_S="${DRIFT_OPENAI_TIMEOUT_S}" \
      DRIFT_OPENAI_MAX_RETRIES="${DRIFT_OPENAI_MAX_RETRIES}" \
      PYTHONPATH="${DRIFT_DIR}:${REPO_ROOT}/third_party/agentdojo/src" \
      PYTHONUNBUFFERED=1 \
      python "${DRIFT_DIR}/pipeline_main.py" \
        --benchmark_version "${BENCHMARK_VERSION}" \
        --model "${MODEL}" \
        --suites "${suite}" \
        --build_constraints \
        --injection_isolation \
        --dynamic_validation
    ) >"${log_path}" 2>&1
  fi
  echo "[done][DRIFT] mode=${mode} suite=${suite} log=${log_path}"
}

run_ipiguard_one() {
  local mode="$1"
  local suite="$2"
  local out_dir="${OUT_ROOT}/ipiguard/${mode}/${suite}"
  local log_path="${LOG_DIR}/ipiguard_${mode}_${suite}.log"

  mkdir -p "${out_dir}"
  if [[ -f "${out_dir}/results.jsonl" ]] && rg -q '"Suite"\s*:\s*"' "${out_dir}/results.jsonl"; then
    echo "[skip][IPIGuard] mode=${mode} suite=${suite} existing summary detected: ${out_dir}/results.jsonl"
    return 0
  fi

  echo "[run][IPIGuard] mode=${mode} suite=${suite}"
  (
    cd "${IPIGUARD_DIR}"
    OPENAI_BASE_URL="${OPENAI_BASE_URL}" \
    OPENAI_API_KEY="${OPENAI_API_KEY}" \
    PYTHONUNBUFFERED=1 \
    python run/eval.py \
      --benchmark_version "${BENCHMARK_VERSION}" \
      --suite_name "${suite}" \
      --agent_model "${MODEL}" \
      --attack_name "${ATTACK_NAME}" \
      --defense_name "${IPIGUARD_DEFENSE}" \
      --output_dir "${out_dir}" \
      --mode "${mode}" \
      --uid 0 \
      --iid 0
  ) >"${log_path}" 2>&1
  echo "[done][IPIGuard] mode=${mode} suite=${suite} out=${out_dir}"
}

main() {
  local suites=()
  local modes=()
  IFS=',' read -r -a suites <<< "${DRIFT_SUITES}"
  IFS=',' read -r -a modes <<< "${DRIFT_MODES}"

  echo "[start] run_tag=${RUN_TAG} out_root=${OUT_ROOT} drift_workspace=${DRIFT_WORKSPACE}"

  if [[ "${RUN_DRIFT}" == "1" ]]; then
    local mode
    local suite
    for mode in "${modes[@]}"; do
      mode="${mode//[[:space:]]/}"
      case "${mode}" in
        benign|attack) ;;
        *)
          echo "[error] Unsupported DRIFT mode: ${mode}. Expected benign or attack."
          exit 1
          ;;
      esac
      for suite in "${suites[@]}"; do
        suite="${suite//[[:space:]]/}"
        if [[ -z "${suite}" ]]; then
          continue
        fi
        run_drift_one "${mode}" "${suite}"
      done
    done
  else
    echo "[skip] DRIFT disabled (RUN_DRIFT=${RUN_DRIFT})"
  fi

  if [[ "${RUN_IPIGUARD}" == "1" ]]; then
    local suite
    for suite in "${suites[@]}"; do
      suite="${suite//[[:space:]]/}"
      if [[ -z "${suite}" ]]; then
        continue
      fi
      run_ipiguard_one benign "${suite}"
    done
    for suite in "${suites[@]}"; do
      suite="${suite//[[:space:]]/}"
      if [[ -z "${suite}" ]]; then
        continue
      fi
      run_ipiguard_one under_attack "${suite}"
    done
  else
    echo "[skip] IPIGuard disabled (RUN_IPIGUARD=${RUN_IPIGUARD})"
  fi

  echo "[all-done] out_root=${OUT_ROOT}"
}

main "$@"
