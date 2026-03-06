#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RUN_TAG="${RUN_TAG:-$(date +%Y%m%d_%H%M%S)_agentdojo_four_fair}"
MODEL="${MODEL:-gpt-4o-mini-2024-07-18}"
BENCHMARK_VERSION="${BENCHMARK_VERSION:-v1.1.2}"
ATTACK_NAME="${ATTACK_NAME:-important_instructions}"

OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifact_out_external_runtime/external_runs/${RUN_TAG}}"
OUT_ROOT="$(python - "${OUT_ROOT}" <<'PY'
import os,sys
print(os.path.abspath(os.path.expanduser(sys.argv[1])))
PY
)"

NATIVE_ROOT="${NATIVE_ROOT:-${OUT_ROOT}/agentdojo_native_plain_secureclaw}"
LOG_DIR="${OUT_ROOT}/logs"
mkdir -p "${OUT_ROOT}" "${LOG_DIR}"

echo "[start] RUN_TAG=${RUN_TAG}"
echo "[config] model=${MODEL} benchmark=${BENCHMARK_VERSION} attack=${ATTACK_NAME}"

# 1) plain + secureclaw under_attack on AgentDojo native runtime.
python "${REPO_ROOT}/scripts/run_agentdojo_native_plain_secureclaw.py" \
  --out-root "${NATIVE_ROOT}" \
  --model "${MODEL}" \
  --benchmark-version "${BENCHMARK_VERSION}" \
  --attack-name "${ATTACK_NAME}" \
  --modes "benign,under_attack" \
  --run-plain 1 \
  --run-secureclaw 1 \
  > "${LOG_DIR}/agentdojo_native_plain_secureclaw.log" 2>&1

# 2) DRIFT + IPIGuard runs (benign + attack), forced to the same benchmark version.
RUN_TAG="${RUN_TAG}" \
OUT_ROOT="${OUT_ROOT}" \
MODEL="${MODEL}" \
ATTACK_NAME="${ATTACK_NAME}" \
BENCHMARK_VERSION="${BENCHMARK_VERSION}" \
IPIGUARD_BENCHMARK_VERSION="${BENCHMARK_VERSION}" \
DRIFT_MODES="${DRIFT_MODES:-benign,attack}" \
RUN_DRIFT="${RUN_DRIFT:-1}" \
RUN_IPIGUARD="${RUN_IPIGUARD:-1}" \
bash "${REPO_ROOT}/scripts/run_drift_ipiguard_full_lowmem.sh" \
  > "${LOG_DIR}/drift_ipiguard_full.log" 2>&1

# 3) Enforce four-baseline equal denominator check (benign + under_attack).
python "${REPO_ROOT}/scripts/agentdojo_four_baseline_fair_report.py" \
  --plain-secureclaw-root "${NATIVE_ROOT}" \
  --ipiguard-root "${OUT_ROOT}/ipiguard" \
  --drift-run-root "${OUT_ROOT}" \
  --model "${MODEL}" \
  --attack-name "${ATTACK_NAME}" \
  --benchmark-version "${BENCHMARK_VERSION}" \
  --require-equal-attacks 1 \
  --require-equal-benign 1 \
  --output-json "${OUT_ROOT}/agentdojo_four_baseline_fair_report.json" \
  --output-md "${OUT_ROOT}/agentdojo_four_baseline_fair_report.md"

echo "[done] ${OUT_ROOT}/agentdojo_four_baseline_fair_report.json"
