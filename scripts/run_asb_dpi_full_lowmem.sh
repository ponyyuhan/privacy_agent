#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASB_DIR="${REPO_ROOT}/third_party/ASB"

RUN_TAG="${RUN_TAG:-$(date +%Y%m%d_%H%M%S)}"
TASK_NUM="${TASK_NUM:-1}"
MAX_WORKERS="${MAX_WORKERS:-auto}"
MAX_INFLIGHT="${MAX_INFLIGHT:-auto}"
ASB_MEM_BUDGET_MB="${ASB_MEM_BUDGET_MB:-6144}"
ASB_BASE_MEM_MB="${ASB_BASE_MEM_MB:-2048}"
ASB_PER_WORKER_MEM_MB="${ASB_PER_WORKER_MEM_MB:-512}"
ASB_MAX_WORKERS_CAP="${ASB_MAX_WORKERS_CAP:-12}"

ASB_SHARDS="${ASB_SHARDS:-1}"
ASB_SHARD_WORKERS="${ASB_SHARD_WORKERS:-2}"
ASB_SHARD_INFLIGHT="${ASB_SHARD_INFLIGHT:-2}"
ASB_SHARD_MAX_CYCLES="${ASB_SHARD_MAX_CYCLES:-60}"
ASB_SHARD_BASE_URLS="${ASB_SHARD_BASE_URLS:-}"

OPENAI_BASE_URL="${OPENAI_BASE_URL:-http://127.0.0.1:18000/v1}"
OPENAI_API_KEY="${OPENAI_API_KEY:-dummy}"
ASB_LLM_PRE_REQUEST_SLEEP="${ASB_LLM_PRE_REQUEST_SLEEP:-0}"
ASB_LLM_REQUEST_TIMEOUT="${ASB_LLM_REQUEST_TIMEOUT:-120}"
ASB_LLM_CLIENT_MAX_RETRIES="${ASB_LLM_CLIENT_MAX_RETRIES:-1}"
ASB_REFUSE_JUDGE_MODE="${ASB_REFUSE_JUDGE_MODE:-heuristic}"
ASB_REFUSE_JUDGE_TIMEOUT="${ASB_REFUSE_JUDGE_TIMEOUT:-60}"
ASB_REFUSE_JUDGE_RETRIES="${ASB_REFUSE_JUDGE_RETRIES:-1}"
ATTACKER_TOOLS_PATH="${ATTACKER_TOOLS_PATH:-data/all_attack_tools.jsonl}"
TASKS_PATH="${TASKS_PATH:-data/agent_task.jsonl}"
OUT_DIR="${OUT_DIR:-${ASB_DIR}/logs/direct_prompt_injection/gpt-4o-mini/no_memory}"

mkdir -p "${OUT_DIR}"

if ! [[ "${ASB_SHARDS}" =~ ^[0-9]+$ ]] || [[ "${ASB_SHARDS}" -lt 1 ]]; then
  echo "Invalid ASB_SHARDS=${ASB_SHARDS}"
  exit 1
fi

SHARD_BASE_URL_ARRAY=()
if [[ -n "${ASB_SHARD_BASE_URLS}" ]]; then
  IFS=',' read -r -a SHARD_BASE_URL_ARRAY <<< "${ASB_SHARD_BASE_URLS}"
fi

resolve_path() {
  local p="$1"
  if [[ "${p}" = /* ]]; then
    echo "${p}"
  else
    echo "${ASB_DIR}/${p}"
  fi
}

RESOLVED_MAX_WORKERS=""
RESOLVED_MAX_INFLIGHT=""

resolve_concurrency() {
  local workers="${MAX_WORKERS}"
  local inflight="${MAX_INFLIGHT}"
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
    echo "Invalid MAX_WORKERS=${workers}"
    exit 1
  fi
  if ! [[ "${inflight}" =~ ^[0-9]+$ ]] || [[ "${inflight}" -lt 1 ]]; then
    echo "Invalid MAX_INFLIGHT=${inflight}"
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

  RESOLVED_MAX_WORKERS="${workers}"
  RESOLVED_MAX_INFLIGHT="${inflight}"
  echo "[asb-concurrency] workers=${RESOLVED_MAX_WORKERS} inflight=${RESOLVED_MAX_INFLIGHT} (budget=${budget_mb}MB base=${base_mb}MB per_worker=${per_worker_mb}MB)"
}

rows_in_csv() {
  local csv_path="$1"
  if [[ ! -f "${csv_path}" ]]; then
    echo 0
    return 0
  fi
  local lines
  lines="$(wc -l < "${csv_path}")"
  if [[ "${lines}" -le 0 ]]; then
    echo 0
  else
    echo $((lines - 1))
  fi
}

calc_expected_rows() {
  local tasks_path_abs="$1"
  local tools_path_abs="$2"
  local task_num="$3"
  python - "${tasks_path_abs}" "${tools_path_abs}" "${task_num}" <<'PY'
import ast
import sys
import pandas as pd

tasks_path, tools_path, task_num_s = sys.argv[1], sys.argv[2], sys.argv[3]
task_num = int(task_num_s)

tasks_df = pd.read_json(tasks_path, lines=True)
tools_df = pd.read_json(tools_path, lines=True)

total = 0
for _, row in tasks_df.iterrows():
    tasks = row["tasks"]
    if isinstance(tasks, str):
        tasks = ast.literal_eval(tasks)
    total += min(len(tasks), task_num) * len(tools_df[tools_df["Corresponding Agent"] == row["agent_name"]])

print(total)
PY
}

run_main_attacker() {
  local attack_type="$1"
  local tools_path_abs="$2"
  local tasks_path_abs="$3"
  local workers="$4"
  local inflight="$5"
  local res_file="$6"
  local log_file="$7"
  local base_url="$8"

  (
    cd "${ASB_DIR}"
    OPENAI_BASE_URL="${base_url}" \
    OPENAI_API_KEY="${OPENAI_API_KEY}" \
    ASB_LLM_PRE_REQUEST_SLEEP="${ASB_LLM_PRE_REQUEST_SLEEP}" \
    ASB_LLM_REQUEST_TIMEOUT="${ASB_LLM_REQUEST_TIMEOUT}" \
    ASB_LLM_CLIENT_MAX_RETRIES="${ASB_LLM_CLIENT_MAX_RETRIES}" \
    ASB_REFUSE_JUDGE_MODE="${ASB_REFUSE_JUDGE_MODE}" \
    ASB_REFUSE_JUDGE_TIMEOUT="${ASB_REFUSE_JUDGE_TIMEOUT}" \
    ASB_REFUSE_JUDGE_RETRIES="${ASB_REFUSE_JUDGE_RETRIES}" \
    PYTHONUNBUFFERED=1 \
    python main_attacker.py \
      --llm_name gpt-4o-mini \
      --direct_prompt_injection \
      --attack_type "${attack_type}" \
      --attacker_tools_path "${tools_path_abs}" \
      --tasks_path "${tasks_path_abs}" \
      --task_num "${TASK_NUM}" \
      --max_workers "${workers}" \
      --max_inflight "${inflight}" \
      --res_file "${res_file}" \
      > "${log_file}" 2>&1
  )
}

shard_base_url_for_index() {
  local idx="$1"
  local n="${#SHARD_BASE_URL_ARRAY[@]}"
  if [[ "${n}" -eq 0 ]]; then
    echo "${OPENAI_BASE_URL}"
    return 0
  fi
  local pick=$((idx % n))
  local raw="${SHARD_BASE_URL_ARRAY[${pick}]}"
  local trimmed="${raw//[[:space:]]/}"
  if [[ -z "${trimmed}" ]]; then
    echo "${OPENAI_BASE_URL}"
  else
    echo "${trimmed}"
  fi
}

prepare_shard_tools() {
  local shard_root="$1"
  local attacker_tools_path_abs="$2"
  local num_shards="$3"

  python - "${shard_root}" "${attacker_tools_path_abs}" "${num_shards}" <<'PY'
import json
import os
import sys

out_dir, tools_path, shards_s = sys.argv[1], sys.argv[2], sys.argv[3]
shards = int(shards_s)
os.makedirs(out_dir, exist_ok=True)

rows = []
with open(tools_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))

for i in range(shards):
    out_path = os.path.join(out_dir, f"tools_shard_{i}.jsonl")
    with open(out_path, "w", encoding="utf-8") as w:
        for idx, row in enumerate(rows):
            if idx % shards == i:
                w.write(json.dumps(row, ensure_ascii=False) + "\n")
PY
}

seed_shards_from_final() {
  local final_csv="$1"
  local shard_root="$2"
  local num_shards="$3"
  local out_dir="$4"
  local attack_type="$5"

  python - "${final_csv}" "${shard_root}" "${num_shards}" "${out_dir}" "${attack_type}" "${RUN_TAG}" <<'PY'
import csv
import json
import os
import sys

final_csv, shard_root, shards_s, out_dir, attack_type, run_tag = sys.argv[1:7]
shards = int(shards_s)

if not os.path.exists(final_csv) or os.path.getsize(final_csv) == 0:
    sys.exit(0)

fieldnames = [
    "Agent Name",
    "Attack Tool",
    "Attack Successful",
    "Original Task Successful",
    "Refuse Result",
    "Memory Found",
    "Aggressive",
    "messages",
]

def normalize_agent(name):
    s = str(name or "")
    return s.rsplit("/", 1)[-1]

pair_to_shard = {}
for i in range(shards):
    shard_tool_path = os.path.join(shard_root, f"tools_shard_{i}.jsonl")
    if not os.path.exists(shard_tool_path):
        continue
    with open(shard_tool_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            pair = (normalize_agent(row.get("Corresponding Agent")), str(row.get("Attacker Tool")))
            pair_to_shard[pair] = i

existing = [set() for _ in range(shards)]
for i in range(shards):
    shard_csv = os.path.join(out_dir, f"{attack_type}-all_lowmem_{run_tag}.shard{i}.csv")
    if not os.path.exists(shard_csv) or os.path.getsize(shard_csv) == 0:
        continue
    with open(shard_csv, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = (normalize_agent(row.get("Agent Name")), str(row.get("Attack Tool")))
            existing[i].add(key)

buffers = [[] for _ in range(shards)]
with open(final_csv, "r", encoding="utf-8", newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        key = (normalize_agent(row.get("Agent Name")), str(row.get("Attack Tool")))
        shard_idx = pair_to_shard.get(key)
        if shard_idx is None:
            continue
        if key in existing[shard_idx]:
            continue
        existing[shard_idx].add(key)
        buffers[shard_idx].append({k: row.get(k, "") for k in fieldnames})

for i in range(shards):
    if not buffers[i]:
        continue
    shard_csv = os.path.join(out_dir, f"{attack_type}-all_lowmem_{run_tag}.shard{i}.csv")
    file_exists = os.path.exists(shard_csv) and os.path.getsize(shard_csv) > 0
    with open(shard_csv, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerows(buffers[i])
PY
}

merge_shards_csv() {
  local final_csv="$1"
  local out_dir="$2"
  local attack_type="$3"
  local run_tag="$4"
  local num_shards="$5"

  python - "${final_csv}" "${out_dir}" "${attack_type}" "${run_tag}" "${num_shards}" <<'PY'
import csv
import os
import sys

final_csv, out_dir, attack_type, run_tag, shards_s = sys.argv[1:6]
shards = int(shards_s)

fieldnames = [
    "Agent Name",
    "Attack Tool",
    "Attack Successful",
    "Original Task Successful",
    "Refuse Result",
    "Memory Found",
    "Aggressive",
    "messages",
]

def normalize_agent(name):
    s = str(name or "")
    return s.rsplit("/", 1)[-1]

rows = []
seen = set()

for i in range(shards):
    shard_csv = os.path.join(out_dir, f"{attack_type}-all_lowmem_{run_tag}.shard{i}.csv")
    if not os.path.exists(shard_csv) or os.path.getsize(shard_csv) == 0:
        continue
    with open(shard_csv, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = (normalize_agent(row.get("Agent Name")), str(row.get("Attack Tool")))
            if key in seen:
                continue
            seen.add(key)
            rows.append({k: row.get(k, "") for k in fieldnames})

with open(final_csv, "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
PY
}

run_one_sharded() {
  local attack_type="$1"
  local expected_rows="$2"
  local final_csv="${OUT_DIR}/${attack_type}-all_lowmem_${RUN_TAG}.csv"
  local shard_root="${OUT_DIR}/_shards/${RUN_TAG}/${attack_type}"

  echo "[run-sharded] ${attack_type} shards=${ASB_SHARDS} shard_workers=${ASB_SHARD_WORKERS} shard_inflight=${ASB_SHARD_INFLIGHT}"
  mkdir -p "${shard_root}"

  prepare_shard_tools "${shard_root}" "${ATTACKER_TOOLS_PATH_ABS}" "${ASB_SHARDS}"
  seed_shards_from_final "${final_csv}" "${shard_root}" "${ASB_SHARDS}" "${OUT_DIR}" "${attack_type}"

  local cycle=0
  while true; do
    cycle=$((cycle + 1))
    echo "[cycle] ${attack_type} cycle=${cycle}"

    local -a pids=()
    local launched=0
    local i
    for ((i = 0; i < ASB_SHARDS; i++)); do
      local shard_tools="${shard_root}/tools_shard_${i}.jsonl"
      local shard_csv="${OUT_DIR}/${attack_type}-all_lowmem_${RUN_TAG}.shard${i}.csv"
      local shard_log="${OUT_DIR}/${attack_type}-all_lowmem_${RUN_TAG}.shard${i}.log"
      local shard_base_url
      shard_base_url="$(shard_base_url_for_index "${i}")"
      local shard_expected
      shard_expected="$(calc_expected_rows "${TASKS_PATH_ABS}" "${shard_tools}" "${TASK_NUM}")"
      local shard_done
      shard_done="$(rows_in_csv "${shard_csv}")"

      if [[ "${shard_expected}" -eq 0 ]]; then
        echo "[skip-shard-empty] ${attack_type} shard=${i}"
        continue
      fi

      if [[ "${shard_done}" -ge "${shard_expected}" ]]; then
        echo "[skip-shard-complete] ${attack_type} shard=${i} (${shard_done}/${shard_expected})"
        continue
      fi

      echo "[run-shard] ${attack_type} shard=${i} (${shard_done}/${shard_expected}) base_url=${shard_base_url}"
      run_main_attacker \
        "${attack_type}" \
        "${shard_tools}" \
        "${TASKS_PATH_ABS}" \
        "${ASB_SHARD_WORKERS}" \
        "${ASB_SHARD_INFLIGHT}" \
        "${shard_csv}" \
        "${shard_log}" \
        "${shard_base_url}" &
      pids+=("$!")
      launched=1
    done

    if [[ "${#pids[@]}" -gt 0 ]]; then
      local pid
      for pid in "${pids[@]}"; do
        wait "${pid}"
      done
    fi

    merge_shards_csv "${final_csv}" "${OUT_DIR}" "${attack_type}" "${RUN_TAG}" "${ASB_SHARDS}"
    local final_done
    final_done="$(rows_in_csv "${final_csv}")"
    echo "[merge] ${attack_type} (${final_done}/${expected_rows}) -> ${final_csv}"

    if [[ "${final_done}" -ge "${expected_rows}" ]]; then
      echo "[done] ${attack_type}: ${final_csv}"
      return 0
    fi

    if [[ "${cycle}" -ge "${ASB_SHARD_MAX_CYCLES}" ]]; then
      echo "[error] ${attack_type}: exceeded ASB_SHARD_MAX_CYCLES=${ASB_SHARD_MAX_CYCLES} (${final_done}/${expected_rows})"
      return 1
    fi

    if [[ "${launched}" -eq 0 ]]; then
      echo "[error] ${attack_type}: no shard launched but incomplete (${final_done}/${expected_rows})"
      return 1
    fi
  done
}

run_one_single() {
  local attack_type="$1"
  local expected_rows="$2"
  local csv_path="${OUT_DIR}/${attack_type}-all_lowmem_${RUN_TAG}.csv"
  local log_path="${OUT_DIR}/${attack_type}-all_lowmem_${RUN_TAG}.log"

  if [[ -f "${csv_path}" && "${expected_rows}" -gt 0 ]]; then
    local rows_done
    rows_done="$(rows_in_csv "${csv_path}")"
    if [[ "${rows_done}" -ge "${expected_rows}" ]]; then
      echo "[skip] ${attack_type}: completed (${rows_done}/${expected_rows} rows): ${csv_path}"
      return 0
    fi
    echo "[resume] ${attack_type}: partial (${rows_done}/${expected_rows} rows), continuing in-place"
  fi

  echo "[run] ${attack_type}"
  run_main_attacker \
    "${attack_type}" \
    "${ATTACKER_TOOLS_PATH_ABS}" \
    "${TASKS_PATH_ABS}" \
    "${RESOLVED_MAX_WORKERS}" \
    "${RESOLVED_MAX_INFLIGHT}" \
    "${csv_path}" \
    "${log_path}" \
    "${OPENAI_BASE_URL}"

  echo "[done] ${attack_type}: ${csv_path}"
}

run_one() {
  local attack_type="$1"
  local expected_rows="$2"
  if [[ "${ASB_SHARDS}" -gt 1 ]]; then
    run_one_sharded "${attack_type}" "${expected_rows}"
  else
    run_one_single "${attack_type}" "${expected_rows}"
  fi
}

TASKS_PATH_ABS="$(resolve_path "${TASKS_PATH}")"
ATTACKER_TOOLS_PATH_ABS="$(resolve_path "${ATTACKER_TOOLS_PATH}")"
resolve_concurrency

EXPECTED_ROWS="${EXPECTED_ROWS:-}"
if [[ -z "${EXPECTED_ROWS}" ]]; then
  EXPECTED_ROWS="$(calc_expected_rows "${TASKS_PATH_ABS}" "${ATTACKER_TOOLS_PATH_ABS}" "${TASK_NUM}")"
fi

run_one naive "${EXPECTED_ROWS}"
run_one escape_characters "${EXPECTED_ROWS}"
run_one fake_completion "${EXPECTED_ROWS}"

echo "[all-done] tag=${RUN_TAG} out=${OUT_DIR}"
