#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ROOT="${RUN_ROOT:-${REPO_ROOT}/artifact_out_external_runtime/external_runs/20260304_agentdojo_four_parallel_rerun_v1}"
DRIFT_OUT="${DRIFT_OUT:-${RUN_ROOT}/agentdojo_drift_only_r2}"
IPIGUARD_OUT="${IPIGUARD_OUT:-${RUN_ROOT}/agentdojo_ipiguard_only}"
STATUS_MD="${STATUS_MD:-${RUN_ROOT}/drift_ipiguard_seq_resume_status.md}"
STATUS_JSON="${STATUS_JSON:-${RUN_ROOT}/drift_ipiguard_seq_resume_status.json}"
SUPERVISOR_LOG="${SUPERVISOR_LOG:-${RUN_ROOT}/logs/drift_ipiguard_seq_resume_supervisor.log}"
MODEL="${MODEL:-gpt-4o-mini-2024-07-18}"
BENCHMARK_VERSION="${BENCHMARK_VERSION:-v1.1.2}"
IPIGUARD_BENCHMARK_VERSION="${IPIGUARD_BENCHMARK_VERSION:-${BENCHMARK_VERSION}}"
ATTACK_NAME="${ATTACK_NAME:-important_instructions}"
DRIFT_SUITES="${DRIFT_SUITES:-banking,slack,travel,workspace}"
DRIFT_MODES="${DRIFT_MODES:-benign,attack}"
OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://api.openai.com/v1}"
STATUS_INTERVAL_S="${STATUS_INTERVAL_S:-60}"
RETRY_SLEEP_S="${RETRY_SLEEP_S:-30}"
TMUX_SESSION_NAME="${TMUX_SESSION_NAME:-drift_ipiguard_seq_resume}"
QUOTA_FLAG="${QUOTA_FLAG:-${RUN_ROOT}/fatal_insufficient_quota.flag}"

mkdir -p "$(dirname "${STATUS_MD}")" "$(dirname "${SUPERVISOR_LOG}")"

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
  echo "[fatal] OPENAI_API_KEY is missing." | tee -a "${SUPERVISOR_LOG}"
  exit 1
fi

if [[ -f "${QUOTA_FLAG}" ]]; then
  echo "[fatal] Quota flag present at ${QUOTA_FLAG}; refusing to start supervisor." | tee -a "${SUPERVISOR_LOG}"
  exit 86
fi

snapshot_status() {
  python - "${REPO_ROOT}" "${RUN_ROOT}" "${BENCHMARK_VERSION}" "${MODEL}" <<'PY'
import json
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
run_root = Path(sys.argv[2])
benchmark = sys.argv[3]
model = sys.argv[4]

sys.path.insert(0, str(repo_root / "third_party" / "agentdojo" / "src"))
from agentdojo.task_suite.load_suites import get_suite  # type: ignore


def expected_rows(suite_name: str, mode: str) -> int:
    suite = get_suite(benchmark, suite_name)
    benign = int(len(suite.user_tasks))
    if hasattr(suite, "get_injections_for_user_task"):
        under_attack = sum(int(len(suite.get_injections_for_user_task(ut))) for ut in suite.user_tasks.values())
    else:
        under_attack = benign * int(len(getattr(suite, "injection_tasks", {}) or {}))
    return benign if mode == "benign" else under_attack


def parse_ipiguard(results_path: Path, mode: str) -> dict:
    if not results_path.exists():
        return {"rows": 0, "summary": False, "max_user": -1, "max_iid": -1}
    text = results_path.read_text(encoding="utf-8", errors="replace")
    dec = json.JSONDecoder()
    i = 0
    n = len(text)
    seen = set()
    has_summary = False
    max_user = -1
    max_iid = -1
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        try:
            obj, j = dec.raw_decode(text, i)
            i = j
        except json.JSONDecodeError:
            i += 1
            continue
        if not isinstance(obj, dict):
            continue
        if "Suite" in obj and "ASR" in obj:
            has_summary = True
        if mode == "under_attack":
            if "user_task_id" in obj and obj.get("injection_task_id") is not None:
                try:
                    uid = int(obj.get("user_task_id", -1))
                except Exception:
                    uid = -1
                try:
                    iid = int(obj.get("injection_task_id", -1))
                except Exception:
                    iid = -1
                seen.add((uid, iid))
                if uid > max_user or (uid == max_user and iid > max_iid):
                    max_user, max_iid = uid, iid
        else:
            if "user_task_id" in obj and ("injection_task_id" not in obj or obj.get("injection_task_id") is None):
                try:
                    uid = int(obj.get("user_task_id", -1))
                except Exception:
                    uid = -1
                seen.add((uid, None))
                if uid > max_user:
                    max_user = uid
    return {"rows": len(seen), "summary": has_summary, "max_user": max_user, "max_iid": max_iid}


suites = ["banking", "slack", "travel", "workspace"]
drift_root = run_root / "agentdojo_drift_only_r2" / "drift_workspace" / "runs" / model
ip_root = run_root / "agentdojo_ipiguard_only" / "ipiguard"

drift = {}
drift_complete = True
for suite in suites:
    benign_expected = expected_rows(suite, "benign")
    attack_expected = expected_rows(suite, "under_attack")
    suite_root = drift_root / suite
    benign_got = len(list(suite_root.glob("user_task_*/none/none.json")))
    attack_got = len(list(suite_root.glob("user_task_*/important_instructions/injection_task_*.json")))
    drift[suite] = {
        "benign": {"rows": benign_got, "expected": benign_expected},
        "under_attack": {"rows": attack_got, "expected": attack_expected},
    }
    if benign_got != benign_expected or attack_got != attack_expected:
        drift_complete = False

ipiguard = {}
ipig_complete = True
for mode in ["benign", "under_attack"]:
    ipiguard[mode] = {}
    for suite in suites:
        expected = expected_rows(suite, mode)
        info = parse_ipiguard(ip_root / mode / suite / "results.jsonl", mode)
        info["expected"] = expected
        ipiguard[mode][suite] = info
        if info["rows"] != expected or not info["summary"]:
            ipig_complete = False

payload = {
    "drift": drift,
    "drift_complete": drift_complete,
    "ipiguard": ipiguard,
    "ipiguard_complete": ipig_complete,
}
print(json.dumps(payload))
PY
}

write_status() {
  local phase="$1"
  local child_pid="$2"
  local last_rc="$3"
  local current_log="$4"
  local snapshot
  snapshot="$(snapshot_status)"
  printf '%s\n' "${snapshot}" > "${STATUS_JSON}"
  python - "${STATUS_JSON}" "${STATUS_MD}" "${phase}" "${child_pid}" "${last_rc}" "${current_log}" "${SUPERVISOR_LOG}" "${TMUX_SESSION_NAME}" <<'PY'
import json
import sys
from datetime import datetime
from pathlib import Path

status_json = Path(sys.argv[1])
status_md = Path(sys.argv[2])
phase = sys.argv[3]
child_pid = sys.argv[4]
last_rc = sys.argv[5]
current_log = sys.argv[6]
supervisor_log = sys.argv[7]
tmux_session = sys.argv[8]
payload = json.loads(status_json.read_text())

lines = [
    "# DRIFT/IPIGuard Sequential Resume Status",
    f"- updated: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}",
    f"- phase: {phase}",
    f"- active_pid: {child_pid}",
    f"- last_exit_code: {last_rc}",
    f"- tmux_session: {tmux_session}",
    f"- current_pass_log: {current_log}",
    f"- supervisor_log: {supervisor_log}",
    "",
    "## DRIFT",
    f"- complete: {payload['drift_complete']}",
]
for suite, info in payload["drift"].items():
    lines.append(
        f"- {suite}: benign {info['benign']['rows']}/{info['benign']['expected']}, "
        f"under_attack {info['under_attack']['rows']}/{info['under_attack']['expected']}"
    )

lines.extend(["", "## IPIGuard", f"- complete: {payload['ipiguard_complete']}"])
for mode, suites in payload["ipiguard"].items():
    for suite, info in suites.items():
        lines.append(
            f"- {mode}/{suite}: {info['rows']}/{info['expected']}, "
            f"summary={info['summary']}, last=({info['max_user']},{info['max_iid']})"
        )

status_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
}

phase_complete() {
  local key="$1"
  python - "${STATUS_JSON}" "${key}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1]))
print("1" if payload.get(sys.argv[2]) else "0")
PY
}

log() {
  local message="$1"
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')" "${message}" | tee -a "${SUPERVISOR_LOG}"
}

run_phase() {
  local phase="$1"
  local current_log="$2"
  if [[ "${phase}" == "drift" ]]; then
    (
      cd "${REPO_ROOT}"
      env \
        OPENAI_API_KEY="${OPENAI_API_KEY}" \
        OPENAI_BASE_URL="${OPENAI_BASE_URL}" \
        BENCHMARK_VERSION="${BENCHMARK_VERSION}" \
        IPIGUARD_BENCHMARK_VERSION="${IPIGUARD_BENCHMARK_VERSION}" \
        MODEL="${MODEL}" \
        ATTACK_NAME="${ATTACK_NAME}" \
        DRIFT_SUITES="${DRIFT_SUITES}" \
        DRIFT_MODES="${DRIFT_MODES}" \
        OUT_ROOT="${DRIFT_OUT}" \
        DRIFT_WORKSPACE="${DRIFT_OUT}/drift_workspace" \
        RUN_DRIFT=1 \
        RUN_IPIGUARD=0 \
        DRIFT_OPENAI_TIMEOUT_S="${DRIFT_OPENAI_TIMEOUT_S:-300}" \
        DRIFT_OPENAI_MAX_RETRIES="${DRIFT_OPENAI_MAX_RETRIES:-8}" \
        DRIFT_CHAT_RETRIES="${DRIFT_CHAT_RETRIES:-6}" \
        DRIFT_CHAT_RETRY_BACKOFF_S="${DRIFT_CHAT_RETRY_BACKOFF_S:-1.5}" \
        bash scripts/run_drift_ipiguard_full_lowmem.sh
    ) >> "${current_log}" 2>&1 &
  else
    (
      cd "${REPO_ROOT}"
      env \
        OPENAI_API_KEY="${OPENAI_API_KEY}" \
        OPENAI_BASE_URL="${OPENAI_BASE_URL}" \
        BENCHMARK_VERSION="${BENCHMARK_VERSION}" \
        IPIGUARD_BENCHMARK_VERSION="${IPIGUARD_BENCHMARK_VERSION}" \
        MODEL="${MODEL}" \
        ATTACK_NAME="${ATTACK_NAME}" \
        DRIFT_SUITES="${DRIFT_SUITES}" \
        OUT_ROOT="${IPIGUARD_OUT}" \
        QUOTA_FLAG="${QUOTA_FLAG}" \
        RUN_DRIFT=0 \
        RUN_IPIGUARD=1 \
        IPIGUARD_OPENAI_TIMEOUT_S="${IPIGUARD_OPENAI_TIMEOUT_S:-120}" \
        IPIGUARD_OPENAI_MAX_RETRIES="${IPIGUARD_OPENAI_MAX_RETRIES:-8}" \
        IPIGUARD_LLM_RETRY_ATTEMPTS="${IPIGUARD_LLM_RETRY_ATTEMPTS:-3}" \
        IPIGUARD_LLM_RETRY_MAX_WAIT_S="${IPIGUARD_LLM_RETRY_MAX_WAIT_S:-40}" \
        IPIGUARD_LLM_RETRY_BACKOFF_S="${IPIGUARD_LLM_RETRY_BACKOFF_S:-2}" \
        IPIGUARD_LLM_RETRY_HINT_SCALE="${IPIGUARD_LLM_RETRY_HINT_SCALE:-1.0}" \
        IPIGUARD_LLM_RETRY_HINT_JITTER_S="${IPIGUARD_LLM_RETRY_HINT_JITTER_S:-0.5}" \
        bash scripts/run_drift_ipiguard_full_lowmem.sh
    ) >> "${current_log}" 2>&1 &
  fi
  echo $!
}

if [[ "${1:-}" == "--status-once" ]]; then
  write_status "idle" "-" "-" "-"
  exit 0
fi

log "Supervisor starting."
phase="init"
child_pid="-"
last_rc="-"
current_log="-"

while true; do
  write_status "${phase}" "${child_pid}" "${last_rc}" "${current_log}"
  local_drift_complete="$(phase_complete drift_complete)"
  local_ipig_complete="$(phase_complete ipiguard_complete)"

  if [[ "${local_drift_complete}" == "1" && "${local_ipig_complete}" == "1" ]]; then
    phase="complete"
    write_status "${phase}" "-" "${last_rc}" "${current_log}"
    log "All DRIFT and IPIGuard work completed."
    exit 0
  fi

  if [[ "${local_drift_complete}" != "1" ]]; then
    phase="drift"
  else
    phase="ipiguard"
  fi

  current_log="${RUN_ROOT}/logs/${phase}_resume_pass_$(date '+%Y%m%d_%H%M%S').log"
  log "Starting ${phase} pass. log=${current_log}"
  child_pid="$(run_phase "${phase}" "${current_log}")"

  while kill -0 "${child_pid}" 2>/dev/null; do
    write_status "${phase}" "${child_pid}" "${last_rc}" "${current_log}"
    sleep "${STATUS_INTERVAL_S}"
  done

  set +e
  wait "${child_pid}"
  last_rc="$?"
  set -e
  log "${phase} pass exited rc=${last_rc}."
  write_status "${phase}" "-" "${last_rc}" "${current_log}"
  sleep "${RETRY_SLEEP_S}"
done
