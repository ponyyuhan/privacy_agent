#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ROOT="${RUN_ROOT:-${REPO_ROOT}/artifact_out_external_runtime/external_runs/20260304_agentdojo_four_parallel_rerun_v1}"
BASE_STATUS_JSON="${BASE_STATUS_JSON:-${RUN_ROOT}/drift_ipiguard_seq_resume_status.json}"
STATUS_MD="${STATUS_MD:-${RUN_ROOT}/drift_ipiguard_faramesh_followup_status.md}"
STATUS_JSON="${STATUS_JSON:-${RUN_ROOT}/drift_ipiguard_faramesh_followup_status.json}"
SUPERVISOR_LOG="${SUPERVISOR_LOG:-${RUN_ROOT}/logs/drift_ipiguard_faramesh_followup.log}"
FARAMESH_OUT="${FARAMESH_OUT:-${RUN_ROOT}/agentdojo_faramesh_only}"
FARAMESH_PID_FILE="${FARAMESH_PID_FILE:-${REPO_ROOT}/tmp/agentdojo_faramesh_followup.pid}"
MODEL="${MODEL:-gpt-4o-mini-2024-07-18}"
BENCHMARK_VERSION="${BENCHMARK_VERSION:-v1.1.2}"
ATTACK_NAME="${ATTACK_NAME:-important_instructions}"
SUITES="${SUITES:-banking,slack,travel,workspace}"
STATUS_INTERVAL_S="${STATUS_INTERVAL_S:-60}"
RETRY_SLEEP_S="${RETRY_SLEEP_S:-30}"

mkdir -p "$(dirname "${STATUS_MD}")" "$(dirname "${SUPERVISOR_LOG}")" "$(dirname "${FARAMESH_PID_FILE}")"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')" "$1" | tee -a "${SUPERVISOR_LOG}"
}

compute_snapshot() {
  python - "${REPO_ROOT}" "${RUN_ROOT}" "${BASE_STATUS_JSON}" "${BENCHMARK_VERSION}" <<'PY'
import json
import sys
from pathlib import Path
repo_root = Path(sys.argv[1])
run_root = Path(sys.argv[2])
base_status_json = Path(sys.argv[3])
benchmark = sys.argv[4]
sys.path.insert(0, str(repo_root / 'third_party' / 'agentdojo' / 'src'))
from agentdojo.task_suite.load_suites import get_suite  # type: ignore

def expected_rows(suite_name: str, mode: str) -> int:
    suite = get_suite(benchmark, suite_name)
    benign = int(len(suite.user_tasks))
    if hasattr(suite, 'get_injections_for_user_task'):
        under_attack = sum(int(len(suite.get_injections_for_user_task(ut))) for ut in suite.user_tasks.values())
    else:
        under_attack = benign * int(len(getattr(suite, 'injection_tasks', {}) or {}))
    return benign if mode == 'benign' else under_attack

def parse_results(path: Path, mode: str) -> dict:
    if not path.exists():
        return {'rows': 0, 'summary': False, 'max_user': -1, 'max_iid': -1}
    text = path.read_text(encoding='utf-8', errors='replace')
    dec = json.JSONDecoder(); i = 0; n = len(text)
    seen = set(); has_summary = False; max_user = -1; max_iid = -1
    while i < n:
        while i < n and text[i].isspace(): i += 1
        if i >= n: break
        try:
            obj, j = dec.raw_decode(text, i); i = j
        except json.JSONDecodeError:
            i += 1; continue
        if not isinstance(obj, dict):
            continue
        if 'Suite' in obj and 'ASR' in obj:
            has_summary = True
        if mode == 'under_attack':
            if 'user_task_id' in obj and obj.get('injection_task_id') is not None:
                try: uid = int(obj.get('user_task_id', -1))
                except Exception: uid = -1
                try: iid = int(obj.get('injection_task_id', -1))
                except Exception: iid = -1
                seen.add((uid, iid))
                if uid > max_user or (uid == max_user and iid > max_iid):
                    max_user, max_iid = uid, iid
        else:
            if 'user_task_id' in obj and ('injection_task_id' not in obj or obj.get('injection_task_id') is None):
                try: uid = int(obj.get('user_task_id', -1))
                except Exception: uid = -1
                seen.add((uid, None))
                if uid > max_user: max_user = uid
    return {'rows': len(seen), 'summary': has_summary, 'max_user': max_user, 'max_iid': max_iid}

base = {}
if base_status_json.exists():
    try: base = json.loads(base_status_json.read_text(encoding='utf-8'))
    except Exception: base = {}

drift_complete = bool(base.get('drift_complete'))
ipiguard_complete = bool(base.get('ipiguard_complete'))
far_root = run_root / 'agentdojo_faramesh_only' / 'faramesh'
far = {}
far_complete = True
for mode in ['benign', 'under_attack']:
    far[mode] = {}
    for suite_name in ['banking', 'slack', 'travel', 'workspace']:
        expected = expected_rows(suite_name, mode)
        info = parse_results(far_root / mode / suite_name / 'results.jsonl', mode)
        info['expected'] = expected
        far[mode][suite_name] = info
        if info['rows'] != expected or not info['summary']:
            far_complete = False
print(json.dumps({'drift_complete': drift_complete, 'ipiguard_complete': ipiguard_complete, 'faramesh': far, 'faramesh_complete': far_complete}))
PY
}

write_status() {
  local phase="$1"
  local child_pid="$2"
  local current_log="$3"
  local snapshot
  snapshot="$(compute_snapshot)"
  printf '%s\n' "${snapshot}" > "${STATUS_JSON}"
  python - "${STATUS_JSON}" "${STATUS_MD}" "${phase}" "${child_pid}" "${current_log}" "${SUPERVISOR_LOG}" <<'PY'
import json, sys
from datetime import datetime
from pathlib import Path
status_json = Path(sys.argv[1]); status_md = Path(sys.argv[2])
phase = sys.argv[3]; child_pid = sys.argv[4]; current_log = sys.argv[5]; supervisor_log = sys.argv[6]
payload = json.loads(status_json.read_text())
lines = [
    '# DRIFT/IPIGuard → Faramesh Follow-up Status',
    f'- updated: {datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")}',
    f'- phase: {phase}',
    f'- active_pid: {child_pid}',
    f'- current_log: {current_log}',
    f'- supervisor_log: {supervisor_log}',
    '',
    '## Upstream',
    f"- drift_complete: {payload.get('drift_complete')}",
    f"- ipiguard_complete: {payload.get('ipiguard_complete')}",
    '',
    '## Faramesh',
    f"- complete: {payload.get('faramesh_complete')}",
]
for mode, suites in payload.get('faramesh', {}).items():
    for suite, info in suites.items():
        lines.append(f"- {mode}/{suite}: {info.get('rows')}/{info.get('expected')}, summary={info.get('summary')}, last=({info.get('max_user')},{info.get('max_iid')})")
status_md.write_text('\n'.join(lines) + '\n', encoding='utf-8')
PY
}

phase_done() {
  python - "${STATUS_JSON}" "$1" <<'PY'
import json, sys
payload = json.load(open(sys.argv[1]))
print('1' if payload.get(sys.argv[2]) else '0')
PY
}

launch_faramesh() {
  local current_log="$1"
  (
    cd "${REPO_ROOT}"
    env OPENAI_API_KEY="${OPENAI_API_KEY}" OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://api.openai.com/v1}" BENCHMARK_VERSION="${BENCHMARK_VERSION}" MODEL="${MODEL}" ATTACK_NAME="${ATTACK_NAME}" \
      python scripts/run_agentdojo_faramesh.py --out-root "${FARAMESH_OUT}" --model "${MODEL}" --benchmark-version "${BENCHMARK_VERSION}" --attack-name "${ATTACK_NAME}" --suites "${SUITES}" --modes "benign,under_attack"
  ) >> "${current_log}" 2>&1 &
  echo $! > "${FARAMESH_PID_FILE}"
  echo $!
}

existing_faramesh_pid() {
  if [[ -f "${FARAMESH_PID_FILE}" ]]; then
    local pid
    pid="$(cat "${FARAMESH_PID_FILE}")"
    if kill -0 "${pid}" 2>/dev/null; then
      echo "${pid}"
      return 0
    fi
  fi
  local pid
  pid="$(pgrep -f "run/eval.py --benchmark_version .* --defense_name faramesh" | head -n 1 || true)"
  if [[ -n "${pid}" ]]; then
    echo "${pid}"
  fi
}

log 'Follow-up watcher starting.'
phase='waiting'; child_pid='-'; current_log='-'
while true; do
  write_status "${phase}" "${child_pid}" "${current_log}"
  drift_done="$(phase_done drift_complete)"
  ipi_done="$(phase_done ipiguard_complete)"
  far_done="$(phase_done faramesh_complete)"
  if [[ "${far_done}" == "1" ]]; then
    phase='report'
    report_json="${RUN_ROOT}/agentdojo_five_baseline_final_report.json"
    report_md="${RUN_ROOT}/agentdojo_five_baseline_final_report.md"
    if [[ ! -f "${report_json}" ]]; then
      log 'Faramesh complete; generating five-baseline report.'
      python "${REPO_ROOT}/scripts/agentdojo_five_baseline_fair_report.py" --plain-root "${RUN_ROOT}/agentdojo_plain_only/plain" --secureclaw-root "${RUN_ROOT}/agentdojo_secureclaw_only/secureclaw" --ipiguard-root "${RUN_ROOT}/agentdojo_ipiguard_only/ipiguard" --drift-run-root "${RUN_ROOT}/agentdojo_drift_only_r2" --faramesh-root "${RUN_ROOT}/agentdojo_faramesh_only/faramesh" --model "${MODEL}" --attack-name "${ATTACK_NAME}" --benchmark-version "${BENCHMARK_VERSION}" --require-equal-attacks 1 --require-equal-benign 1 --output-json "${report_json}" --output-md "${report_md}" >> "${SUPERVISOR_LOG}" 2>&1 || true
    fi
    write_status 'complete' '-' "${current_log}"
    log 'Follow-up watcher complete.'
    exit 0
  fi
  if [[ "${drift_done}" != "1" || "${ipi_done}" != "1" ]]; then
    phase='waiting'; child_pid='-'; sleep "${STATUS_INTERVAL_S}"; continue
  fi
  phase='faramesh'
  child_pid="$(existing_faramesh_pid || true)"
  if [[ -z "${child_pid}" ]]; then
    current_log="${RUN_ROOT}/logs/faramesh_resume_pass_$(date '+%Y%m%d_%H%M%S').log"
    log "Launching Faramesh pass. log=${current_log}"
    child_pid="$(launch_faramesh "${current_log}")"
  fi
  while kill -0 "${child_pid}" 2>/dev/null; do
    write_status "${phase}" "${child_pid}" "${current_log}"
    sleep "${STATUS_INTERVAL_S}"
  done
  sleep "${RETRY_SLEEP_S}"
done
