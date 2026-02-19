#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT"

OUT_DIR="${OUT_DIR:-$ROOT/artifact_out}"
mkdir -p "$OUT_DIR"
export AUDIT_LOG_PATH="${AUDIT_LOG_PATH:-$OUT_DIR/audit.jsonl}"

# Deterministic defaults for reproducibility.
export MIRAGE_SEED="${MIRAGE_SEED:-7}"
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"

# Paper-scale defaults (override by env when needed).
export EVAL_ATTACKS_PER_CATEGORY="${EVAL_ATTACKS_PER_CATEGORY:-60}"
export EVAL_BENIGNS_PER_CATEGORY="${EVAL_BENIGNS_PER_CATEGORY:-60}"
export POLICY_CURVE_REQUESTS="${POLICY_CURVE_REQUESTS:-80}"
export POLICY_CURVE_CONCURRENCY="${POLICY_CURVE_CONCURRENCY:-8}"
export REAL_AGENT_REPS="${REAL_AGENT_REPS:-1}"


echo "[paper] 1) unit tests"
python -m unittest discover -s tests -p 'test_*.py' 2>&1 | tee "$OUT_DIR/unittest.paper.txt"

echo "[paper] 2) formal security game check (NBE theorem harness)"
PYTHONPATH=. python scripts/security_game_nbe_check.py | tee "$OUT_DIR/security_game_nbe_path.txt"

echo "[paper] 3) strong baseline + large-scale eval"
if command -v cargo >/dev/null 2>&1; then
  POLICY_BACKEND="${POLICY_BACKEND:-rust}" PYTHONPATH=. python scripts/paper_eval.py | tee "$OUT_DIR/paper_eval_path.txt"
else
  POLICY_BACKEND="${POLICY_BACKEND:-python}" PYTHONPATH=. python scripts/paper_eval.py | tee "$OUT_DIR/paper_eval_path.txt"
fi

echo "[paper] 3b) AgentLeak-style C1..C7 channel evaluation"
if command -v cargo >/dev/null 2>&1; then
  POLICY_BACKEND="${POLICY_BACKEND:-rust}" PYTHONPATH=. python scripts/agentleak_channel_eval.py | tee "$OUT_DIR/agentleak_eval_path.txt"
else
  POLICY_BACKEND="${POLICY_BACKEND:-python}" PYTHONPATH=. python scripts/agentleak_channel_eval.py | tee "$OUT_DIR/agentleak_eval_path.txt"
fi

echo "[paper] 3c) official AgentLeak C1..C5 fair comparison (MIRAGE + native Codex/OpenClaw baselines)"
if [[ "${RUN_FAIR_FULL:-0}" == "1" ]]; then
  OUT_DIR_COMPARE="${OUT_DIR_COMPARE:-$ROOT/artifact_out_compare}"
  mkdir -p "$OUT_DIR_COMPARE"
  # Codex/OpenClaw baselines can be slow and may require external credentials; keep optional.
  CODEX_BASELINE_CONCURRENCY="${CODEX_BASELINE_CONCURRENCY:-4}" \
    OPENCLAW_BASELINE_CONCURRENCY="${OPENCLAW_BASELINE_CONCURRENCY:-2}" \
    CODEX_BASELINE_REASONING="${CODEX_BASELINE_REASONING:-low}" \
    FAIR_FULL_REUSE_NATIVE="${FAIR_FULL_REUSE_NATIVE:-1}" \
    FAIR_FULL_REUSE_SECURECLAW="${FAIR_FULL_REUSE_SECURECLAW:-1}" \
    OUT_DIR="$OUT_DIR_COMPARE" \
    PYTHONPATH=. python scripts/fair_full_compare.py | tee "$OUT_DIR_COMPARE/fair_full_compare_path.txt"
  PYTHONPATH=. python scripts/fair_full_stats.py --report "$OUT_DIR_COMPARE/fair_full_report.json" --out "$OUT_DIR_COMPARE/stats/fair_full_stats.json" \
    | tee "$OUT_DIR_COMPARE/fair_full_stats_path.txt"
  PYTHONPATH=. python scripts/fair_utility_breakdown.py --report "$OUT_DIR_COMPARE/fair_full_report.json" --out "$OUT_DIR_COMPARE/stats/fair_utility_breakdown.json" \
    | tee "$OUT_DIR_COMPARE/fair_utility_breakdown_path.txt"
else
  echo "[paper] skip fair_full_compare (set RUN_FAIR_FULL=1)" | tee "$OUT_DIR/fair_full_compare_skipped.txt"
fi

echo "[paper] 4) policy server throughput curves (batch/padding, python+rust)"
PYTHONPATH=. python scripts/bench_policy_server_curves.py | tee "$OUT_DIR/policy_curve_path.txt"

echo "[paper] 5) policy server scaling (single/multi core, json vs binary)"
if command -v cargo >/dev/null 2>&1; then
  PYTHONPATH=. python scripts/bench_policy_server_scaling.py | tee "$OUT_DIR/policy_scaling_path.txt"
else
  echo "[paper] skip policy scaling: cargo not found" | tee "$OUT_DIR/policy_scaling_path.txt"
fi

echo "[paper] 6) end-to-end throughput benches"
BENCH_ITERS="${BENCH_ITERS:-30}" BENCH_CONCURRENCY="${BENCH_CONCURRENCY:-8}" POLICY_BACKEND=python BENCH_OUT_PATH="$OUT_DIR/bench_e2e.paper.python.json" \
  python scripts/bench_e2e_throughput.py | tee "$OUT_DIR/bench_e2e_paper_python_path.txt"
if command -v cargo >/dev/null 2>&1; then
  BENCH_ITERS="${BENCH_ITERS:-30}" BENCH_CONCURRENCY="${BENCH_CONCURRENCY:-8}" POLICY_BACKEND=rust BENCH_OUT_PATH="$OUT_DIR/bench_e2e.paper.rust.json" \
    python scripts/bench_e2e_throughput.py | tee "$OUT_DIR/bench_e2e_paper_rust_path.txt"
fi

echo "[paper] 7) end-to-end shaping curves (mixing/padding/cover)"
if command -v cargo >/dev/null 2>&1; then
  POLICY_BACKEND=rust PYTHONPATH=. python scripts/bench_e2e_shaping_curves.py | tee "$OUT_DIR/bench_e2e_shaping_curves_path.txt"
else
  POLICY_BACKEND=python PYTHONPATH=. python scripts/bench_e2e_shaping_curves.py | tee "$OUT_DIR/bench_e2e_shaping_curves_path.txt"
fi

echo "[paper] 7b) production performance report (target ops + scaling summary)"
PYTHONPATH=. python scripts/perf_production_report.py --run-missing 0 | tee "$OUT_DIR/perf_production_report_path.txt"

echo "[paper] 7c) leakage channel report (C1..C7 + distinguishability summary)"
PYTHONPATH=. python scripts/leakage_channel_report.py | tee "$OUT_DIR/leakage_channel_report_path.txt"

echo "[paper] 8) native runtime baselines (codex/openclaw)"
PYTHONPATH=. python scripts/native_guardrail_eval.py | tee "$OUT_DIR/native_guardrail_eval_path.txt"

echo "[paper] 9) real-agent closed-loop campaign (openclaw/nanoclaw/scripted)"
set +e
PYTHONPATH=. python scripts/real_agent_campaign.py | tee "$OUT_DIR/real_agent_campaign_path.txt"
RC=$?
set -e
if [[ "$RC" -ne 0 ]]; then
  echo "[paper] real_agent_campaign returned $RC (continuing for reproducibility pipeline)." | tee "$OUT_DIR/real_agent_campaign_warn.txt"
fi

echo "[paper] 10) verify audit log chaining"
PYTHONPATH=. python scripts/verify_audit_log.py | tee "$OUT_DIR/audit_verify.json"

echo "[paper] 11) auto plots"
PYTHONPATH=. python scripts/plot_paper_figures.py | tee "$OUT_DIR/figures_path.txt"

echo "[paper] 12) repro manifest"
PYTHONPATH=. python scripts/write_repro_manifest.py | tee "$OUT_DIR/repro_manifest_path.txt"

echo "[paper] 12b) submission convergence snapshot"
PYTHONPATH=. python scripts/write_submission_convergence.py | tee "$OUT_DIR/submission_convergence_path.txt" || true

echo "[paper] done; outputs in $OUT_DIR"
