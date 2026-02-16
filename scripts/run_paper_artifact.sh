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

echo "[paper] 8) native runtime baselines (codex/claude/openclaw)"
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

echo "[paper] done; outputs in $OUT_DIR"
