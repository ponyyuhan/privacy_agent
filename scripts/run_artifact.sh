#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT"

OUT_DIR="${OUT_DIR:-$ROOT/artifact_out}"
mkdir -p "$OUT_DIR"

echo "[artifact] 1) unit tests"
python -m unittest discover -s tests -p 'test_*.py' 2>&1 | tee "$OUT_DIR/unittest.txt"

echo "[artifact] 2) FSS/DPF micro-benchmark"
python scripts/bench_fss.py | tee "$OUT_DIR/bench_fss.txt"

echo "[artifact] 2b) FSS/DPF curve (CSV)"
OUT_CSV="$OUT_DIR/bench_fss_curve.csv" python scripts/bench_fss_curve.py | tee "$OUT_DIR/bench_fss_curve.txt"

echo "[artifact] 3) end-to-end demo + JSON report (policy servers + executor + MCP gateway)"
python scripts/artifact_report.py | tee "$OUT_DIR/report_path.txt"

echo "[artifact] 4) end-to-end throughput (short)"
BENCH_ITERS="${BENCH_ITERS:-10}" BENCH_CONCURRENCY="${BENCH_CONCURRENCY:-2}" python scripts/bench_e2e_throughput.py | tee "$OUT_DIR/bench_e2e_path.txt"

echo "[artifact] done; outputs at: $OUT_DIR"
