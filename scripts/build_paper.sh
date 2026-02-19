#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TEX="${TEX:-neurips_2025.tex}"
OUT_DIR="${OUT_DIR:-$ROOT/artifact_out/paper_build}"
mkdir -p "$OUT_DIR"

PDFLATEX="${PDFLATEX:-pdflatex}"
BIBTEX="${BIBTEX:-bibtex}"

export TEXINPUTS="$ROOT/third_party/latex/environ:$ROOT/third_party/latex/trimspaces:${TEXINPUTS:-}"

run_pdflatex () {
  "$PDFLATEX" -interaction=nonstopmode -halt-on-error -file-line-error \
    -output-directory "$OUT_DIR" "$TEX" >/dev/null
}

echo "[paper] building $TEX into $OUT_DIR"
run_pdflatex

# Bibliography (best-effort). If no .aux was produced or there are no citations, bibtex may fail.
if [[ -f "$OUT_DIR/neurips_2025.aux" ]]; then
  set +e
  "$BIBTEX" "$OUT_DIR/neurips_2025.aux" >/dev/null 2>&1
  set -e
fi

run_pdflatex
run_pdflatex

PDF_OUT="$OUT_DIR/neurips_2025.pdf"
if [[ ! -f "$PDF_OUT" ]]; then
  echo "[paper] missing pdf output: $PDF_OUT" >&2
  exit 2
fi
echo "$PDF_OUT"
