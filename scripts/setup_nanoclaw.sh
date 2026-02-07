#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REPO_URL="https://github.com/gavrielc/nanoclaw.git"
PINNED_COMMIT="db216a459e51acd319c53c5c88b18c72d27447cf"
DEST="$ROOT/third_party/nanoclaw"

mkdir -p "$ROOT/third_party"

if [[ ! -d "$DEST/.git" ]]; then
  echo "[setup_nanoclaw] cloning $REPO_URL -> $DEST"
  git clone --depth 1 "$REPO_URL" "$DEST"
else
  echo "[setup_nanoclaw] found existing repo at $DEST"
fi

cd "$DEST"

# Best-effort pinning for artifact reproducibility.
if git rev-parse --verify "$PINNED_COMMIT^{commit}" >/dev/null 2>&1; then
  git checkout -q "$PINNED_COMMIT"
else
  # In shallow clones, the commit may not be present; fetch it directly.
  git fetch --depth 1 origin "$PINNED_COMMIT" || true
  git checkout -q "$PINNED_COMMIT" || true
fi

echo "[setup_nanoclaw] current HEAD: $(git rev-parse HEAD)"

