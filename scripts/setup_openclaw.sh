#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NODE_VERSION="$(node -p 'process.versions.node')"
REQ="22.12.0"
python - <<PY
import sys
def parse(v: str) -> tuple[int, int, int]:
    parts = (v.split(".") + ["0", "0", "0"])[:3]
    return (int(parts[0]), int(parts[1]), int(parts[2]))

node = "${NODE_VERSION}"
req = "${REQ}"
if parse(node) < parse(req):
    print(f"[setup_openclaw] Node {node} is too old; OpenClaw requires >= {req}.")
    sys.exit(2)
print(f"[setup_openclaw] Node {node} OK (>= {req}).")
PY

echo "[setup_openclaw] Installing OpenClaw (local, pinned) ..."
(cd integrations/openclaw_runner && npm install)

echo "[setup_openclaw] Done."
