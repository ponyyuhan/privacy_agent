#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT"

cleanup () {
  # Best-effort cleanup; avoid failing on kill if already exited.
  if [[ -n "${GW:-}" ]]; then kill "$GW" 2>/dev/null || true; fi
  if [[ -n "${EX:-}" ]]; then kill "$EX" 2>/dev/null || true; fi
  if [[ -n "${P0:-}" ]]; then kill "$P0" 2>/dev/null || true; fi
  if [[ -n "${P1:-}" ]]; then kill "$P1" 2>/dev/null || true; fi
}
trap cleanup EXIT

python -m policy_server.build_dbs

pick_port () {
  python - <<'PY'
import socket
s=socket.socket()
s.bind(("",0))
print(s.getsockname()[1])
s.close()
PY
}

wait_http_ok () {
  local url="$1"
  local tries="${2:-50}"
  python - <<PY
import time, sys
import requests
url="${url}"
tries=int("${tries}")
for i in range(tries):
    try:
        r = requests.get(url, timeout=0.5)
        if r.status_code == 200:
            sys.exit(0)
    except Exception:
        pass
    time.sleep(0.1)
sys.exit(1)
PY
}

# Choose free ports automatically (override by env if desired)
P0_PORT="${P0_PORT:-$(pick_port)}"
P1_PORT="${P1_PORT:-$(pick_port)}"
EX_PORT="${EX_PORT:-$(pick_port)}"

export POLICY0_URL="http://localhost:${P0_PORT}"
export POLICY1_URL="http://localhost:${P1_PORT}"
export EXECUTOR_URL="http://localhost:${EX_PORT}"
export DLP_MODE="${DLP_MODE:-dfa}"
export SIGNED_PIR="${SIGNED_PIR:-1}"

# Per-policy-server MAC keys for dual authorization.
export POLICY0_MAC_KEY="${POLICY0_MAC_KEY:-$(python -c 'import secrets; print(secrets.token_hex(32))')}"
export POLICY1_MAC_KEY="${POLICY1_MAC_KEY:-$(python -c 'import secrets; print(secrets.token_hex(32))')}"

echo "[run_all] POLICY0_URL=${POLICY0_URL}"
echo "[run_all] POLICY1_URL=${POLICY1_URL}"
echo "[run_all] EXECUTOR_URL=${EXECUTOR_URL}"
echo "[run_all] DLP_MODE=${DLP_MODE}"
echo "[run_all] SIGNED_PIR=${SIGNED_PIR}"
echo "[run_all] POLICY_BACKEND=${POLICY_BACKEND:-python}"

# Start policy servers
POLICY_BACKEND="${POLICY_BACKEND:-python}"
if [[ "$POLICY_BACKEND" == "rust" ]]; then
  BIN="$ROOT/policy_server_rust/target/release/mirage_policy_server"
  if [[ ! -x "$BIN" ]]; then
    echo "[run_all] building rust policy server..."
    (cd "$ROOT/policy_server_rust" && cargo build --release)
  fi
  SERVER_ID=0 PORT="${P0_PORT}" DATA_DIR="policy_server/data" POLICY_MAC_KEY="${POLICY0_MAC_KEY}" "$BIN" &
  P0=$!
  SERVER_ID=1 PORT="${P1_PORT}" DATA_DIR="policy_server/data" POLICY_MAC_KEY="${POLICY1_MAC_KEY}" "$BIN" &
  P1=$!
else
  SERVER_ID=0 PORT="${P0_PORT}" POLICY_MAC_KEY="${POLICY0_MAC_KEY}" python -m policy_server.server &
  P0=$!
  SERVER_ID=1 PORT="${P1_PORT}" POLICY_MAC_KEY="${POLICY1_MAC_KEY}" python -m policy_server.server &
  P1=$!
fi

# Start executor
EXECUTOR_PORT="${EX_PORT}" POLICY0_MAC_KEY="${POLICY0_MAC_KEY}" POLICY1_MAC_KEY="${POLICY1_MAC_KEY}" python -m executor_server.server &
EX=$!

# Wait readiness
wait_http_ok "${POLICY0_URL}/health" 80
wait_http_ok "${POLICY1_URL}/health" 80
wait_http_ok "${EXECUTOR_URL}/health" 80

echo "Running benign agent..."
python -m agent.nanoclaw_agent benign

echo "Running malicious agent..."
python -m agent.nanoclaw_agent malicious

# cleanup handled by trap
