#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT"

OPENCLAW_BIN="$ROOT/integrations/openclaw_runner/node_modules/.bin/openclaw"
if [[ ! -x "$OPENCLAW_BIN" ]]; then
  echo "[run_openclaw] OpenClaw not installed yet; running scripts/setup_openclaw.sh ..."
  bash scripts/setup_openclaw.sh
fi

cleanup () {
  if [[ -n "${OCGW:-}" ]]; then kill "$OCGW" 2>/dev/null || true; fi
  # OpenClaw runs a separate `openclaw-gateway` process; make sure it is stopped.
  if [[ -n "${OC_PORT:-}" ]]; then
    lsof -nP -tiTCP:"${OC_PORT}" -sTCP:LISTEN 2>/dev/null | xargs -I{} kill {} 2>/dev/null || true
  fi
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
  local tries="${2:-80}"
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

wait_gateway_ok () {
  local tries="${1:-80}"
  local i=0
  while [[ "$i" -lt "$tries" ]]; do
    if "$OPENCLAW_BIN" gateway health --timeout 250 >/dev/null 2>&1; then
      return 0
    fi
    i=$((i+1))
    sleep 0.1
  done
  return 1
}

P0_PORT="${P0_PORT:-$(pick_port)}"
P1_PORT="${P1_PORT:-$(pick_port)}"
EX_PORT="${EX_PORT:-$(pick_port)}"

export POLICY0_URL="http://localhost:${P0_PORT}"
export POLICY1_URL="http://localhost:${P1_PORT}"
export EXECUTOR_URL="http://localhost:${EX_PORT}"
export DLP_MODE="${DLP_MODE:-dfa}"
export SIGNED_PIR="${SIGNED_PIR:-1}"

export POLICY0_MAC_KEY="${POLICY0_MAC_KEY:-$(python -c 'import secrets; print(secrets.token_hex(32))')}"
export POLICY1_MAC_KEY="${POLICY1_MAC_KEY:-$(python -c 'import secrets; print(secrets.token_hex(32))')}"

echo "[run_openclaw] POLICY0_URL=${POLICY0_URL}"
echo "[run_openclaw] POLICY1_URL=${POLICY1_URL}"
echo "[run_openclaw] EXECUTOR_URL=${EXECUTOR_URL}"
echo "[run_openclaw] DLP_MODE=${DLP_MODE}"
echo "[run_openclaw] SIGNED_PIR=${SIGNED_PIR}"
echo "[run_openclaw] POLICY_BACKEND=${POLICY_BACKEND:-python}"

POLICY_BACKEND="${POLICY_BACKEND:-python}"
if [[ "$POLICY_BACKEND" == "rust" ]]; then
  BIN="$ROOT/policy_server_rust/target/release/mirage_policy_server"
  if [[ ! -x "$BIN" ]]; then
    echo "[run_openclaw] building rust policy server..."
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

EXECUTOR_PORT="${EX_PORT}" POLICY0_MAC_KEY="${POLICY0_MAC_KEY}" POLICY1_MAC_KEY="${POLICY1_MAC_KEY}" python -m executor_server.server &
EX=$!

wait_http_ok "${POLICY0_URL}/health" 120
wait_http_ok "${POLICY1_URL}/health" 120
wait_http_ok "${EXECUTOR_URL}/health" 120

mkdir -p artifact_out
OPENCLAW_STATE_DIR="${OPENCLAW_STATE_DIR:-$ROOT/artifact_out/openclaw_state}"
mkdir -p "$OPENCLAW_STATE_DIR"

OC_PORT="${OPENCLAW_GATEWAY_PORT:-$(pick_port)}"
OC_TOKEN="${OPENCLAW_GATEWAY_TOKEN:-$(python -c 'import secrets; print(secrets.token_hex(16))')}"
OC_WS_URL="ws://127.0.0.1:${OC_PORT}"

OPENCLAW_CONFIG_PATH="${OPENCLAW_CONFIG_PATH:-$ROOT/artifact_out/openclaw.demo.json5}"

PLUGIN_FILE="$ROOT/integrations/openclaw_plugin/mirage_ogpp.ts"
PROVIDER_PLUGIN_DIR="$ROOT/integrations/openclaw_runner/extensions/openai-codex-auth"
WORKSPACE_DIR="$ROOT/integrations/openclaw_workspace"
MODEL_PRIMARY="${OPENCLAW_MODEL_PRIMARY:-openai-codex/gpt-5.1-codex-mini}"

cat >"$OPENCLAW_CONFIG_PATH" <<JSON5
{
  gateway: {
    mode: "local",
    port: ${OC_PORT},
    bind: "loopback",
    auth: { mode: "token", token: "${OC_TOKEN}" }
  },
  plugins: {
    enabled: true,
    load: { paths: ["${PLUGIN_FILE}", "${PROVIDER_PLUGIN_DIR}"] },
    entries: {
      mirage_ogpp: { enabled: true },
      "openai-codex-auth": { enabled: true }
    }
  },
  tools: {
    // Lock down core tools: keep only session_status + opt-in plugin tool.
    profile: "minimal",
    // NOTE: tools.allow cannot add tools that are not in the profile allowlist; use tools.alsoAllow.
    alsoAllow: ["mirage_act"]
  },
  agents: {
    defaults: {
      workspace: "${WORKSPACE_DIR}",
      model: { primary: "${MODEL_PRIMARY}" }
    }
  }
}
JSON5

export OPENCLAW_STATE_DIR
export OPENCLAW_CONFIG_PATH
export OPENCLAW_GATEWAY_TOKEN="${OC_TOKEN}"
export OPENCLAW_GATEWAY_PORT="${OC_PORT}"

echo "[run_openclaw] OPENCLAW_CONFIG_PATH=${OPENCLAW_CONFIG_PATH}"
echo "[run_openclaw] OPENCLAW_STATE_DIR=${OPENCLAW_STATE_DIR}"
echo "[run_openclaw] OPENCLAW_GATEWAY_URL=${OC_WS_URL}"
echo "[run_openclaw] OPENCLAW_MODEL_PRIMARY=${MODEL_PRIMARY}"

echo "[run_openclaw] starting OpenClaw gateway..."
OC_LOG="artifact_out/openclaw_gateway.log"
if [[ "${OPENCLAW_VERBOSE:-0}" == "1" ]]; then
  "$OPENCLAW_BIN" gateway run --force --port "${OC_PORT}" --bind loopback --auth token --token "${OC_TOKEN}" 2>&1 | tee "$OC_LOG" &
else
  "$OPENCLAW_BIN" gateway run --force --port "${OC_PORT}" --bind loopback --auth token --token "${OC_TOKEN}" >"$OC_LOG" 2>&1 &
fi
OCGW=$!

if ! wait_gateway_ok 160; then
  echo "[run_openclaw] ERROR: OpenClaw gateway did not become healthy."
  echo "[run_openclaw] Gateway log: ${OC_LOG}"
  exit 1
fi

echo "[run_openclaw] NOTE: This run requires OpenClaw to be authenticated for provider: openai-codex."
echo "[run_openclaw] Recommended (real OpenClaw OAuth):"
echo "  OPENCLAW_STATE_DIR=\"${OPENCLAW_STATE_DIR}\" bash scripts/setup_openclaw_state.sh"
echo "  OPENCLAW_STATE_DIR=\"${OPENCLAW_STATE_DIR}\" \"$OPENCLAW_BIN\" models auth login --provider openai-codex"
echo "[run_openclaw] Fallback (non-interactive, uses Codex CLI tokens if available):"
echo "  OPENCLAW_STATE_DIR=\"${OPENCLAW_STATE_DIR}\" python scripts/import_codex_oauth_to_openclaw.py"

BENIGN_PROMPT="$(cat integrations/openclaw_runner/prompts/benign.txt)"
MALICIOUS_PROMPT="$(cat integrations/openclaw_runner/prompts/malicious.txt)"

AUTH_FILE="${OPENCLAW_STATE_DIR}/agents/main/agent/auth-profiles.json"
if [[ ! -f "$AUTH_FILE" ]]; then
  CODEX_AUTH="${HOME}/.codex/auth.json"
  if [[ -f "$CODEX_AUTH" ]]; then
    echo "[run_openclaw] Missing auth profiles; importing from ${CODEX_AUTH} ..."
    OPENCLAW_STATE_DIR="${OPENCLAW_STATE_DIR}" python scripts/import_codex_oauth_to_openclaw.py
 else
    echo "[run_openclaw] Missing auth profiles: ${AUTH_FILE}"
    echo "[run_openclaw] Also missing: ${CODEX_AUTH}"
    echo "[run_openclaw] Authenticate Codex first (recommended): codex login"
    echo "[run_openclaw] Or run OpenClaw onboarding: $OPENCLAW_BIN onboard --auth-choice openai-codex"
    exit 2
  fi
fi
python - <<PY
import json, sys
path = "${AUTH_FILE}"
try:
    data = json.load(open(path, "r", encoding="utf-8"))
except Exception as e:
    print(f"[run_openclaw] Failed to read auth profiles: {path}: {e}")
    sys.exit(2)
profiles = data.get("profiles") or {}
ok = any((p.get("provider") == "openai-codex") for p in profiles.values() if isinstance(p, dict))
if not ok:
    print(f"[run_openclaw] No openai-codex profile found in: {path}")
    sys.exit(2)
PY

echo "[run_openclaw] running benign prompt..."
"$OPENCLAW_BIN" agent --session-id "mirage-openclaw-benign" --message "$BENIGN_PROMPT" --json \
  | tee artifact_out/openclaw_benign.json >/dev/null

echo "[run_openclaw] running malicious prompt..."
"$OPENCLAW_BIN" agent --session-id "mirage-openclaw-malicious" --message "$MALICIOUS_PROMPT" --json \
  | tee artifact_out/openclaw_malicious.json >/dev/null

echo "[run_openclaw] outputs:"
echo "  artifact_out/openclaw_benign.json"
echo "  artifact_out/openclaw_malicious.json"
