#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OPENCLAW_BIN="$ROOT/integrations/openclaw_runner/node_modules/.bin/openclaw"
if [[ ! -x "$OPENCLAW_BIN" ]]; then
  echo "[setup_openclaw_state] OpenClaw not installed yet; running scripts/setup_openclaw.sh ..."
  bash scripts/setup_openclaw.sh
fi

STATE_DIR="${OPENCLAW_STATE_DIR:-$ROOT/artifact_out/openclaw_state}"
mkdir -p "$STATE_DIR"

# This config is used when the user runs OpenClaw without OPENCLAW_CONFIG_PATH.
# Default: $OPENCLAW_STATE_DIR/openclaw.json
CFG="$STATE_DIR/openclaw.json"
PROVIDER_PLUGIN_DIR="$ROOT/integrations/openclaw_runner/extensions/openai-codex-auth"

cat >"$CFG" <<JSON
{
  "plugins": {
    "enabled": true,
    "load": { "paths": ["$PROVIDER_PLUGIN_DIR"] },
    "entries": {
      "openai-codex-auth": { "enabled": true }
    }
  }
}
JSON

echo "[setup_openclaw_state] wrote: $CFG"
echo "[setup_openclaw_state] verify:"
echo "  OPENCLAW_STATE_DIR=\"$STATE_DIR\" \"$OPENCLAW_BIN\" plugins list | rg -n \"openai-codex-auth\" || true"
echo "  OPENCLAW_STATE_DIR=\"$STATE_DIR\" \"$OPENCLAW_BIN\" models auth login --provider openai-codex"

