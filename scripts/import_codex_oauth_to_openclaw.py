#!/usr/bin/env python3
"""
Import OpenAI Codex (ChatGPT OAuth) tokens from Codex CLI into OpenClaw's auth store.

Source: ~/.codex/auth.json
Target: $OPENCLAW_STATE_DIR/agents/main/agent/auth-profiles.json

This avoids running OpenClaw's interactive onboarding flow when you already have Codex CLI authenticated.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import time
from pathlib import Path


def _decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT (expected 3 dot-separated parts)")
    payload_b64 = parts[1]
    payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
    payload = base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8")
    return json.loads(payload)


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    state_dir = Path(os.environ.get("OPENCLAW_STATE_DIR", str(repo_root / "artifact_out" / "openclaw_state"))).expanduser()

    src = Path.home() / ".codex" / "auth.json"
    if not src.exists():
        raise SystemExit(f"missing source file: {src}")

    codex = json.loads(src.read_text(encoding="utf-8"))
    tokens = codex.get("tokens") or {}
    access = tokens.get("access_token")
    refresh = tokens.get("refresh_token")
    account_id = tokens.get("account_id") or tokens.get("accountId")
    if not isinstance(access, str) or not access.strip():
        raise SystemExit("missing tokens.access_token in ~/.codex/auth.json")
    if not isinstance(refresh, str) or not refresh.strip():
        raise SystemExit("missing tokens.refresh_token in ~/.codex/auth.json")

    payload = _decode_jwt_payload(access)
    exp_s = payload.get("exp")
    if not isinstance(exp_s, int) or exp_s <= 0:
        raise SystemExit("access_token JWT missing exp")
    expires_ms = exp_s * 1000

    auth_path = state_dir / "agents" / "main" / "agent" / "auth-profiles.json"
    auth_path.parent.mkdir(parents=True, exist_ok=True)

    store = {"version": 1, "profiles": {}}
    if auth_path.exists():
        try:
            store = json.loads(auth_path.read_text(encoding="utf-8"))
        except Exception:
            store = {"version": 1, "profiles": {}}
    if not isinstance(store, dict):
        store = {"version": 1, "profiles": {}}
    if not isinstance(store.get("profiles"), dict):
        store["profiles"] = {}
    store["version"] = 1

    store["profiles"]["openai-codex:default"] = {
        "type": "oauth",
        "provider": "openai-codex",
        "access": access,
        "refresh": refresh,
        "expires": expires_ms,
        "accountId": account_id,
    }

    auth_path.write_text(json.dumps(store, indent=2) + "\n", encoding="utf-8")
    try:
        # Best-effort: restrict local read permissions.
        auth_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass

    expires_utc = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(exp_s))
    print(f"[import_codex_oauth_to_openclaw] wrote: {auth_path}")
    print(f"[import_codex_oauth_to_openclaw] openai-codex:default expires (UTC): {expires_utc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

