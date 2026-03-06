from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any, Dict


def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    # Stable, ASCII-only canonicalization for MAC/digest binding across components.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _request_binding_key() -> bytes | None:
    """
    Optional keyed binding secret shared by gateway + executor.

    If configured, request binding uses HMAC-SHA256 over the canonical request
    payload, preventing offline dictionary guesses by policy-side observers.
    """
    raw = (
        os.getenv("SECURECLAW_REQUEST_BINDING_KEY_HEX", "").strip()
        or os.getenv("REQUEST_BINDING_KEY_HEX", "").strip()
    )
    if not raw:
        return None
    try:
        key = bytes.fromhex(raw)
    except Exception as e:
        raise RuntimeError("invalid_request_binding_key_hex") from e
    if len(key) < 16:
        raise RuntimeError("request_binding_key_too_short")
    return key


def request_sha256_v1(
    *,
    intent_id: str,
    caller: str,
    session: str,
    inputs: Dict[str, Any],
    context: Dict[str, Any] | None = None,
) -> str:
    """Bind a side-effecting request for PREVIEW->COMMIT.

    Important:
    - Excludes commit-phase flags like `user_confirm` so a preview token can be used for commit.
    - Must be identical in gateway and executor.
    - If `SECURECLAW_REQUEST_BINDING_KEY_HEX` is set, this returns a keyed
      commitment `HMAC-SHA256(key, CanonJSON(payload))`.
    - Otherwise it falls back to legacy unkeyed `SHA256(CanonJSON(payload))`.
    """
    payload = {
        "v": 1,
        "intent_id": str(intent_id),
        "caller": str(caller),
        "session": str(session),
        "inputs": inputs or {},
        "context": context or {},
    }
    msg = canonical_json_bytes(payload)
    key = _request_binding_key()
    if key:
        return hmac.new(key, msg, hashlib.sha256).hexdigest()
    return sha256_hex(msg)
