from __future__ import annotations

import hashlib
import json
from typing import Any, Dict


def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    # Stable, ASCII-only canonicalization for MAC/digest binding across components.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def request_sha256_v1(*, intent_id: str, caller: str, session: str, inputs: Dict[str, Any]) -> str:
    """Hash a side-effecting request for PREVIEW->COMMIT binding.

    Important:
    - Excludes commit-phase flags like `user_confirm` so a preview token can be used for commit.
    - Must be identical in gateway and executor.
    """
    payload = {
        "v": 1,
        "intent_id": str(intent_id),
        "caller": str(caller),
        "session": str(session),
        "inputs": inputs or {},
    }
    return sha256_hex(canonical_json_bytes(payload))

