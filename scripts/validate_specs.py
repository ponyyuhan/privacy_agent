from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path

import jsonschema


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _hmac_b64(key: bytes, payload: dict) -> str:
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    mac = hmac.new(key, msg, hashlib.sha256).digest()
    return base64.b64encode(mac).decode("ascii")


def _example_commit_evidence() -> dict:
    # Minimal structurally valid example. This is a schema check, not a semantic check.
    k0 = bytes.fromhex("11" * 32)
    k1 = bytes.fromhex("22" * 32)
    action_id = "a_schema"
    program_id = "policy_unified_v1"
    request_sha256 = "ab" * 32
    ts = int(time.time())

    def mk(server_id: int, kid: str, key: bytes, outputs: dict[str, int]) -> dict:
        payload = {
            "v": 1,
            "kind": "commit",
            "server_id": int(server_id),
            "kid": str(kid),
            "ts": int(ts),
            "action_id": str(action_id),
            "program_id": str(program_id),
            "request_sha256": str(request_sha256),
            "outputs": {str(k): int(v) & 1 for k, v in outputs.items()},
            "commit_tag_share_b64": base64.b64encode(b"\x01" * 16).decode("ascii"),
        }
        payload["mac_b64"] = _hmac_b64(key, payload)
        return payload

    p0 = mk(0, "0", k0, {"allow_pre": 1, "need_confirm": 0, "patch0": 0, "patch1": 0})
    p1 = mk(1, "0", k1, {"allow_pre": 0, "need_confirm": 0, "patch0": 0, "patch1": 0})
    return {"policy0": p0, "policy1": p1}


def main() -> None:
    root = _repo_root()
    spec_dir = root / "spec"

    # Capsule contract schema validation.
    capsule_schema = _load_json(spec_dir / "secureclaw_capsule_contract_v1.schema.json")
    capsule_contract = _load_json(spec_dir / "secureclaw_capsule_contract_v1.json")
    jsonschema.validate(instance=capsule_contract, schema=capsule_schema)

    # Executor evidence schema validation.
    exec_schema = _load_json(spec_dir / "secureclaw_executor_accept_v1.schema.json")
    example = _example_commit_evidence()
    jsonschema.validate(instance=example, schema=exec_schema)

    # Basic sanity: contract instance matches repository transport choice.
    if os.getenv("MIRAGE_GATEWAY_UDS_PATH"):
        assert capsule_contract.get("transport", {}).get("mode") == "uds"

    print("OK: specs validate")


if __name__ == "__main__":
    main()

