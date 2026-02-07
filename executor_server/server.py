from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel, Field


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(payload: dict) -> bytes:
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _verify_mac(proof: dict, mac_key: bytes) -> bool:
    mac_b64 = proof.get("mac_b64")
    if not isinstance(mac_b64, str) or not mac_b64:
        return False
    payload = dict(proof)
    payload.pop("mac_b64", None)
    msg = _canonical_json_bytes(payload)
    want = hmac.new(mac_key, msg, hashlib.sha256).digest()
    try:
        got = base64.b64decode(mac_b64)
    except Exception:
        return False
    return hmac.compare_digest(want, got)


def _require_key(env_name: str) -> bytes:
    v = os.getenv(env_name, "").strip()
    if not v:
        raise RuntimeError(f"missing env {env_name}")
    return bytes.fromhex(v)


POLICY0_KEYS: dict[str, bytes] | None = None
POLICY1_KEYS: dict[str, bytes] | None = None
MAC_TTL_S = int(os.getenv("POLICY_MAC_TTL_S", "30"))
if MAC_TTL_S <= 0:
    MAC_TTL_S = 30


def _parse_mac_keys(s: str) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for part in (s or "").split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            kid, hexkey = part.split(":", 1)
        else:
            kid, hexkey = "0", part
        kid = kid.strip() or "0"
        hexkey = hexkey.strip()
        if not hexkey:
            continue
        out[kid] = bytes.fromhex(hexkey)
    return out


def _load_keys_for_server(server_id: int) -> dict[str, bytes]:
    global POLICY0_KEYS, POLICY1_KEYS
    if server_id == 0:
        if POLICY0_KEYS is None:
            multi = os.getenv("POLICY0_MAC_KEYS", "").strip()
            if multi:
                POLICY0_KEYS = _parse_mac_keys(multi)
            else:
                POLICY0_KEYS = {"0": _require_key("POLICY0_MAC_KEY")}
        return POLICY0_KEYS
    if server_id == 1:
        if POLICY1_KEYS is None:
            multi = os.getenv("POLICY1_MAC_KEYS", "").strip()
            if multi:
                POLICY1_KEYS = _parse_mac_keys(multi)
            else:
                POLICY1_KEYS = {"0": _require_key("POLICY1_MAC_KEY")}
        return POLICY1_KEYS
    raise ValueError("unexpected server_id")


def _mac_key_for_server(server_id: int, *, kid: str) -> bytes:
    keys = _load_keys_for_server(server_id)
    k = keys.get(kid)
    if not k:
        raise ValueError("unknown_kid")
    return k


def _validate_proof_common(proof: dict, *, kind: str, action_id: str, db: str) -> tuple[bool, str]:
    if not isinstance(proof, dict):
        return False, "bad_proof"
    if proof.get("v") != 1:
        return False, "bad_proof_version"
    if proof.get("kind") != kind:
        return False, "bad_proof_kind"
    if proof.get("action_id") != action_id:
        return False, "bad_action_id"
    if proof.get("db") != db:
        return False, "bad_db"
    try:
        ts = int(proof.get("ts"))
    except Exception:
        return False, "bad_ts"
    now = int(time.time())
    if abs(now - ts) > MAC_TTL_S:
        return False, "expired_proof"
    try:
        server_id = int(proof.get("server_id"))
    except Exception:
        return False, "bad_server_id"
    kid = str(proof.get("kid") or "0")
    try:
        key = _mac_key_for_server(server_id, kid=kid)
    except Exception:
        return False, "unknown_kid"
    if not _verify_mac(proof, key):
        return False, "bad_mac"
    return True, "OK"


def _verify_bit_batch_evidence(ev: dict, *, action_id: str, logical_db: str, allowed_dbs: list[str]) -> tuple[Optional[List[int]], str]:
    if not isinstance(ev, dict):
        return None, "missing_evidence"
    actual_db = str(ev.get("db") or "")
    if actual_db not in set(str(x) for x in (allowed_dbs or [])):
        return None, "unexpected_db"
    if ev.get("action_id") != action_id:
        return None, "evidence_mismatch"
    a0 = ev.get("a0")
    a1 = ev.get("a1")
    if not isinstance(a0, list) or not isinstance(a1, list) or len(a0) != len(a1):
        return None, "bad_share_lists"
    p0 = ev.get("policy0")
    p1 = ev.get("policy1")
    ok0, code0 = _validate_proof_common(p0, kind="bit", action_id=action_id, db=actual_db)
    if not ok0:
        return None, code0
    ok1, code1 = _validate_proof_common(p1, kind="bit", action_id=action_id, db=actual_db)
    if not ok1:
        return None, code1

    # Bind resp_sha256 to the actual shares.
    if _sha256_hex(bytes([int(x) & 1 for x in a0])) != p0.get("resp_sha256"):
        return None, "resp_hash_mismatch_p0"
    if _sha256_hex(bytes([int(x) & 1 for x in a1])) != p1.get("resp_sha256"):
        return None, "resp_hash_mismatch_p1"

    recon = [(int(x) & 1) ^ (int(y) & 1) for x, y in zip(a0, a1)]
    return recon, "OK"


def _verify_block_step(step: dict, *, action_id: str, db: str, block_size: int) -> tuple[Optional[bytes], str]:
    if not isinstance(step, dict):
        return None, "bad_step"
    pr = step.get("proof")
    if not isinstance(pr, dict):
        return None, "bad_step_proof"
    if pr.get("db") != db or pr.get("action_id") != action_id:
        return None, "step_mismatch"
    if int(pr.get("block_size", 0)) != int(block_size):
        return None, "block_size_mismatch"

    p0 = pr.get("policy0")
    p1 = pr.get("policy1")
    ok0, code0 = _validate_proof_common(p0, kind="block", action_id=action_id, db=db)
    if not ok0:
        return None, code0
    ok1, code1 = _validate_proof_common(p1, kind="block", action_id=action_id, db=db)
    if not ok1:
        return None, code1

    s0_b64 = pr.get("s0_b64") or []
    s1_b64 = pr.get("s1_b64") or []
    if not isinstance(s0_b64, list) or not isinstance(s1_b64, list) or len(s0_b64) != len(s1_b64):
        return None, "bad_block_share_lists"
    if len(s0_b64) != 1:
        return None, "expected_single_block"
    try:
        b0 = base64.b64decode(s0_b64[0])
        b1 = base64.b64decode(s1_b64[0])
    except Exception:
        return None, "bad_block_b64"
    if len(b0) != block_size or len(b1) != block_size:
        return None, "bad_block_size"

    if _sha256_hex(b0) != p0.get("resp_sha256"):
        return None, "resp_hash_mismatch_block_p0"
    if _sha256_hex(b1) != p1.get("resp_sha256"):
        return None, "resp_hash_mismatch_block_p1"

    blk = bytes([x ^ y for x, y in zip(b0, b1)])
    return blk, "OK"


def _verify_dfa_evidence(dfa_ev: dict, *, text: str, action_id: str) -> tuple[Optional[bool], str]:
    if not isinstance(dfa_ev, dict):
        return None, "missing_dfa"
    db = str(dfa_ev.get("db") or "dfa_transitions")
    alpha = int(dfa_ev.get("alpha", 0))
    block_size = int(dfa_ev.get("block_size", 0))
    char_to_sym = dfa_ev.get("char_to_sym") or {}
    steps = dfa_ev.get("steps") or []
    if alpha <= 0 or block_size <= 0:
        return None, "bad_dfa_config"
    if not isinstance(char_to_sym, dict) or not isinstance(steps, list):
        return None, "bad_dfa_evidence"

    # Normalize text exactly like gateway.
    s = (text or "").upper().replace("\n", " ")
    max_chars = int(os.getenv("MAX_DFA_SCAN_CHARS", "256"))
    if max_chars < 16:
        max_chars = 16
    if max_chars > 4096:
        max_chars = 4096
    if len(s) > max_chars:
        s = s[:max_chars]

    if len(steps) != len(s):
        # Gateway is expected to include a step per char scanned (and it only scans in confirm-path).
        return None, "dfa_step_count_mismatch"

    state = 0
    for i, ch in enumerate(s):
        sym = int(char_to_sym.get(ch, 0))
        expected_idx = (state * alpha) + sym
        step = steps[i]
        if int(step.get("idx", -1)) != expected_idx:
            return None, "dfa_idx_mismatch"
        blk, code = _verify_block_step(step, action_id=action_id, db=db, block_size=block_size)
        if blk is None:
            return None, code
        # next_state u16 + match flag byte
        state = int.from_bytes(blk[0:2], "little", signed=False)
        if (blk[2] & 1) == 1:
            return True, "OK"
    return False, "OK"


class ExecSendMessageReq(BaseModel):
    action_id: str
    channel: str = "email"
    recipient: str
    text: str
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    dlp_mode: str = "fourgram"
    evidence: dict[str, Any] = Field(default_factory=dict)


class ExecFetchReq(BaseModel):
    action_id: str
    resource_id: str = "example"
    domain: str
    evidence: dict[str, Any] = Field(default_factory=dict)


app = FastAPI(title="MIRAGE-OG++ Executor", version="0.1")


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/exec/send_message")
def exec_send_message(req: ExecSendMessageReq):
    action_id = req.action_id
    ev = req.evidence or {}

    # Hard-stop: never allow exporting handles as artifacts in this demo executor.
    if req.artifacts:
        return {"status": "DENY", "reason_code": "ARTIFACTS_NOT_ALLOWED"}

    # Recipient allowlist must be proven by both servers.
    recon, code = _verify_bit_batch_evidence(
        ev.get("allow_recipients") or {},
        action_id=action_id,
        logical_db="allow_recipients",
        allowed_dbs=["allow_recipients", os.getenv("POLICY_BUNDLE_DB", "policy_bundle")],
    )
    if recon is None or not recon or recon[0] != 1:
        return {"status": "DENY", "reason_code": "RECIPIENT_NOT_ALLOWED", "details": code}

    # DLP checks
    dlp_mode = (req.dlp_mode or "fourgram").strip().lower()
    hits, code2 = _verify_bit_batch_evidence(
        ev.get("banned_tokens") or {},
        action_id=action_id,
        logical_db="banned_tokens",
        allowed_dbs=["banned_tokens", os.getenv("POLICY_BUNDLE_DB", "policy_bundle")],
    )
    if hits is None:
        return {"status": "DENY", "reason_code": "MISSING_DLP_PROOF", "details": code2}

    has_hit = any(int(h) == 1 for h in hits)
    if not has_hit:
        return {"status": "OK", "reason_code": "ALLOW"}

    if dlp_mode != "dfa":
        return {"status": "DENY", "reason_code": "DLP_BLOCKED"}

    matched, code3 = _verify_dfa_evidence(ev.get("dfa") or {}, text=req.text, action_id=action_id)
    if matched is None:
        return {"status": "DENY", "reason_code": "BAD_DFA_PROOF", "details": code3}
    if matched:
        return {"status": "DENY", "reason_code": "DLP_BLOCKED"}
    return {"status": "OK", "reason_code": "ALLOW"}


@app.post("/exec/fetch")
def exec_fetch(req: ExecFetchReq):
    action_id = req.action_id
    ev = req.evidence or {}

    recon, code = _verify_bit_batch_evidence(
        ev.get("allow_domains") or {},
        action_id=action_id,
        logical_db="allow_domains",
        allowed_dbs=["allow_domains", os.getenv("POLICY_BUNDLE_DB", "policy_bundle")],
    )
    if recon is None or not recon or recon[0] != 1:
        return {"status": "DENY", "reason_code": "DOMAIN_NOT_ALLOWED", "details": code}

    # Offline demo: return a canned response.
    return {
        "status": "OK",
        "reason_code": "ALLOW",
        "data": {"resource_id": req.resource_id, "domain": req.domain, "content_preview": "<html>...</html>"},
    }


def main():
    port = int(os.getenv("EXECUTOR_PORT", "9100"))
    access_log = bool(int(os.getenv("ACCESS_LOG", "0")))
    uvicorn.run("executor_server.server:app", host="0.0.0.0", port=port, reload=False, access_log=access_log)


if __name__ == "__main__":
    main()
