from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any

import jsonschema

from common.canonical import request_sha256_v1


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_json(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("expected_json_object")
    return obj


def _canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


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


def _load_keyring(*, server_id: int, override: str | None = None) -> dict[str, bytes]:
    if override is not None:
        return _parse_mac_keys(str(override))
    if server_id == 0:
        multi = (os.getenv("POLICY0_MAC_KEYS") or "").strip()
        if multi:
            return _parse_mac_keys(multi)
        single = (os.getenv("POLICY0_MAC_KEY") or "").strip()
        if not single:
            raise RuntimeError("missing_policy0_mac_key")
        return {"0": bytes.fromhex(single)}
    if server_id == 1:
        multi = (os.getenv("POLICY1_MAC_KEYS") or "").strip()
        if multi:
            return _parse_mac_keys(multi)
        single = (os.getenv("POLICY1_MAC_KEY") or "").strip()
        if not single:
            raise RuntimeError("missing_policy1_mac_key")
        return {"0": bytes.fromhex(single)}
    raise ValueError("unexpected_server_id")


def _verify_mac(proof: dict, key: bytes) -> bool:
    mac_b64 = proof.get("mac_b64")
    if not isinstance(mac_b64, str) or not mac_b64:
        return False
    payload = dict(proof)
    payload.pop("mac_b64", None)
    msg = _canonical_json_bytes(payload)
    want = hmac.new(key, msg, hashlib.sha256).digest()
    try:
        got = base64.b64decode(mac_b64)
    except Exception:
        return False
    return hmac.compare_digest(want, got)


def _bool01(x: Any) -> int:
    try:
        return int(x) & 1
    except Exception:
        return 0


def _xor_outputs(o0: dict[str, Any], o1: dict[str, Any]) -> dict[str, int]:
    keys = set(str(k) for k in (o0 or {}).keys()) | set(str(k) for k in (o1 or {}).keys())
    out: dict[str, int] = {}
    for k in keys:
        out[str(k)] = (_bool01(o0.get(k)) ^ _bool01(o1.get(k))) & 1
    return out


def _validate_commit_share(
    proof: dict[str, Any],
    *,
    server_id: int,
    action_id: str,
    program_id: str,
    request_sha256: str,
    now: int,
    mac_ttl_s: int,
    keyring: dict[str, bytes],
) -> tuple[bool, str]:
    if not isinstance(proof, dict):
        return False, "bad_proof"
    if proof.get("v") != 1:
        return False, "bad_proof_version"
    if proof.get("kind") != "commit":
        return False, "bad_proof_kind"
    if int(proof.get("server_id", -1)) != int(server_id):
        return False, "server_id_mismatch"
    if str(proof.get("action_id") or "") != str(action_id):
        return False, "bad_action_id"
    if str(proof.get("program_id") or "") != str(program_id):
        return False, "bad_program_id"
    if str(proof.get("request_sha256") or "") != str(request_sha256):
        return False, "bad_request_sha256"
    try:
        ts = int(proof.get("ts"))
    except Exception:
        return False, "bad_ts"
    if abs(int(now) - int(ts)) > int(mac_ttl_s):
        return False, "expired_proof"
    kid = str(proof.get("kid") or "0")
    key = keyring.get(kid)
    if not key:
        return False, "unknown_kid"
    if not _verify_mac(proof, key):
        return False, "bad_mac"
    return True, "OK"


def verify_accept_predicate(
    *,
    spec_path: Path,
    commit_path: Path,
    request_path: Path,
    policy0_keys: str | None = None,
    policy1_keys: str | None = None,
    now: int | None = None,
    user_confirm: bool = False,
    replay_seen: bool = False,
) -> dict[str, Any]:
    repo_root = _repo_root()
    spec = _load_json(spec_path)
    commit = _load_json(commit_path)
    req = _load_json(request_path)

    # 1) Schema validation.
    schema_path = repo_root / "spec" / "secureclaw_executor_accept_v1.schema.json"
    schema = _load_json(schema_path)
    try:
        jsonschema.validate(instance=commit, schema=schema)
        schema_ok = True
        schema_err = ""
    except Exception as e:
        schema_ok = False
        schema_err = type(e).__name__

    # Load semantic spec.
    program_id = str(spec.get("program_id") or "policy_unified_v1")
    required_out_keys = [str(x) for x in (spec.get("required_output_keys") or [])]
    want_tag_len = int(spec.get("commit_tag_share_len_bytes") or 16)
    if want_tag_len < 8:
        want_tag_len = 8
    if want_tag_len > 64:
        want_tag_len = 64

    now2 = int(time.time()) if now is None else int(now)
    mac_ttl_s = int(os.getenv(str(spec.get("mac_ttl_env") or "POLICY_MAC_TTL_S"), "30") or "30")
    if mac_ttl_s <= 0:
        mac_ttl_s = 30

    # Extract request context.
    action_id = str(req.get("action_id") or "")
    intent_id = str(req.get("intent_id") or "")
    caller = str(req.get("caller") or "")
    session = str(req.get("session") or "")
    inputs = req.get("inputs") if isinstance(req.get("inputs"), dict) else {}
    request_sha256 = request_sha256_v1(intent_id=intent_id, caller=caller, session=session, inputs=inputs)

    # Evidence shares.
    p0 = commit.get("policy0") if isinstance(commit.get("policy0"), dict) else {}
    p1 = commit.get("policy1") if isinstance(commit.get("policy1"), dict) else {}

    # 2) Share-level semantic validation: keys, MAC, TTL, binding.
    keyring0 = _load_keyring(server_id=0, override=policy0_keys)
    keyring1 = _load_keyring(server_id=1, override=policy1_keys)
    ok0, code0 = _validate_commit_share(
        p0,
        server_id=0,
        action_id=action_id or str(p0.get("action_id") or ""),
        program_id=program_id,
        request_sha256=request_sha256,
        now=now2,
        mac_ttl_s=mac_ttl_s,
        keyring=keyring0,
    )
    ok1, code1 = _validate_commit_share(
        p1,
        server_id=1,
        action_id=action_id or str(p1.get("action_id") or ""),
        program_id=program_id,
        request_sha256=request_sha256,
        now=now2,
        mac_ttl_s=mac_ttl_s,
        keyring=keyring1,
    )

    # Align action_id if request omits it.
    if not action_id:
        action_id = str(p0.get("action_id") or p1.get("action_id") or "")

    evidence_valid = bool(schema_ok and ok0 and ok1)

    # 3) Tag share length constraint.
    tag_ok = False
    tag_details: dict[str, Any] = {}
    try:
        t0 = base64.b64decode(str(p0.get("commit_tag_share_b64") or ""))
        t1 = base64.b64decode(str(p1.get("commit_tag_share_b64") or ""))
        tag_ok = (len(t0) == len(t1) == int(want_tag_len))
        tag_details = {"len0": int(len(t0)), "len1": int(len(t1)), "want": int(want_tag_len)}
    except Exception as e:
        tag_ok = False
        tag_details = {"error": type(e).__name__}

    # 4) Output interface constraint.
    outs0 = p0.get("outputs") if isinstance(p0.get("outputs"), dict) else {}
    outs1 = p1.get("outputs") if isinstance(p1.get("outputs"), dict) else {}
    missing_keys = [k for k in required_out_keys if (k not in outs0 or k not in outs1)]
    out_iface_ok = len(missing_keys) == 0

    # 5) Reconstruct decision bits.
    outs = _xor_outputs(outs0, outs1) if isinstance(outs0, dict) and isinstance(outs1, dict) else {}
    allow_pre = int(outs.get("allow_pre", 0)) & 1
    need_confirm = int(outs.get("need_confirm", 0)) & 1

    # 6) Acceptance decision for a concrete request.
    decision = "BAD_PROOF"
    accepts = False
    if not schema_ok:
        decision = "BAD_SCHEMA"
    elif not ok0 or not ok1:
        decision = "BAD_COMMIT_PROOF"
    elif not tag_ok:
        decision = "BAD_COMMIT_TAG_LEN"
    elif not out_iface_ok:
        decision = "MISSING_OUTPUT_KEY"
    elif replay_seen:
        decision = "REPLAY_DENY"
    elif allow_pre != 1:
        decision = "POLICY_DENY"
    elif need_confirm == 1 and not bool(user_confirm):
        decision = "REQUIRE_CONFIRM"
    else:
        decision = "ACCEPT"
        accepts = True

    return {
        "status": "OK",
        "spec_path": str(spec_path),
        "commit_path": str(commit_path),
        "request_path": str(request_path),
        "schema_ok": bool(schema_ok),
        "schema_error": str(schema_err),
        "program_id": program_id,
        "action_id": action_id,
        "intent_id": intent_id,
        "caller": caller,
        "session": session,
        "request_sha256": request_sha256,
        "now": int(now2),
        "mac_ttl_s": int(mac_ttl_s),
        "evidence_valid": bool(evidence_valid),
        "share0_ok": bool(ok0),
        "share1_ok": bool(ok1),
        "share0_code": str(code0),
        "share1_code": str(code1),
        "tag_ok": bool(tag_ok),
        "tag_details": tag_details,
        "output_interface_ok": bool(out_iface_ok),
        "missing_output_keys": missing_keys,
        "outs": outs,
        "allow_pre": int(allow_pre),
        "need_confirm": int(need_confirm),
        "user_confirm": bool(user_confirm),
        "replay_seen": bool(replay_seen),
        "accepts": bool(accepts),
        "decision": str(decision),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", default="spec/secureclaw_accept_predicate_v1.json")
    ap.add_argument("--commit", required=True, help="commit evidence JSON path (dual proofs)")
    ap.add_argument("--request", required=True, help="request context JSON path")
    ap.add_argument("--out", default="", help="optional output JSON path")
    ap.add_argument("--now", default="", help="optional unix time for TTL checks")
    ap.add_argument("--user-confirm", action="store_true", help="set user_confirm=true for acceptance decision")
    ap.add_argument("--replay-seen", action="store_true", help="treat action_id as already used for replay check")
    ap.add_argument("--policy0-mac-keys", default="", help="override POLICY0_MAC_KEYS format kid:hex,kid2:hex")
    ap.add_argument("--policy1-mac-keys", default="", help="override POLICY1_MAC_KEYS format kid:hex,kid2:hex")
    args = ap.parse_args()

    repo_root = _repo_root()
    spec_path = Path(str(args.spec)).expanduser()
    if not spec_path.is_absolute():
        spec_path = (repo_root / spec_path).resolve()
    commit_path = Path(str(args.commit)).expanduser().resolve()
    request_path = Path(str(args.request)).expanduser().resolve()
    out_path = Path(str(args.out)).expanduser().resolve() if str(args.out or "").strip() else None

    now = int(str(args.now)) if str(args.now or "").strip() else None
    p0 = str(args.policy0_mac_keys or "").strip() or None
    p1 = str(args.policy1_mac_keys or "").strip() or None

    report = verify_accept_predicate(
        spec_path=spec_path,
        commit_path=commit_path,
        request_path=request_path,
        policy0_keys=p0,
        policy1_keys=p1,
        now=now,
        user_confirm=bool(args.user_confirm),
        replay_seen=bool(args.replay_seen),
    )

    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        print(str(out_path))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=True))

    raise SystemExit(0 if bool(report.get("accepts")) else 2)


if __name__ == "__main__":
    main()

