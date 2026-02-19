from __future__ import annotations

import base64
import hashlib
import hmac
import json
import tempfile
import time
import unittest
from pathlib import Path

from common.canonical import request_sha256_v1
from scripts.verify_accept_predicate import verify_accept_predicate


def _mac_b64(key_hex: str, payload: dict) -> str:
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    mac = hmac.new(bytes.fromhex(key_hex), msg, hashlib.sha256).digest()
    return base64.b64encode(mac).decode("ascii")


def _mk_commit_proof(
    *,
    server_id: int,
    key_hex: str,
    action_id: str,
    program_id: str,
    request_sha256: str,
    outputs: dict[str, int],
    ts: int,
    kid: str = "0",
    commit_tag_len: int = 16,
) -> dict:
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
        "commit_tag_share_b64": base64.b64encode(b"\x01" * int(commit_tag_len)).decode("ascii"),
    }
    payload["mac_b64"] = _mac_b64(key_hex, payload)
    return payload


class AcceptPredicateVerifierTests(unittest.TestCase):
    def test_accepts_valid_commit_with_no_confirm(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        spec_path = repo_root / "spec" / "secureclaw_accept_predicate_v1.json"
        k0 = "11" * 32
        k1 = "22" * 32
        action_id = "a_test"
        program_id = "policy_unified_v1"

        req = {
            "action_id": action_id,
            "intent_id": "SendMessage",
            "caller": "c",
            "session": "s",
            "inputs": {"channel": "email", "recipient": "alice@example.com", "domain": "", "text": "hello"},
        }
        req_sha = request_sha256_v1(intent_id=req["intent_id"], caller=req["caller"], session=req["session"], inputs=req["inputs"])
        ts = int(time.time())

        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=ts,
        )
        p1 = _mk_commit_proof(
            server_id=1,
            key_hex=k1,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 0, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=ts,
        )
        commit = {"policy0": p0, "policy1": p1}

        with tempfile.TemporaryDirectory() as td:
            td = str(td)
            cp = Path(td) / "commit.json"
            rp = Path(td) / "req.json"
            cp.write_text(json.dumps(commit, ensure_ascii=True), encoding="utf-8")
            rp.write_text(json.dumps(req, ensure_ascii=True), encoding="utf-8")
            out = verify_accept_predicate(
                spec_path=spec_path,
                commit_path=cp,
                request_path=rp,
                policy0_keys=f"0:{k0}",
                policy1_keys=f"0:{k1}",
                now=ts,
                user_confirm=False,
                replay_seen=False,
            )
            self.assertTrue(bool(out.get("accepts")), msg=str(out))
            self.assertEqual(str(out.get("decision")), "ACCEPT")

    def test_require_confirm_is_distinct_from_invalid_evidence(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        spec_path = repo_root / "spec" / "secureclaw_accept_predicate_v1.json"
        k0 = "11" * 32
        k1 = "22" * 32
        action_id = "a_confirm"
        program_id = "policy_unified_v1"

        req = {
            "action_id": action_id,
            "intent_id": "SendMessage",
            "caller": "c",
            "session": "s",
            "inputs": {"channel": "email", "recipient": "alice@example.com", "domain": "", "text": "hello"},
        }
        req_sha = request_sha256_v1(intent_id=req["intent_id"], caller=req["caller"], session=req["session"], inputs=req["inputs"])
        ts = int(time.time())

        # need_confirm reconstructs to 1.
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1, "need_confirm": 1, "patch0": 1, "patch1": 0},
            ts=ts,
        )
        p1 = _mk_commit_proof(
            server_id=1,
            key_hex=k1,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 0, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=ts,
        )
        commit = {"policy0": p0, "policy1": p1}

        with tempfile.TemporaryDirectory() as td:
            td = str(td)
            cp = Path(td) / "commit.json"
            rp = Path(td) / "req.json"
            cp.write_text(json.dumps(commit, ensure_ascii=True), encoding="utf-8")
            rp.write_text(json.dumps(req, ensure_ascii=True), encoding="utf-8")
            out = verify_accept_predicate(
                spec_path=spec_path,
                commit_path=cp,
                request_path=rp,
                policy0_keys=f"0:{k0}",
                policy1_keys=f"0:{k1}",
                now=ts,
                user_confirm=False,
                replay_seen=False,
            )
            self.assertTrue(bool(out.get("evidence_valid")), msg=str(out))
            self.assertFalse(bool(out.get("accepts")))
            self.assertEqual(str(out.get("decision")), "REQUIRE_CONFIRM")


if __name__ == "__main__":
    unittest.main()

