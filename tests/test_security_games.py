from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import unittest

from executor_server import server as ex


def _mac_b64(key_hex: str, payload: dict) -> str:
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    mac = hmac.new(bytes.fromhex(key_hex), msg, hashlib.sha256).digest()
    return base64.b64encode(mac).decode("ascii")


def _mk_commit_proof(*, server_id: int, key_hex: str, action_id: str, program_id: str, request_sha256: str, outputs: dict[str, int], ts: int | None = None) -> dict:
    payload = {
        "v": 1,
        "kind": "commit",
        "server_id": int(server_id),
        "kid": "0",
        "ts": int(ts if ts is not None else time.time()),
        "action_id": str(action_id),
        "program_id": str(program_id),
        "request_sha256": str(request_sha256),
        "outputs": {str(k): int(v) & 1 for k, v in outputs.items()},
        "commit_tag_share_b64": base64.b64encode(b"\x01" * 16).decode("ascii"),
    }
    payload["mac_b64"] = _mac_b64(key_hex, payload)
    return payload


class SecurityGameTests(unittest.TestCase):
    def setUp(self) -> None:
        self.k0 = "11" * 32
        self.k1 = "22" * 32
        os.environ["POLICY0_MAC_KEY"] = self.k0
        os.environ["POLICY1_MAC_KEY"] = self.k1
        os.environ["POLICY_MAC_TTL_S"] = "60"
        ex.POLICY0_KEYS = None
        ex.POLICY1_KEYS = None
        ex.MAC_TTL_S = 60

    def test_dual_valid_commit_proofs_accept(self) -> None:
        action_id = "a_test"
        program_id = "policy_unified_v1"
        req_sha = "ab" * 32
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1, "need_confirm": 0, "patch0": 0, "patch1": 0},
        )
        p1 = _mk_commit_proof(
            server_id=1,
            key_hex=self.k1,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 0, "need_confirm": 0, "patch0": 0, "patch1": 0},
        )
        outs, tag, code = ex._verify_commit_evidence({"policy0": p0, "policy1": p1}, action_id=action_id, program_id=program_id, request_sha256=req_sha)
        self.assertEqual(code, "OK")
        self.assertIsNotNone(outs)
        self.assertIsNotNone(tag)
        self.assertEqual(int((outs or {}).get("allow_pre", 0)), 1)

    def test_missing_second_proof_rejected(self) -> None:
        action_id = "a_test_missing"
        program_id = "policy_unified_v1"
        req_sha = "cd" * 32
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1},
        )
        outs, tag, code = ex._verify_commit_evidence({"policy0": p0, "policy1": None}, action_id=action_id, program_id=program_id, request_sha256=req_sha)
        self.assertIsNone(outs)
        self.assertIsNone(tag)
        self.assertNotEqual(code, "OK")

    def test_bad_mac_rejected(self) -> None:
        action_id = "a_test_mac"
        program_id = "policy_unified_v1"
        req_sha = "ef" * 32
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1},
        )
        p1 = _mk_commit_proof(
            server_id=1,
            key_hex=self.k1,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 0},
        )
        p0["mac_b64"] = base64.b64encode(b"badbadbadbadbadb").decode("ascii")
        outs, tag, code = ex._verify_commit_evidence({"policy0": p0, "policy1": p1}, action_id=action_id, program_id=program_id, request_sha256=req_sha)
        self.assertIsNone(outs)
        self.assertIsNone(tag)
        self.assertNotEqual(code, "OK")

    def test_request_hash_binding_rejected(self) -> None:
        action_id = "a_test_sha"
        program_id = "policy_unified_v1"
        req_sha = "12" * 32
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1},
        )
        p1 = _mk_commit_proof(
            server_id=1,
            key_hex=self.k1,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 0},
        )
        outs, tag, code = ex._verify_commit_evidence({"policy0": p0, "policy1": p1}, action_id=action_id, program_id=program_id, request_sha256=("34" * 32))
        self.assertIsNone(outs)
        self.assertIsNone(tag)
        self.assertNotEqual(code, "OK")


if __name__ == "__main__":
    unittest.main()
