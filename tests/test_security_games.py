from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import unittest

from executor_server import server as ex
from common.canonical import request_sha256_v1


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
        ex._REPLAY_GUARD = None

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

    def test_replay_denied(self) -> None:
        action_id = "a_replay"
        program_id = "policy_unified_v1"
        req_sha = request_sha256_v1(
            intent_id="SendMessage",
            caller="c",
            session="s",
            inputs={"channel": "email", "recipient": "alice@example.com", "domain": "", "text": "hello"},
        )
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=int(time.time()),
        )
        p1 = _mk_commit_proof(
            server_id=1,
            key_hex=self.k1,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 0, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=int(time.time()),
        )

        req = ex.ExecSendMessageReq(
            action_id=action_id,
            channel="email",
            recipient="alice@example.com",
            domain="",
            text="hello",
            artifacts=[],
            dlp_mode="fourgram",
            evidence={},
            commit={"policy0": p0, "policy1": p1},
            caller="c",
            session="s",
            user_confirm=False,
        )
        r1 = ex.exec_send_message(req)
        self.assertEqual(str(r1.get("status")), "OK")

        r2 = ex.exec_send_message(req)
        self.assertEqual(str(r2.get("status")), "DENY")
        self.assertEqual(str(r2.get("reason_code")), "REPLAY_DENY")

    def test_session_binding_denied(self) -> None:
        action_id = "a_sess_bind"
        program_id = "policy_unified_v1"
        req_sha = request_sha256_v1(
            intent_id="SendMessage",
            caller="caller_a",
            session="session_a",
            inputs={"channel": "email", "recipient": "alice@example.com", "domain": "", "text": "hello"},
        )
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=int(time.time()),
        )
        p1 = _mk_commit_proof(
            server_id=1,
            key_hex=self.k1,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 0, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=int(time.time()),
        )
        # Change the session in the request so executor recomputes a different request_sha256.
        req = ex.ExecSendMessageReq(
            action_id=action_id,
            channel="email",
            recipient="alice@example.com",
            domain="",
            text="hello",
            artifacts=[],
            dlp_mode="fourgram",
            evidence={},
            commit={"policy0": p0, "policy1": p1},
            caller="caller_a",
            session="session_b",
            user_confirm=False,
        )
        r = ex.exec_send_message(req)
        self.assertEqual(str(r.get("status")), "DENY")
        self.assertEqual(str(r.get("reason_code")), "BAD_COMMIT_PROOF")
        self.assertEqual(str(r.get("details")), "bad_request_sha256")

    def test_caller_binding_denied(self) -> None:
        action_id = "a_caller_bind"
        program_id = "policy_unified_v1"
        req_sha = request_sha256_v1(
            intent_id="SendMessage",
            caller="caller_a",
            session="session_a",
            inputs={"channel": "email", "recipient": "alice@example.com", "domain": "", "text": "hello"},
        )
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=int(time.time()),
        )
        p1 = _mk_commit_proof(
            server_id=1,
            key_hex=self.k1,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 0, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=int(time.time()),
        )
        # Change the caller in the request so executor recomputes a different request_sha256.
        req = ex.ExecSendMessageReq(
            action_id=action_id,
            channel="email",
            recipient="alice@example.com",
            domain="",
            text="hello",
            artifacts=[],
            dlp_mode="fourgram",
            evidence={},
            commit={"policy0": p0, "policy1": p1},
            caller="caller_b",
            session="session_a",
            user_confirm=False,
        )
        r = ex.exec_send_message(req)
        self.assertEqual(str(r.get("status")), "DENY")
        self.assertEqual(str(r.get("reason_code")), "BAD_COMMIT_PROOF")
        self.assertEqual(str(r.get("details")), "bad_request_sha256")

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
