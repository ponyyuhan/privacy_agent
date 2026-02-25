from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

import gateway.federated_auth as fa
from common.federated_proof_token import mint_federated_proof_token


def _canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _payload_sha(payload: dict) -> str:
    return hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()


def _sign(key_hex: str, *, method: str, path: str, session: str, principal: str, ts_ms: int, nonce: str, payload_sha256: str) -> str:
    msg = "\n".join(
        [
            "secureclaw-federated-sig-v1",
            method.upper(),
            path,
            session,
            principal,
            str(int(ts_ms)),
            nonce,
            payload_sha256,
        ]
    ).encode("utf-8")
    mac = hmac.new(bytes.fromhex(key_hex), msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")


class FederatedAuthTests(unittest.TestCase):
    def test_mtls_required(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {
                "INGRESS_REPLAY_DB_PATH": os.path.join(td, "ingress_replay.sqlite"),
                "MIRAGE_MTLS_REQUIRED": "1",
            },
            clear=False,
        ):
            fa._REPLAY = None
            d = fa.verify_federated_ingress(
                method="POST",
                path="/act",
                payload={"intent_id": "ReadFile"},
                session="s",
                external_principal="ext:internal-a",
                mtls_client_cert_sha256="",
                sig_kid="",
                sig_value="",
                sig_ts_ms="",
                sig_nonce="",
                proof_token="",
            )
            self.assertFalse(d.ok)
            self.assertEqual(d.code, "MTLS_REQUIRED")

    def test_signature_and_proof_success_then_replay_denied(self) -> None:
        sig_key = "11" * 32
        proof_key = "22" * 32
        payload = {"intent_id": "ReadFile", "inputs": {"path_spec": "README.md"}, "constraints": {}, "caller": "artifact"}
        session = "s"
        principal = "ext:internal-blue"
        nonce = "n1"
        ts_ms = int(time.time() * 1000)
        sig = _sign(
            sig_key,
            method="POST",
            path="/act",
            session=session,
            principal=principal,
            ts_ms=ts_ms,
            nonce=nonce,
            payload_sha256=_payload_sha(payload),
        )
        proof = mint_federated_proof_token(
            key_hex=proof_key,
            principal=principal,
            session=session,
            ttl_s=120,
            evidence="mtls-attested",
        )

        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {
                "INGRESS_REPLAY_DB_PATH": os.path.join(td, "ingress_replay.sqlite"),
                "MIRAGE_FEDERATED_SIG_REQUIRED": "1",
                "MIRAGE_FEDERATED_PROOF_REQUIRED": "1",
                "MIRAGE_FEDERATED_SIG_KEYS": f"k0:{sig_key}",
                "MIRAGE_FEDERATED_PROOF_KEY": proof_key,
            },
            clear=False,
        ):
            fa._REPLAY = None
            d1 = fa.verify_federated_ingress(
                method="POST",
                path="/act",
                payload=payload,
                session=session,
                external_principal=principal,
                mtls_client_cert_sha256="",
                sig_kid="k0",
                sig_value=sig,
                sig_ts_ms=str(ts_ms),
                sig_nonce=nonce,
                proof_token=proof,
            )
            self.assertTrue(d1.ok)
            self.assertEqual(d1.code, "ALLOW")
            self.assertEqual(d1.external_principal, principal)

            # Replay of same nonce should fail.
            d2 = fa.verify_federated_ingress(
                method="POST",
                path="/act",
                payload=payload,
                session=session,
                external_principal=principal,
                mtls_client_cert_sha256="",
                sig_kid="k0",
                sig_value=sig,
                sig_ts_ms=str(ts_ms),
                sig_nonce=nonce,
                proof_token=proof,
            )
            self.assertFalse(d2.ok)
            self.assertEqual(d2.code, "FEDERATED_SIG_REPLAY")


if __name__ == "__main__":
    unittest.main()
