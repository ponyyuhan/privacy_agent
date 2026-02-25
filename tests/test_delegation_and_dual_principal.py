from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from common.delegation_token import mint_delegation_token, parse_and_verify_delegation_token
from gateway.fss_pir import PirClient
from gateway.guardrails import ObliviousGuardrails
from gateway.handles import HandleStore
from gateway.router import IntentRouter


class DelegationAndDualPrincipalTests(unittest.TestCase):
    def _build_router(self) -> IntentRouter:
        handles = HandleStore()
        pir = PirClient(
            policy0_url="http://127.0.0.1:1",
            policy1_url="http://127.0.0.1:1",
            domain_size=4096,
        )
        guardrails = ObliviousGuardrails(pir=pir, handles=handles, domain_size=4096, max_tokens=16)
        return IntentRouter(handles=handles, guardrails=guardrails)

    def test_external_side_effect_requires_delegation(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {
                "UNIFIED_POLICY": "0",
                "DELEGATION_REQUIRED_FOR_EXTERNAL": "1",
                "DELEGATION_DB_PATH": os.path.join(td, "delegation.sqlite"),
            },
            clear=False,
        ):
            r = self._build_router()
            obs = r.act(
                "SendInterAgentMessage",
                {"to_agent": "agent-b", "text": "hello"},
                {"external_principal": "ext:partner-low"},
                caller="artifact",
                session="s1",
            )
            self.assertEqual(str(obs.get("status")), "DENY")
            self.assertEqual(str(obs.get("reason_code")), "DELEGATION_REQUIRED")

    def test_valid_delegation_then_revoke(self) -> None:
        key = "ab" * 32
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {
                "UNIFIED_POLICY": "0",
                "DELEGATION_REQUIRED_FOR_EXTERNAL": "1",
                "DELEGATION_TOKEN_KEY": key,
                "DELEGATION_DB_PATH": os.path.join(td, "delegation.sqlite"),
            },
            clear=False,
        ):
            r = self._build_router()
            caller = "unittest-agent"
            token = mint_delegation_token(
                key_hex=key,
                issuer="ext:internal-blue",
                subject=caller,
                session="s1",
                scope=["intent:SendInterAgentMessage"],
                ttl_s=600,
            )
            chk = parse_and_verify_delegation_token(
                key_hex=key,
                token=token,
                expected_session="s1",
                expected_subject=caller,
                expected_intent="SendInterAgentMessage",
            )
            self.assertTrue(chk.ok)
            self.assertIsNotNone(chk.token)

            ok_send = r.act(
                "SendInterAgentMessage",
                {"to_agent": "agent-b", "text": "hello"},
                {"external_principal": "ext:internal-blue", "delegation_token": token},
                caller=caller,
                session="s1",
            )
            self.assertEqual(str(ok_send.get("status")), "OK")

            rev = r.act(
                "RevokeDelegation",
                {"delegation_jti": str((chk.token or object()).jti), "reason": "test"},
                {"user_confirm": True},
                caller=caller,
                session="s1",
            )
            self.assertEqual(str(rev.get("status")), "OK")

            denied = r.act(
                "SendInterAgentMessage",
                {"to_agent": "agent-b", "text": "hello2"},
                {"external_principal": "ext:internal-blue", "delegation_token": token},
                caller=caller,
                session="s1",
            )
            self.assertEqual(str(denied.get("status")), "DENY")
            self.assertEqual(str(denied.get("reason_code")), "DELEGATION_REVOKED")

    def test_dual_principal_denies_intent_not_allowed_for_external(self) -> None:
        key = "cd" * 32
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {
                "UNIFIED_POLICY": "0",
                "DELEGATION_REQUIRED_FOR_EXTERNAL": "1",
                "DELEGATION_TOKEN_KEY": key,
                "DELEGATION_DB_PATH": os.path.join(td, "delegation.sqlite"),
            },
            clear=False,
        ):
            r = self._build_router()
            token = mint_delegation_token(
                key_hex=key,
                issuer="ext:partner-low",
                subject="artifact",
                session="s2",
                scope=["intent:SendMessage"],
                ttl_s=600,
            )
            obs = r.act(
                "SendMessage",
                {"recipient": "alice@example.com", "text": "hi", "channel": "email"},
                {"external_principal": "ext:partner-low", "delegation_token": token},
                caller="artifact",
                session="s2",
            )
            self.assertEqual(str(obs.get("status")), "DENY")
            self.assertEqual(str(obs.get("reason_code")), "PRINCIPAL_CAPABILITY_DENY")


if __name__ == "__main__":
    unittest.main()
