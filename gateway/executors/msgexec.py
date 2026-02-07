import secrets
from typing import Dict, Any, List
from ..handles import HandleStore
from ..guardrails import ObliviousGuardrails
from ..executor_client import get_executor_client

class MsgExec:
    def __init__(self, handles: HandleStore, guardrails: ObliviousGuardrails):
        self.handles = handles
        self.guardrails = guardrails

    def check_message_policy(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        """Dry-run message guardrails without performing the send.

        This is useful for safety-constrained agent runtimes that will refuse to perform real-world
        side effects, while still exercising MIRAGE policy checks end-to-end (including PIR/FSS).
        """
        channel = str(inputs.get("channel", "email"))
        recipient = str(inputs.get("recipient", ""))
        text = str(inputs.get("text", ""))
        artifacts = inputs.get("artifacts", []) or []

        action_id = f"a_{secrets.token_urlsafe(12)}"
        dec = self.guardrails.check_egress_message(
            recipient=recipient,
            text=text,
            artifacts=artifacts,
            session=session,
            caller=caller,
            action_id=action_id,
        )
        if not dec.allow:
            return {
                "status": "DENY",
                "summary": "Message would be blocked by guardrails (dry-run).",
                "data": {"channel": channel, "recipient": recipient, "evidence": dec.evidence},
                "artifacts": [],
                "reason_code": dec.reason_code,
            }
        return {
            "status": "OK",
            "summary": "Message would be allowed by guardrails (dry-run).",
            "data": {"channel": channel, "recipient": recipient, "evidence": dec.evidence},
            "artifacts": [],
            "reason_code": "ALLOW",
        }

    def send_message(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        channel = str(inputs.get("channel", "email"))
        recipient = str(inputs.get("recipient", ""))
        text = str(inputs.get("text", ""))
        artifacts = inputs.get("artifacts", []) or []

        action_id = f"a_{secrets.token_urlsafe(12)}"
        dec = self.guardrails.check_egress_message(
            recipient=recipient,
            text=text,
            artifacts=artifacts,
            session=session,
            caller=caller,
            action_id=action_id,
        )
        if not dec.allow:
            return {
                "status": "DENY",
                "summary": "Message blocked by guardrails.",
                "data": {"channel": channel, "recipient": recipient},
                "artifacts": [],
                "reason_code": dec.reason_code,
            }

        # Pass through an executor service if configured (dual authorization checks happen there).
        ex = get_executor_client()
        if ex is None:
            return {
                "status": "OK",
                "summary": "Message allowed (no external executor configured; demo stub).",
                "data": {"channel": channel, "recipient": recipient, "sent_chars": len(text)},
                "artifacts": [],
                "reason_code": "ALLOW",
            }

        # We always include a fresh action_id in proofs; if evidence is missing, fail closed.
        if not isinstance(dec.evidence, dict):
            return {
                "status": "DENY",
                "summary": "Missing policy evidence for executor enforcement.",
                "data": {"channel": channel, "recipient": recipient},
                "artifacts": [],
                "reason_code": "MISSING_EVIDENCE",
            }

        resp = ex.send_message(
            action_id=str(action_id),
            channel=channel,
            recipient=recipient,
            text=text,
            artifacts=list(artifacts),
            dlp_mode=self.guardrails.dlp_mode,
            evidence=dec.evidence,
        )
        if resp.get("status") != "OK":
            return {
                "status": "DENY",
                "summary": "Executor denied the action.",
                "data": {"channel": channel, "recipient": recipient},
                "artifacts": [],
                "reason_code": str(resp.get("reason_code") or "EXECUTOR_DENY"),
            }
        return {
            "status": "OK",
            "summary": "Message allowed and sent (executor stub).",
            "data": {"channel": channel, "recipient": recipient, "sent_chars": len(text)},
            "artifacts": [],
            "reason_code": "ALLOW",
        }
