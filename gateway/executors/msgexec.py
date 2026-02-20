import os
from typing import Dict, Any, List
from ..handles import HandleStore
from ..egress_policy import EgressPolicyEngine
from ..executor_client import get_executor_client

class MsgExec:
    def __init__(self, handles: HandleStore, policy: EgressPolicyEngine):
        self.handles = handles
        self.policy = policy

    def check_message_policy(self, inputs: Dict[str, Any], constraints: Dict[str, Any] | None = None, session: str = "", caller: str = "unknown") -> Dict[str, Any]:
        """Dry-run message guardrails without performing the send.

        This is useful for safety-constrained agent runtimes that will refuse to perform real-world
        side effects, while still exercising MIRAGE policy checks end-to-end (including PIR/FSS).
        """
        channel = str(inputs.get("channel", "email"))
        recipient = str(inputs.get("recipient", ""))
        text = str(inputs.get("text", ""))
        artifacts = inputs.get("artifacts", []) or []

        auth_ctx = (constraints or {}).get("_auth_ctx") if isinstance((constraints or {}).get("_auth_ctx"), dict) else {}
        pv_constraints = {"_auth_ctx": dict(auth_ctx)} if auth_ctx else {}
        pv = self.policy.preview(
            intent_id="CheckMessagePolicy",
            inputs={"channel": channel, "recipient": recipient, "text": text, "domain": str(inputs.get("domain", "")), "artifacts": list(artifacts)},
            constraints=pv_constraints,
            session=session,
            caller=caller,
        )
        if not pv.get("allow_pre", False):
            return {
                "status": "DENY",
                "summary": "Message would be blocked by policy (dry-run).",
                "data": {"channel": channel, "recipient": recipient, "tx_id": pv.get("tx_id"), "patch": pv.get("patch"), "evidence": pv.get("evidence")},
                "artifacts": [],
                "reason_code": str(pv.get("reason_code") or "POLICY_DENY"),
            }
        if pv.get("need_confirm", False):
            return {
                "status": "DENY",
                "summary": "Message requires explicit user confirmation (dry-run).",
                "data": {"channel": channel, "recipient": recipient, "tx_id": pv.get("tx_id"), "patch": pv.get("patch"), "evidence": pv.get("evidence")},
                "artifacts": [],
                "reason_code": "REQUIRE_CONFIRM",
            }
        return {
            "status": "OK",
            "summary": "Message would be allowed by policy (dry-run).",
            "data": {"channel": channel, "recipient": recipient, "tx_id": pv.get("tx_id"), "patch": pv.get("patch"), "evidence": pv.get("evidence")},
            "artifacts": [],
            "reason_code": "ALLOW",
        }

    def send_message(self, inputs: Dict[str, Any], constraints: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        channel = str(inputs.get("channel", "email"))
        recipient = str(inputs.get("recipient", ""))
        text = str(inputs.get("text", ""))
        artifacts = inputs.get("artifacts", []) or []
        tx_id = str(inputs.get("tx_id") or "").strip()
        user_confirm = bool((constraints or {}).get("user_confirm", False))
        auth_ctx = (constraints or {}).get("_auth_ctx") if isinstance((constraints or {}).get("_auth_ctx"), dict) else {}
        pv_constraints = {"_auth_ctx": dict(auth_ctx)} if auth_ctx else {}

        # If a tx_id is provided, commit that preview. Otherwise, create a fresh preview and commit it.
        if tx_id:
            auth = self.policy.commit_from_tx(
                tx_id=tx_id,
                intent_id="SendMessage",
                constraints={"user_confirm": user_confirm, "_auth_ctx": dict(auth_ctx)} if auth_ctx else {"user_confirm": user_confirm},
                session=session,
                caller=caller,
            )
            if auth.get("status") != "OK":
                return auth
            commit_ev = (auth.get("data") or {}).get("commit_evidence") or {}
            action_id = str((auth.get("data") or {}).get("action_id") or "")
            request_sha256 = str((auth.get("data") or {}).get("request_sha256") or "")
        else:
            pv = self.policy.preview(
                intent_id="SendMessage",
                inputs={"channel": channel, "recipient": recipient, "text": text, "domain": str(inputs.get("domain", "")), "artifacts": list(artifacts)},
                constraints=pv_constraints,
                session=session,
                caller=caller,
            )
            if not pv.get("allow_pre", False):
                return {
                    "status": "DENY",
                    "summary": "Message blocked by policy.",
                    "data": {"channel": channel, "recipient": recipient, "tx_id": pv.get("tx_id"), "patch": pv.get("patch")},
                    "artifacts": [],
                    "reason_code": str(pv.get("reason_code") or "POLICY_DENY"),
                }
            if pv.get("need_confirm", False) and not user_confirm:
                return {
                    "status": "DENY",
                    "summary": "Message requires explicit user confirmation.",
                    "data": {"channel": channel, "recipient": recipient, "tx_id": pv.get("tx_id"), "patch": pv.get("patch")},
                    "artifacts": [],
                    "reason_code": "REQUIRE_CONFIRM",
                }
            commit_ev = (pv.get("evidence") or {}).get("commit") or {}
            action_id = str(pv.get("action_id") or "")
            request_sha256 = str(pv.get("request_sha256") or "")

        # Pass through an executor service if configured (dual authorization checks happen there).
        ex = get_executor_client()
        if ex is None:
            return {
                "status": "OK",
                "summary": "Message allowed (no external executor configured; demo stub).",
                "data": {"channel": channel, "recipient": recipient, "sent_chars": len(text), "tx": {"action_id": action_id, "request_sha256": request_sha256}},
                "artifacts": [],
                "reason_code": "ALLOW",
            }

        if not isinstance(commit_ev, dict) or not commit_ev.get("policy0") or not commit_ev.get("policy1"):
            return {"status": "DENY", "summary": "Missing commit evidence for executor enforcement.", "data": {"channel": channel, "recipient": recipient}, "artifacts": [], "reason_code": "MISSING_EVIDENCE"}

        # Include the same shadowed fields used in PREVIEW, so executor can recompute request_sha256.
        dummy_domain = os.getenv("DUMMY_DOMAIN", "example.com")
        resp = ex.send_message(
            action_id=str(action_id),
            channel=channel,
            recipient=recipient,
            domain=str(dummy_domain),
            text=text,
            artifacts=[],
            dlp_mode=os.getenv("DLP_MODE", "fourgram"),
            evidence={},
            commit=commit_ev,
            caller=caller,
            session=session,
            user_confirm=bool(user_confirm),
            external_principal=str(auth_ctx.get("external_principal") or ""),
            delegation_jti=str(auth_ctx.get("delegation_jti") or ""),
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
            "data": {"channel": channel, "recipient": recipient, "sent_chars": len(text), "tx": {"action_id": action_id, "request_sha256": request_sha256}},
            "artifacts": [],
            "reason_code": "ALLOW",
        }
