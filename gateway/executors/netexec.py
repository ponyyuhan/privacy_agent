import secrets
from typing import Dict, Any
from ..handles import HandleStore
from ..guardrails import ObliviousGuardrails
from ..executor_client import get_executor_client

class NetExec:
    def __init__(self, handles: HandleStore, guardrails: ObliviousGuardrails):
        self.handles = handles
        self.guardrails = guardrails

    def fetch(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        # Demo: only allow fetching a resource_id that maps to a domain.
        resource_id = str(inputs.get("resource_id", "example"))
        domain = str(inputs.get("domain", "example.com"))

        action_id = f"a_{secrets.token_urlsafe(12)}"
        dec = self.guardrails.check_network_domain(domain=domain, action_id=action_id, caller=caller, session=session)
        if not dec.allow:
            return {
                "status": "DENY",
                "summary": "Network fetch blocked by domain policy.",
                "data": {"domain": domain},
                "artifacts": [],
                "reason_code": dec.reason_code,
            }

        ex = get_executor_client()
        if ex is None:
            return {
                "status": "OK",
                "summary": "Fetched resource (no external executor configured; demo stub).",
                "data": {"resource_id": resource_id, "domain": domain, "content_preview": "<html>...</html>"},
                "artifacts": [],
                "reason_code": "ALLOW",
            }
        if not isinstance(dec.evidence, dict):
            return {
                "status": "DENY",
                "summary": "Missing policy evidence for executor enforcement.",
                "data": {"domain": domain},
                "artifacts": [],
                "reason_code": "MISSING_EVIDENCE",
            }
        resp = ex.fetch(action_id=action_id, resource_id=resource_id, domain=domain, evidence=dec.evidence)
        if resp.get("status") != "OK":
            return {
                "status": "DENY",
                "summary": "Executor denied the action.",
                "data": {"domain": domain},
                "artifacts": [],
                "reason_code": str(resp.get("reason_code") or "EXECUTOR_DENY"),
            }
        return {
            "status": "OK",
            "summary": "Fetched resource (executor stub).",
            "data": resp.get("data") or {"resource_id": resource_id, "domain": domain, "content_preview": "<html>...</html>"},
            "artifacts": [],
            "reason_code": "ALLOW",
        }
