import re
import hmac
import hashlib
from typing import Dict, Any
from ..handles import HandleStore
from ..secret_store import SecretStore
from ..tx_store import TxStore

class CryptoExec:
    def __init__(self, handles: HandleStore, tx_store: TxStore | None = None):
        self.handles = handles
        self.tx_store = tx_store
        self.secrets = SecretStore()
        # Best-effort redaction for demo output. The real design would use structured declassification.
        self._redact_res = [
            re.compile(r"AKIA[0-9A-Z]{16}"),
            re.compile(r"xoxb-[A-Za-z0-9-]+"),
            re.compile(r"-----BEGIN[ -].*?PRIVATE KEY-----"),
        ]

    def describe_handle(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        hid = str(inputs.get("handle", ""))
        rec = self.handles.get(hid)
        if not rec or rec.session != session:
            return {"status": "DENY", "summary": "Invalid or expired handle.", "data": {}, "artifacts": [], "reason_code": "HANDLE_INVALID"}
        if rec.caller != caller:
            return {"status": "DENY", "summary": "Handle is bound to a different caller.", "data": {}, "artifacts": [], "reason_code": "HANDLE_CALLER_MISMATCH"}
        return {
            "status": "OK",
            "summary": "Handle description (no secret value disclosed).",
            "data": self.handles.describe(hid) or {},
            "artifacts": [],
            "reason_code": "ALLOW",
        }

    def revoke_handle(self, inputs: Dict[str, Any], constraints: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        hid = str(inputs.get("handle", ""))
        user_confirm = bool(constraints.get("user_confirm", False))
        if not user_confirm:
            return {"status": "DENY", "summary": "Revocation requires explicit user confirmation.", "data": {}, "artifacts": [], "reason_code": "REQUIRE_CONFIRM"}
        rec = self.handles.get(hid)
        if not rec or rec.session != session:
            return {"status": "DENY", "summary": "Invalid or expired handle.", "data": {}, "artifacts": [], "reason_code": "HANDLE_INVALID"}
        if rec.caller != caller:
            return {"status": "DENY", "summary": "Handle is bound to a different caller.", "data": {}, "artifacts": [], "reason_code": "HANDLE_CALLER_MISMATCH"}
        ok = self.handles.revoke(hid)
        return {
            "status": "OK" if ok else "DENY",
            "summary": "Handle revoked." if ok else "Handle not found.",
            "data": {"handle": hid},
            "artifacts": [],
            "reason_code": "ALLOW" if ok else "HANDLE_INVALID",
        }

    def revoke_session(self, inputs: Dict[str, Any], constraints: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        _ = inputs  # reserved
        user_confirm = bool(constraints.get("user_confirm", False))
        if not user_confirm:
            return {"status": "DENY", "summary": "Session revocation requires explicit user confirmation.", "data": {}, "artifacts": [], "reason_code": "REQUIRE_CONFIRM"}
        # Caller is included for audit/binding but session revocation is scoped to the current session.
        n_handles = self.handles.revoke_session(session)
        n_tx = 0
        if self.tx_store is not None:
            n_tx = self.tx_store.revoke_session(session)
        return {
            "status": "OK",
            "summary": "Session revoked (handles + tx).",
            "data": {"revoked_handles": int(n_handles), "revoked_tx": int(n_tx)},
            "artifacts": [],
            "reason_code": "ALLOW",
        }

    def read_secret(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        # In a real system this would use workload identity / attestation to mint short-lived capability tokens.
        name = str(inputs.get("name", ""))
        # Demo: mint a capability handle instead of returning secrets.
        rec = self.handles.mint(
            label="CAPABILITY",
            sensitivity="HIGH",
            value={"secret_name": name, "note": "demo secretless capability"},
            allowed_sinks=["UseCredential"],
            session=session,
            ttl_seconds=300,
            caller=caller,
            issuer_intent="ReadSecret",
        )
        return {
            "status": "OK",
            "summary": "Secretless capability minted (no plaintext secret returned).",
            "data": {"name": name},
            "artifacts": [{"handle": rec.handle, "label": rec.label, "sensitivity": rec.sensitivity}],
            "reason_code": "CAPABILITY_HANDLE",
        }

    def use_credential(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        hid = str(inputs.get("handle", ""))
        op = str(inputs.get("op", "SIGN"))
        target = str(inputs.get("target", "generic"))

        rec = self.handles.get(hid)
        if not rec or rec.session != session:
            return {
                "status": "DENY",
                "summary": "Invalid or expired handle.",
                "data": {},
                "artifacts": [],
                "reason_code": "HANDLE_INVALID",
            }
        if rec.caller != caller:
            return {
                "status": "DENY",
                "summary": "Handle is bound to a different caller.",
                "data": {},
                "artifacts": [],
                "reason_code": "HANDLE_CALLER_MISMATCH",
            }
        if "UseCredential" not in rec.allowed_sinks:
            return {
                "status": "DENY",
                "summary": "Handle cannot be used for this operation.",
                "data": {"label": rec.label},
                "artifacts": [],
                "reason_code": "HANDLE_SINK_BLOCKED",
            }

        # Demo: compute an HMAC using a secret referenced by the capability handle.
        # The secret value is never returned to the agent.
        secret_name = None
        if isinstance(rec.value, dict):
            secret_name = rec.value.get("secret_name")
        secret_val = self.secrets.get(str(secret_name or ""))
        if secret_val is None:
            return {
                "status": "DENY",
                "summary": "Unknown secret reference.",
                "data": {"secret_name": secret_name},
                "artifacts": [],
                "reason_code": "SECRET_NOT_FOUND",
            }
        mac = hmac.new(secret_val.encode("utf-8"), target.encode("utf-8"), hashlib.sha256).hexdigest()
        signature = f"hmac_sha256({op}:{target})={mac[:16]}..."
        return {
            "status": "OK",
            "summary": "Credential used inside trusted executor (no secret disclosed).",
            "data": {"op": op, "target": target, "result": signature},
            "artifacts": [],
            "reason_code": "ALLOW",
        }

    def declassify(self, inputs: Dict[str, Any], constraints: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        hid = str(inputs.get("handle", ""))
        purpose = str(inputs.get("purpose", ""))
        user_confirm = bool(constraints.get("user_confirm", False))
        max_chars = int(constraints.get("max_chars", 400))
        if max_chars < 50:
            max_chars = 50
        if max_chars > 2000:
            max_chars = 2000

        rec = self.handles.get(hid)
        if not rec or rec.session != session:
            return {
                "status": "DENY",
                "summary": "Invalid or expired handle.",
                "data": {},
                "artifacts": [],
                "reason_code": "HANDLE_INVALID",
            }
        if rec.caller != caller:
            return {
                "status": "DENY",
                "summary": "Handle is bound to a different caller.",
                "data": {},
                "artifacts": [],
                "reason_code": "HANDLE_CALLER_MISMATCH",
            }
        if "Declassify" not in rec.allowed_sinks:
            return {
                "status": "DENY",
                "summary": "Handle cannot be declassified by policy.",
                "data": {"label": rec.label, "purpose": purpose},
                "artifacts": [],
                "reason_code": "DECLASSIFY_BLOCKED",
            }
        if rec.sensitivity.upper() == "HIGH" and not user_confirm:
            return {
                "status": "DENY",
                "summary": "Declassification requires explicit user confirmation for HIGH sensitivity handles.",
                "data": {"label": rec.label, "purpose": purpose},
                "artifacts": [],
                "reason_code": "REQUIRE_CONFIRM",
            }

        # Demo: attempt to extract a safe preview from handle payload.
        value = rec.value
        if isinstance(value, dict) and "content" in value:
            text = str(value.get("content", ""))
        else:
            text = str(value)

        redacted = text
        for r in self._redact_res:
            redacted = r.sub("[REDACTED]", redacted)

        return {
            "status": "OK",
            "summary": "Declassified preview returned (demo; redaction applied).",
            "data": {"purpose": purpose, "text_preview": redacted[:max_chars]},
            "artifacts": [],
            "reason_code": "ALLOW",
        }
