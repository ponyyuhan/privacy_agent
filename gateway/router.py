from typing import Dict, Any

from .handles import HandleStore
from .executors.fsexec import FSExec
from .executors.msgexec import MsgExec
from .executors.cryptoexec import CryptoExec
from .executors.netexec import NetExec
from .guardrails import ObliviousGuardrails
from .audit import AuditEvent, get_audit_logger, now_ts

class IntentRouter:
    def __init__(self, handles: HandleStore, guardrails: ObliviousGuardrails):
        self.handles = handles
        self.guardrails = guardrails
        self.fs = FSExec(handles)
        self.msg = MsgExec(handles, guardrails)
        self.crypto = CryptoExec(handles)
        self.net = NetExec(handles, guardrails)

    def act(self, intent_id: str, inputs: Dict[str, Any], constraints: Dict[str, Any], caller: str, session: str) -> Dict[str, Any]:
        audit = get_audit_logger()
        audit.log(
            AuditEvent(
                ts=now_ts(),
                event="act_request",
                session=session,
                caller=caller,
                intent_id=intent_id,
                data={"input_keys": sorted(list((inputs or {}).keys()))},
            )
        )

        # Level 2: the agent cannot choose low-level tools; only intents exist.
        if intent_id == "ReadFile":
            obs = self.fs.read_file(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "ReadSecret":
            obs = self.crypto.read_secret(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "UseCredential":
            obs = self.crypto.use_credential(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "Declassify":
            obs = self.crypto.declassify(inputs, constraints, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "CheckMessagePolicy":
            obs = self.msg.check_message_policy(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "SendMessage":
            obs = self.msg.send_message(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "FetchResource":
            obs = self.net.fetch(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "WriteWorkspaceFile":
            obs = self.fs.write_workspace_file(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "DescribeHandle":
            obs = self.crypto.describe_handle(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "RevokeHandle":
            obs = self.crypto.revoke_handle(inputs, constraints, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "RevokeSession":
            obs = self.crypto.revoke_session(inputs, constraints, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "ListWorkspaceFiles":
            obs = self.fs.list_workspace_files(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "ReadWorkspaceFile":
            obs = self.fs.read_workspace_file(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        return {
            "status": "DENY",
            "summary": f"Unknown intent_id: {intent_id}",
            "data": {},
            "artifacts": [],
            "reason_code": "UNKNOWN_INTENT",
        }
