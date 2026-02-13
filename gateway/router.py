import os
from typing import Dict, Any

from .handles import HandleStore
from .executors.fsexec import FSExec
from .executors.msgexec import MsgExec
from .executors.cryptoexec import CryptoExec
from .executors.netexec import NetExec
from .executors.webhookexec import WebhookExec
from .executors.skillexec import SkillExec
from .guardrails import ObliviousGuardrails
from .egress_policy import EgressPolicyEngine
from .skill_policy import SkillIngressPolicyEngine
from .skill_store import SkillStore
from .tx_store import TxStore
from .capabilities import get_capabilities
from .audit import AuditEvent, get_audit_logger, now_ts
from common.workload_token import verify_workload_token

class IntentRouter:
    def __init__(self, handles: HandleStore, guardrails: ObliviousGuardrails):
        self.handles = handles
        self.guardrails = guardrails
        self.tx_store = TxStore()
        self.policy = EgressPolicyEngine(pir=guardrails.pir, handles=handles, tx_store=self.tx_store, domain_size=guardrails.domain_size, max_tokens=guardrails.max_tokens)
        self.skill_policy = SkillIngressPolicyEngine(pir=guardrails.pir, tx_store=self.tx_store, domain_size=guardrails.domain_size, max_tokens=guardrails.max_tokens)
        self.skill_store = SkillStore()
        self.fs = FSExec(handles)
        self.msg = MsgExec(handles, self.policy)
        self.crypto = CryptoExec(handles, self.tx_store)
        self.net = NetExec(handles, self.policy)
        self.webhook = WebhookExec(handles, self.policy)
        self.skill = SkillExec(handles, self.skill_policy, self.skill_store)

    def act(self, intent_id: str, inputs: Dict[str, Any], constraints: Dict[str, Any], caller: str, session: str) -> Dict[str, Any]:
        audit = get_audit_logger()
        orig_caller = caller
        # Optional per-skill workload identity: if present and valid, override the untrusted caller string.
        wt = None
        token = None
        if isinstance(constraints, dict):
            token = constraints.get("workload_token") or constraints.get("workload_token_b64")
        if isinstance(token, str) and token.strip():
            key_hex = os.getenv("WORKLOAD_TOKEN_KEY", "").strip()
            wt = verify_workload_token(key_hex=key_hex, token=token.strip(), session=session)
            if wt is None:
                obs = {
                    "status": "DENY",
                    "summary": "Invalid workload token.",
                    "data": {"caller": str(orig_caller), "intent_id": str(intent_id)},
                    "artifacts": [],
                    "reason_code": "WORKLOAD_TOKEN_INVALID",
                }
                audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=str(orig_caller), intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
                return obs
            caller = f"skill:{wt.skill_digest}"

        audit.log(
            AuditEvent(
                ts=now_ts(),
                event="act_request",
                session=session,
                caller=caller,
                intent_id=intent_id,
                data={
                    "input_keys": sorted(list((inputs or {}).keys())),
                    "orig_caller": str(orig_caller),
                    "workload_skill_digest": (wt.skill_digest if wt else ""),
                },
            )
        )

        caps = get_capabilities(caller)
        if not caps.allow_intent(intent_id):
            obs = {
                "status": "DENY",
                "summary": "Caller capability does not allow this intent.",
                "data": {"caller": caller, "intent_id": intent_id},
                "artifacts": [],
                "reason_code": "CAPABILITY_DENY",
            }
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs

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
            obs = self.msg.send_message(inputs, constraints, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "CheckWebhookPolicy":
            obs = self.webhook.check_webhook_policy(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "PostWebhook":
            obs = self.webhook.post_webhook(inputs, constraints, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "FetchResource":
            obs = self.net.fetch(inputs, constraints, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "CheckFetchPolicy":
            obs = self.net.check_fetch_policy(inputs, session=session, caller=caller)
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
        if intent_id == "ImportSkill":
            obs = self.skill.import_skill(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "DescribeSkill":
            obs = self.skill.describe_skill(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "CheckSkillInstallPolicy":
            obs = self.skill.check_skill_install_policy(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "CommitSkillInstall":
            obs = self.skill.commit_skill_install(inputs, constraints, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "ListEnabledSkills":
            obs = self.skill.list_enabled_skills(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        return {
            "status": "DENY",
            "summary": f"Unknown intent_id: {intent_id}",
            "data": {},
            "artifacts": [],
            "reason_code": "UNKNOWN_INTENT",
        }
