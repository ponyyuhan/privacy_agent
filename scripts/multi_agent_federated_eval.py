from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from common.delegation_token import mint_delegation_token, parse_and_verify_delegation_token
from gateway.fss_pir import PirClient
from gateway.guardrails import ObliviousGuardrails
from gateway.handles import HandleStore
from gateway.router import IntentRouter


@dataclass
class CaseResult:
    name: str
    status: str
    reason_code: str
    ok: bool
    latency_ms: float
    data: dict[str, Any]


def _build_router() -> IntentRouter:
    handles = HandleStore()
    pir = PirClient(
        policy0_url="http://127.0.0.1:1",
        policy1_url="http://127.0.0.1:1",
        domain_size=4096,
    )
    guardrails = ObliviousGuardrails(pir=pir, handles=handles, domain_size=4096, max_tokens=16)
    return IntentRouter(handles=handles, guardrails=guardrails)


def _run_case(fn) -> CaseResult:
    t0 = time.perf_counter()
    name, exp_ok, obs = fn()
    dt = (time.perf_counter() - t0) * 1000.0
    status = str(obs.get("status") or "")
    reason = str(obs.get("reason_code") or "")
    ok = (status == "OK") if exp_ok else (status == "DENY")
    return CaseResult(name=name, status=status, reason_code=reason, ok=ok, latency_ms=float(dt), data=obs.get("data") if isinstance(obs.get("data"), dict) else {})


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    out_dir = Path(os.getenv("OUT_DIR", str(repo_root / "artifact_out_compare"))).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "multi_agent_federated_eval.json"

    key = (os.getenv("DELEGATION_TOKEN_KEY") or "").strip() or ("45" * 32)
    env_patch = {
        "UNIFIED_POLICY": os.getenv("UNIFIED_POLICY", "0"),
        "DELEGATION_REQUIRED_FOR_EXTERNAL": "1",
        "DELEGATION_TOKEN_KEY": key,
        "DECLASSIFY_CONFIRM_LABELS": "MEMORY_ENTRY,WORKSPACE_FILE,FILE_CONTENT,INTER_AGENT_MESSAGE",
    }
    old_env: dict[str, str | None] = {k: os.environ.get(k) for k in env_patch.keys()}
    for k, v in env_patch.items():
        os.environ[k] = v

    try:
        r = _build_router()
        session = "ma-session-1"

        def mk_token(*, issuer: str, subject: str, scope: list[str], ttl_s: int = 600) -> str:
            return mint_delegation_token(
                key_hex=key,
                issuer=issuer,
                subject=subject,
                session=session,
                scope=scope,
                ttl_s=ttl_s,
            )

        tok_a = mk_token(
            issuer="ext:internal-blue",
            subject="agent-a",
            scope=["intent:SendInterAgentMessage", "intent:MemoryWrite", "intent:MemoryRead", "intent:Declassify"],
        )
        tok_mem = mk_token(
            issuer="ext:internal-blue",
            subject="agent-a",
            scope=["intent:MemoryWrite", "intent:MemoryRead", "intent:Declassify"],
        )
        tok_b = mk_token(
            issuer="ext:internal-blue",
            subject="agent-b",
            scope=["intent:ReceiveInterAgentMessages", "intent:Declassify"],
        )
        tok_low = mk_token(
            issuer="ext:partner-low",
            subject="agent-a",
            scope=["intent:SendMessage"],
        )

        chk_a = parse_and_verify_delegation_token(
            key_hex=key,
            token=tok_a,
            expected_session=session,
            expected_subject="agent-a",
            expected_intent="SendInterAgentMessage",
        )
        jti_a = str((chk_a.token or object()).jti)

        cases: list[CaseResult] = []

        def c1():
            obs = r.act(
                "SendInterAgentMessage",
                {"to_agent": "agent-b", "text": "project status: green"},
                {"external_principal": "ext:internal-blue", "delegation_token": tok_a},
                caller="agent-a",
                session=session,
            )
            return "allow_c2_send_with_delegation", True, obs

        def c2():
            obs = r.act(
                "ReceiveInterAgentMessages",
                {"agent_id": "agent-b", "max_messages": 1},
                {"external_principal": "ext:internal-blue", "delegation_token": tok_b},
                caller="agent-b",
                session=session,
            )
            return "allow_c2_receive_with_delegation", True, obs

        def c3():
            obs = r.act(
                "SendInterAgentMessage",
                {"to_agent": "agent-b", "text": "hello"},
                {"external_principal": "ext:internal-blue"},
                caller="agent-a",
                session=session,
            )
            return "deny_c2_send_missing_delegation", False, obs

        def c4():
            obs = r.act(
                "RevokeDelegation",
                {"delegation_jti": jti_a, "reason": "incident"},
                {"user_confirm": True},
                caller="agent-a",
                session=session,
            )
            return "revoke_delegation", True, obs

        def c5():
            obs = r.act(
                "SendInterAgentMessage",
                {"to_agent": "agent-b", "text": "hello again"},
                {"external_principal": "ext:internal-blue", "delegation_token": tok_a},
                caller="agent-a",
                session=session,
            )
            return "deny_revoked_delegation", False, obs

        def c6():
            obs = r.act(
                "SendMessage",
                {"recipient": "alice@example.com", "text": "notify", "channel": "email"},
                {"external_principal": "ext:partner-low", "delegation_token": tok_low},
                caller="agent-a",
                session=session,
            )
            return "deny_dual_principal_policy", False, obs

        def c7():
            wr = r.act(
                "MemoryWrite",
                {"namespace": "team", "key": "k1", "content": "confidential plan"},
                {"external_principal": "ext:internal-blue", "delegation_token": tok_mem},
                caller="agent-a",
                session=session,
            )
            if str(wr.get("status") or "") != "OK":
                return "allow_c5_memory_via_mediation", True, wr
            rd = r.act(
                "MemoryRead",
                {"namespace": "team", "key": "k1"},
                {"external_principal": "ext:internal-blue", "delegation_token": tok_mem},
                caller="agent-a",
                session=session,
            )
            return "allow_c5_memory_via_mediation", True, rd

        for fn in (c1, c2, c3, c4, c5, c6, c7):
            cases.append(_run_case(fn))

        summary = {
            "n_cases": len(cases),
            "n_pass": int(sum(1 for c in cases if c.ok)),
            "pass_rate": float(sum(1 for c in cases if c.ok)) / float(max(1, len(cases))),
            "latency_p50_ms": float(sorted([c.latency_ms for c in cases])[max(0, int(round(0.50 * (len(cases) - 1))))]) if cases else 0.0,
            "latency_p95_ms": float(sorted([c.latency_ms for c in cases])[max(0, int(round(0.95 * (len(cases) - 1))))]) if cases else 0.0,
        }
        out = {
            "status": "OK",
            "session": session,
            "env": {
                "UNIFIED_POLICY": os.getenv("UNIFIED_POLICY", ""),
                "DELEGATION_REQUIRED_FOR_EXTERNAL": os.getenv("DELEGATION_REQUIRED_FOR_EXTERNAL", ""),
            },
            "cases": [asdict(c) for c in cases],
            "summary": summary,
        }
        out_path.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        print(str(out_path))
    finally:
        for k, old in old_env.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


if __name__ == "__main__":
    main()
