from __future__ import annotations

import dataclasses
import json
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from common.canonical import request_sha256_v1


PROGRAM_ID = "policy_unified_v1"


@dataclass(frozen=True)
class Rho:
    intent_id: str
    caller: str
    session: str
    inputs: tuple[tuple[str, str], ...]

    def inputs_dict(self) -> dict[str, str]:
        return {k: v for k, v in self.inputs}


@dataclass(frozen=True)
class CommitProof:
    v: int
    kind: str
    server_id: int
    kid: str
    ts: int
    action_id: str
    program_id: str
    request_sha256: str
    outputs: tuple[tuple[str, int], ...]
    mac: str

    def outputs_dict(self) -> dict[str, int]:
        return {k: int(v) & 1 for k, v in self.outputs}


@dataclass(frozen=True)
class Issued:
    rho: Rho
    action_id: str
    ts_issued: int
    p0: CommitProof
    p1: CommitProof


@dataclass(frozen=True)
class CommitEvent:
    action_id: str
    req_rho: Rho
    ts_commit: int
    user_confirm: bool


@dataclass(frozen=True)
class StateNBE:
    now: int
    issued: tuple[Issued, ...]
    accepted: tuple[tuple[str, int], ...]  # (action_id, seen_at)
    committed: tuple[CommitEvent, ...]


def _req_sha(rho: Rho) -> str:
    return request_sha256_v1(
        intent_id=rho.intent_id,
        caller=rho.caller,
        session=rho.session,
        inputs=rho.inputs_dict(),
    )


def _xor_outputs(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    out: dict[str, int] = {}
    keys = set(a.keys()) | set(b.keys())
    for k in keys:
        out[str(k)] = (int(a.get(k, 0)) ^ int(b.get(k, 0))) & 1
    return out


def _policy_outputs_for_rho(rho: Rho) -> dict[str, int]:
    """
    An abstract, deterministic policy function used for model checking.

    - allow_pre is always 1 for this domain.
    - need_confirm is 1 when the message text contains "status".
    """
    txt = str(rho.inputs_dict().get("text") or "").lower()
    need_confirm = 1 if ("status" in txt) else 0
    return {
        "allow_pre": 1,
        "need_confirm": need_confirm,
        "patch0": need_confirm,
        "patch1": 0,
    }


def _commit_oracle(*, rho: Rho, action_id: str, now: int) -> Issued:
    req_sha = _req_sha(rho)
    outs = _policy_outputs_for_rho(rho)

    # Deterministic XOR share split: p0 provides fixed shares; p1 is derived.
    p0_out = {"allow_pre": 1, "need_confirm": 0, "patch0": 0, "patch1": 0}
    p1_out = {k: (int(p0_out.get(k, 0)) ^ int(v)) & 1 for k, v in outs.items()}

    p0 = CommitProof(
        v=1,
        kind="commit",
        server_id=0,
        kid="0",
        ts=now,
        action_id=action_id,
        program_id=PROGRAM_ID,
        request_sha256=req_sha,
        outputs=tuple(sorted((k, int(v) & 1) for k, v in p0_out.items())),
        mac=f"opaque_mac_0_{action_id}",
    )
    p1 = CommitProof(
        v=1,
        kind="commit",
        server_id=1,
        kid="0",
        ts=now,
        action_id=action_id,
        program_id=PROGRAM_ID,
        request_sha256=req_sha,
        outputs=tuple(sorted((k, int(v) & 1) for k, v in p1_out.items())),
        mac=f"opaque_mac_1_{action_id}",
    )
    return Issued(rho=rho, action_id=action_id, ts_issued=now, p0=p0, p1=p1)


def _accepted_map(accepted: tuple[tuple[str, int], ...]) -> dict[str, int]:
    return {str(a): int(t) for a, t in accepted}


def _prune_accepted(accepted: tuple[tuple[str, int], ...], *, now: int, replay_ttl_s: int) -> tuple[tuple[str, int], ...]:
    if replay_ttl_s <= 0:
        return tuple()
    out: list[tuple[str, int]] = []
    for aid, seen_at in accepted:
        if (int(now) - int(seen_at)) <= int(replay_ttl_s):
            out.append((str(aid), int(seen_at)))
    out.sort()
    return tuple(out)


def _accept_commit(
    *,
    rho: Rho,
    action_id: str,
    p0: CommitProof,
    p1: CommitProof,
    user_confirm: bool,
    now: int,
    mac_ttl_s: int,
    replay_ttl_s: int,
    accepted: tuple[tuple[str, int], ...],
) -> bool:
    if p0.v != 1 or p1.v != 1:
        return False
    if p0.kind != "commit" or p1.kind != "commit":
        return False
    if p0.server_id != 0 or p1.server_id != 1:
        return False
    if p0.action_id != action_id or p1.action_id != action_id:
        return False
    if p0.program_id != PROGRAM_ID or p1.program_id != PROGRAM_ID:
        return False
    if p0.request_sha256 != p1.request_sha256:
        return False
    if p0.request_sha256 != _req_sha(rho):
        return False
    if abs(int(now) - int(p0.ts)) > int(mac_ttl_s):
        return False
    if abs(int(now) - int(p1.ts)) > int(mac_ttl_s):
        return False

    # Replay guard within replay_ttl_s window.
    amap = _accepted_map(_prune_accepted(accepted, now=now, replay_ttl_s=replay_ttl_s))
    if action_id in amap:
        return False

    outs = _xor_outputs(p0.outputs_dict(), p1.outputs_dict())
    if int(outs.get("allow_pre", 0)) != 1:
        return False
    if int(outs.get("need_confirm", 0)) == 1 and not bool(user_confirm):
        return False
    return True


def _bad_nbe(st: StateNBE, *, replay_ttl_s: int) -> bool:
    authorized = {iss.action_id: _req_sha(iss.rho) for iss in st.issued}

    # No-auth and binding break.
    for ev in st.committed:
        want = authorized.get(ev.action_id)
        if want is None:
            return True
        if want != _req_sha(ev.req_rho):
            return True

    # Replay within the replay window.
    by: dict[str, list[int]] = {}
    for ev in st.committed:
        by.setdefault(str(ev.action_id), []).append(int(ev.ts_commit))
    for aid, times in by.items():
        _ = aid
        ts_sorted = sorted(int(x) for x in times)
        for i in range(1, len(ts_sorted)):
            if int(ts_sorted[i] - ts_sorted[i - 1]) <= int(replay_ttl_s):
                return True
    return False


def _state_key_nbe(st: StateNBE) -> str:
    obj = {
        "now": st.now,
        "issued": [{"action_id": it.action_id, "rho": dataclasses.asdict(it.rho), "ts_issued": it.ts_issued} for it in st.issued],
        "accepted": sorted([(a, int(t)) for a, t in st.accepted]),
        "committed": [dataclasses.asdict(ev) for ev in st.committed],
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _rho_domain() -> list[Rho]:
    # Keep a small domain, but include multiple caller and session values for binding checks.
    callers = ["caller0", "caller1"]
    sessions = ["sess0", "sess1"]
    texts = ["hello", "status update"]
    out: list[Rho] = []
    for caller in callers:
        for session in sessions:
            for text in texts:
                inputs = (
                    ("channel", "email"),
                    ("recipient", "alice@example.com"),
                    ("domain", ""),
                    ("text", text),
                )
                out.append(Rho(intent_id="SendMessage", caller=caller, session=session, inputs=inputs))
    return out


def _next_states_nbe(
    st: StateNBE,
    *,
    mac_ttl_s: int,
    replay_ttl_s: int,
    max_issues: int,
    max_now: int,
) -> Iterable[tuple[str, StateNBE]]:
    # Issue transition.
    if len(st.issued) < max_issues:
        next_action_id = f"a{len(st.issued)}"
        for rho in _rho_domain():
            iss = _commit_oracle(rho=rho, action_id=next_action_id, now=st.now)
            yield (
                f"issue({rho.caller},{rho.session},{rho.inputs_dict().get('text','')})",
                StateNBE(now=st.now, issued=st.issued + (iss,), accepted=st.accepted, committed=st.committed),
            )

    # Time tick.
    if st.now < max_now:
        acc2 = _prune_accepted(st.accepted, now=st.now + 1, replay_ttl_s=replay_ttl_s)
        yield ("tick", StateNBE(now=st.now + 1, issued=st.issued, accepted=acc2, committed=st.committed))

    # Commit attempts: adversary chooses any request rho and whether to confirm.
    if st.issued:
        for rho_req in _rho_domain():
            for iss in st.issued:
                for user_confirm in (False, True):
                    if _accept_commit(
                        rho=rho_req,
                        action_id=iss.action_id,
                        p0=iss.p0,
                        p1=iss.p1,
                        user_confirm=user_confirm,
                        now=st.now,
                        mac_ttl_s=mac_ttl_s,
                        replay_ttl_s=replay_ttl_s,
                        accepted=st.accepted,
                    ):
                        ev = CommitEvent(action_id=iss.action_id, req_rho=rho_req, ts_commit=st.now, user_confirm=bool(user_confirm))
                        acc2 = tuple(sorted(list(_prune_accepted(st.accepted, now=st.now, replay_ttl_s=replay_ttl_s)) + [(iss.action_id, st.now)]))
                        yield (f"commit({iss.action_id},confirm={int(user_confirm)})", StateNBE(now=st.now, issued=st.issued, accepted=acc2, committed=st.committed + (ev,)))


def check_model_nbe(*, mac_ttl_s: int = 1, replay_ttl_s: int = 2, max_issues: int = 2, max_depth: int = 7) -> tuple[bool, dict[str, Any]]:
    init = StateNBE(now=0, issued=tuple(), accepted=tuple(), committed=tuple())
    q: deque[tuple[StateNBE, list[str]]] = deque()
    q.append((init, []))
    seen: set[str] = set()
    max_now = max_depth

    while q:
        st, trace = q.popleft()
        key = _state_key_nbe(st)
        if key in seen:
            continue
        seen.add(key)
        if _bad_nbe(st, replay_ttl_s=replay_ttl_s):
            return False, {"ok": False, "property": "NBE", "counterexample": trace, "state": json.loads(key)}
        if len(trace) >= max_depth:
            continue
        for act, st2 in _next_states_nbe(st, mac_ttl_s=mac_ttl_s, replay_ttl_s=replay_ttl_s, max_issues=max_issues, max_now=max_now):
            q.append((st2, trace + [act]))

    return True, {"ok": True, "property": "NBE", "states": len(seen), "mac_ttl_s": mac_ttl_s, "replay_ttl_s": replay_ttl_s, "max_issues": max_issues, "max_depth": max_depth}


# --- Secret myopia: bounded interface-level model ---


@dataclass(frozen=True)
class Handle:
    handle_id: str
    session: str
    caller: str


@dataclass(frozen=True)
class StateSM:
    minted: tuple[Handle, ...]
    observations: tuple[str, ...]  # what the untrusted runtime learns from API responses


def _bad_sm(st: StateSM, *, secret_token: str) -> bool:
    # The secret token must never be present in the untrusted runtime observation stream.
    for obs in st.observations:
        if secret_token in str(obs):
            return True
    return False


def _state_key_sm(st: StateSM) -> str:
    obj = {
        "minted": [dataclasses.asdict(h) for h in st.minted],
        "observations": list(st.observations),
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _next_states_sm(st: StateSM, *, sessions: list[str], callers: list[str], max_mint: int) -> Iterable[tuple[str, StateSM]]:
    # Mint a new high-sensitivity handle (the runtime learns only the opaque handle id).
    if len(st.minted) < max_mint:
        hid = f"h{len(st.minted)}"
        for sess in sessions:
            for caller in callers:
                h = Handle(handle_id=hid, session=sess, caller=caller)
                yield (f"mint({hid},{sess},{caller})", StateSM(minted=st.minted + (h,), observations=st.observations + (hid,)))

    # Describe and use operations: succeed only on correct binding.
    for h in st.minted:
        for sess in sessions:
            for caller in callers:
                ok = (sess == h.session) and (caller == h.caller)
                yield (
                    f"describe({h.handle_id},{sess},{caller})",
                    StateSM(minted=st.minted, observations=st.observations + (("OK" if ok else "DENY"),)),
                )
                # UseCredential returns a signature string, but not the secret token.
                sig = "hmac_sha256(...)=deadbeef..." if ok else "DENY"
                yield (
                    f"use({h.handle_id},{sess},{caller})",
                    StateSM(minted=st.minted, observations=st.observations + (sig,)),
                )


def check_model_sm(*, max_depth: int = 6, max_mint: int = 1) -> tuple[bool, dict[str, Any]]:
    secret_token = "SECRET_TOKEN"
    sessions = ["sess0", "sess1"]
    callers = ["caller0", "caller1"]
    init = StateSM(minted=tuple(), observations=tuple())

    q: deque[tuple[StateSM, list[str]]] = deque()
    q.append((init, []))
    seen: set[str] = set()

    while q:
        st, trace = q.popleft()
        key = _state_key_sm(st)
        if key in seen:
            continue
        seen.add(key)
        if _bad_sm(st, secret_token=secret_token):
            return False, {"ok": False, "property": "SM", "counterexample": trace, "state": json.loads(key)}
        if len(trace) >= max_depth:
            continue
        for act, st2 in _next_states_sm(st, sessions=sessions, callers=callers, max_mint=max_mint):
            q.append((st2, trace + [act]))

    return True, {"ok": True, "property": "SM", "states": len(seen), "max_depth": max_depth, "max_mint": max_mint}


# --- Skill-confined safety: spec consistency checks ---


def check_model_scs_spec(*, contract_path: Path | None = None) -> tuple[bool, dict[str, Any]]:
    """
    A static consistency check for the capsule mediation contract instance.

    This does not attempt to prove OS sandbox correctness. It checks that the contract instance
    is internally consistent and aligned with the artifact transport configuration.
    """
    repo_root = Path(__file__).resolve().parents[1]
    p = contract_path or (repo_root / "spec" / "secureclaw_capsule_contract_v1.json")
    obj = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        return False, {"ok": False, "property": "SCS", "reason": "bad_contract_json"}
    tr = obj.get("transport") if isinstance(obj.get("transport"), dict) else {}
    mode = str(tr.get("mode") or "")
    uds = tr.get("allowed_uds_paths") if isinstance(tr.get("allowed_uds_paths"), list) else []
    uds2 = {str(x) for x in uds}
    want_sock = {"/tmp/mirage_ogpp_gateway.sock", "/private/tmp/mirage_ogpp_gateway.sock"}
    ok = (mode == "uds") and bool(uds2 & want_sock)
    return ok, {
        "ok": bool(ok),
        "property": "SCS",
        "contract_path": str(p),
        "transport_mode": mode,
        "allowed_uds_paths": sorted(list(uds2))[:10],
        "expects_one_of": sorted(list(want_sock)),
    }


def check_all_models() -> tuple[bool, dict[str, Any]]:
    ok1, r1 = check_model_nbe()
    ok2, r2 = check_model_sm()
    ok3, r3 = check_model_scs_spec()
    ok = bool(ok1 and ok2 and ok3)
    return ok, {"ok": ok, "results": [r1, r2, r3]}


def main() -> None:
    ok, report = check_all_models()
    if not ok:
        raise SystemExit(json.dumps(report, ensure_ascii=True, indent=2))
    print(json.dumps(report, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()

