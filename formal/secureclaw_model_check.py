from __future__ import annotations

import dataclasses
import json
from collections import deque
from dataclasses import dataclass
from typing import Iterable

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
    p0: CommitProof
    p1: CommitProof


@dataclass(frozen=True)
class CommitEvent:
    action_id: str
    req_rho: Rho


@dataclass(frozen=True)
class State:
    now: int
    issued: tuple[Issued, ...]
    accepted: frozenset[str]
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


def _accept_commit(
    *,
    rho: Rho,
    action_id: str,
    p0: CommitProof,
    p1: CommitProof,
    now: int,
    ttl_s: int,
    accepted: frozenset[str],
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
    if abs(int(now) - int(p0.ts)) > int(ttl_s):
        return False
    if abs(int(now) - int(p1.ts)) > int(ttl_s):
        return False
    if action_id in accepted:
        return False
    outs = _xor_outputs(p0.outputs_dict(), p1.outputs_dict())
    if int(outs.get("allow_pre", 0)) != 1:
        return False
    return True


def _commit_oracle(*, rho: Rho, action_id: str, now: int) -> Issued:
    # Idealized oracle: MAC and hash are treated as unforgeable and collision resistant,
    # by restricting adversary actions to reuse only oracle-issued proofs in this checker.
    req_sha = _req_sha(rho)
    p0 = CommitProof(
        v=1,
        kind="commit",
        server_id=0,
        kid="0",
        ts=now,
        action_id=action_id,
        program_id=PROGRAM_ID,
        request_sha256=req_sha,
        outputs=(("allow_pre", 1), ("need_confirm", 0), ("patch0", 0), ("patch1", 0)),
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
        outputs=(("allow_pre", 0), ("need_confirm", 0), ("patch0", 0), ("patch1", 0)),
        mac=f"opaque_mac_1_{action_id}",
    )
    return Issued(rho=rho, action_id=action_id, p0=p0, p1=p1)


def _bad_nbe(st: State) -> bool:
    authorized = {iss.action_id: _req_sha(iss.rho) for iss in st.issued}
    for ev in st.committed:
        want = authorized.get(ev.action_id)
        if want is None:
            return True
        if want != _req_sha(ev.req_rho):
            return True
    return False


def _state_key(st: State) -> str:
    # A stable key for visited set.
    obj = {
        "now": st.now,
        "issued": [
            {
                "action_id": it.action_id,
                "rho": dataclasses.asdict(it.rho),
            }
            for it in st.issued
        ],
        "accepted": sorted(st.accepted),
        "committed": [dataclasses.asdict(ev) for ev in st.committed],
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _rho_domain() -> list[Rho]:
    intents = ["SendMessage"]
    callers = ["caller0", "caller1"]
    sessions = ["sess0", "sess1"]
    recipients = ["alice@example.com", "bob@example.com"]
    texts = ["hello", "status update"]
    out: list[Rho] = []
    for intent in intents:
        for caller in callers:
            for session in sessions:
                for recipient in recipients:
                    for text in texts:
                        inputs = (
                            ("channel", "email"),
                            ("recipient", recipient),
                            ("domain", ""),
                            ("text", text),
                        )
                        out.append(Rho(intent_id=intent, caller=caller, session=session, inputs=inputs))
    return out


def _next_states(st: State, *, ttl_s: int, max_issues: int, max_now: int) -> Iterable[tuple[str, State]]:
    # Issue transition.
    if len(st.issued) < max_issues:
        next_action_id = f"a{len(st.issued)}"
        for rho in _rho_domain():
            iss = _commit_oracle(rho=rho, action_id=next_action_id, now=st.now)
            yield (f"issue({rho.intent_id},{rho.caller},{rho.session},{rho.inputs_dict()})", State(now=st.now, issued=st.issued + (iss,), accepted=st.accepted, committed=st.committed))

    # Time tick.
    if st.now < max_now:
        yield ("tick", State(now=st.now + 1, issued=st.issued, accepted=st.accepted, committed=st.committed))

    # Commit attempts: adversary chooses any request rho and any pair of proofs it has seen.
    if st.issued:
        for rho_req in _rho_domain():
            for iss0 in st.issued:
                for iss1 in st.issued:
                    # Adversary can mix shares across issuances.
                    p0 = iss0.p0
                    p1 = iss1.p1
                    action_id = iss0.action_id
                    if _accept_commit(
                        rho=rho_req,
                        action_id=action_id,
                        p0=p0,
                        p1=p1,
                        now=st.now,
                        ttl_s=ttl_s,
                        accepted=st.accepted,
                    ):
                        ev = CommitEvent(action_id=action_id, req_rho=rho_req)
                        yield (f"commit({action_id},{rho_req.caller},{rho_req.session})", State(now=st.now, issued=st.issued, accepted=st.accepted | frozenset([action_id]), committed=st.committed + (ev,)))
                    else:
                        # Include failing commits as no-op transitions only if needed for coverage.
                        continue


def check_model(*, ttl_s: int = 1, max_issues: int = 2, max_depth: int = 6) -> tuple[bool, dict]:
    init = State(now=0, issued=tuple(), accepted=frozenset(), committed=tuple())
    q: deque[tuple[State, list[str]]] = deque()
    q.append((init, []))
    seen: set[str] = set()
    max_now = max_depth  # conservative bound
    while q:
        st, trace = q.popleft()
        key = _state_key(st)
        if key in seen:
            continue
        seen.add(key)
        if _bad_nbe(st):
            return False, {"ok": False, "counterexample": trace, "state": json.loads(key)}
        if len(trace) >= max_depth:
            continue
        for act, st2 in _next_states(st, ttl_s=ttl_s, max_issues=max_issues, max_now=max_now):
            q.append((st2, trace + [act]))
    return True, {"ok": True, "states": len(seen), "ttl_s": ttl_s, "max_issues": max_issues, "max_depth": max_depth}


def main() -> None:
    ok, report = check_model()
    if not ok:
        raise SystemExit(json.dumps(report, ensure_ascii=True, indent=2))
    print(json.dumps(report, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()

