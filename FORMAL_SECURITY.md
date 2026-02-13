# Formal Security Claims and Games (NBE / SM / SAP / SCS)

This document defines the core claims as security games and links each claim to
concrete implementation checks in this repository.

Status:

- Scope: current MIRAGE-OG++ artifact implementation.
- Model: computational security for MAC-based authenticity; bounded-time adversaries.
- Verification: code-linked checks in `scripts/security_game_nbe_check.py` and
  `tests/test_security_games.py`.

---

## 1. Entities, Syntax, and Predicates

Entities:

- `A`: adversary controlling prompts/skills/runtime inputs.
- `G`: trusted gateway.
- `P0, P1`: two policy servers (honest-but-curious, non-colluding for SAP).
- `E`: executor (trusted effect gate).
- `C`: capsule (optional confinement layer for SCS).

Core tuple:

- `ctx = (action_id, program_id, request_sha256)`.

Commit proof share from server `i ∈ {0,1}`:

- `pi_i = (meta_i, mac_i)`.
- `meta_i` includes `v, kind=commit, server_id, kid, ts, action_id, program_id, request_sha256, outputs, commit_tag_share_b64`.
- `mac_i = HMAC(K_i, Canonical(meta_i))`.

Acceptance predicate at executor:

- `Accept_E(req, pi_0, pi_1) = 1` iff:
1. both proofs parse and verify MAC under active keys;
2. both proofs are fresh (`|now-ts| <= TTL`);
3. both proofs bind the same `ctx`;
4. output shares reconstruct an allow path (`allow_pre=1`) and satisfy confirm constraints.

Implemented in:

- `executor_server/server.py:_validate_commit_proof_common`
- `executor_server/server.py:_verify_commit_evidence`

---

## 2. Security Games

### 2.1 Game `G_NBE` (Non-Bypassable Effects)

Goal: adversary causes an external side effect without valid dual authorization.

Game:

1. Challenger samples independent keys `K0, K1`.
2. Adversary can adaptively query policy oracles for valid commit proofs on chosen contexts.
3. Adversary outputs `(req*, pi_0*, pi_1*)` for an effect endpoint.
4. Adversary wins iff `Accept_E(req*, pi_0*, pi_1*) = 1` and at least one of:
   - one proof is missing/invalid/unfresh;
   - `ctx` in proof(s) does not match the executed request context;
   - proof pair was not obtained from both servers for that context.

Claim (NBE):

- For any PPT adversary `A`,
  `Pr[G_NBE^A = 1] <= Adv_mac_unforgeable(A') + Adv_hash_collision(A'') + negl(lambda)`.

Interpretation:

- Successful bypass implies either MAC forgery (breaking HMAC authenticity) or
  hash-binding break (finding context mismatch accepted as equal).

### 2.2 Game `G_SM` (Secret Myopia)

Goal: adversary obtains sensitive plaintext through untrusted runtime path.

Game:

1. Adversary requests sensitive read intents through `act`.
2. Challenger returns handles with `(session, caller, ttl, sensitivity)` bindings.
3. Adversary tries to externalize sensitive value without declassification constraints.
4. Adversary wins iff sensitive plaintext is released or externally sent without required confirm/authorization.

Claim (SM):

- Along gateway/executor path, high-sensitivity material is non-extractable by default;
  only handle references are emitted unless explicit declassification policy passes.

### 2.3 Game `G_SAP` (Single-Auditor Privacy)

Goal: one policy server infers queried identity from its own transcript.

Game:

1. Challenger picks hidden query identity `q_b` from candidate set.
2. Adversary controls one server transcript view only (metadata and that server's shares).
3. Adversary outputs guess `b'`.
4. Advantage is `|Pr[b'=b]-1/2|`.

Claim (SAP, implemented target):

- Under two-server non-collusion and DPF/PIR correctness, single-server transcript
  does not reveal plaintext queried identity beyond configured leakage shape.
- Artifact reports leakage empirically (`outsourcing_comparison`, `leakage_eval`).

### 2.4 Game `G_SCS` (Skill-Confined Safety)

Goal: malicious skill bypasses `act` path via direct file/process/network actions.

Game:

1. Adversary controls skill content/runtime instructions.
2. Capsule mediation contract enforces configured deny rules.
3. Adversary tries direct local execution/exfil outside gateway.
4. Adversary wins iff direct bypass succeeds.

Claim (SCS, conditional):

- If capsule mediation assumptions hold, direct bypass probability is negligible
  under configured policy; side effects are forced through gateway/executor chain.

---

## 3. Theorem (Code-Linked)

### Theorem T1: Dual-Proof Necessity for Effect Commit

Statement:

- For `/exec/send_message`, `/exec/fetch`, `/exec/webhook`, `/exec/skill_install`,
  acceptance with commit path implies existence of two MAC-valid commit proofs
  (from `P0` and `P1`) bound to identical `ctx`.

Proof sketch:

1. Executor calls `_verify_commit_evidence`, which independently validates each proof
   via `_validate_commit_proof_common`.
2. Each common validator checks:
   - `kind == commit`, version, server id, key id, TTL;
   - exact equality of `action_id`, `program_id`, `request_sha256`;
   - `HMAC(K_i, Canonical(meta_i))` verification.
3. If either proof fails, function returns failure code and endpoint returns `DENY`.
4. Therefore `Accept_E = 1` implies both proofs pass all checks.
5. Any successful bypass without dual valid proofs requires either:
   - forging a valid MAC under unknown key (`Adv_mac_unforgeable`);
   - producing mismatched request context that collides under binding hash (`Adv_hash_collision`).

Code references:

- `executor_server/server.py:137`
- `executor_server/server.py:171`
- `executor_server/server.py:386`
- `executor_server/server.py:473`
- `executor_server/server.py:517`
- `executor_server/server.py:551`

Machine-checked artifact:

- `scripts/security_game_nbe_check.py`
- `tests/test_security_games.py`

---

## 4. Assumptions and Limits

Assumptions:

1. At least one policy server does not collude with the other (SAP).
2. Executor keys remain secret and uncompromised.
3. Gateway and executor are not simultaneously compromised.
4. Capsule contract is correctly enforced when claiming SCS.

Non-goals:

1. Full malicious security against two colluding policy servers (out of scope for current PIR setting).
2. Proof of indistinguishability under arbitrary side channels (timing/network metadata shaping is partial).

---

## 5. How to Reproduce the Formal Checks

Run:

```bash
PYTHONPATH=. python scripts/security_game_nbe_check.py
python -m unittest discover -s tests -p 'test_security_games.py'
```

Expected:

- Valid dual-proof commit path accepts.
- Missing one proof, tampered MAC, mismatched hash/context, and replay-unsafe variants are rejected.

