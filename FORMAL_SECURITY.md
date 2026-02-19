# SecureClaw Formal Security Model

This document defines a single, reviewable security statement and the full proof skeleton for four properties:

1. Non-Bypassable Effects (NBE)
2. Secret Myopia (SM)
3. Single-Auditor Privacy (SAP)
4. Skill-Confined Safety (SCS)

It is artifact-faithful and mapped to executable checks in this repository.

## 1. Single Reviewable Proposition

Primary claim:

For the deployed SecureClaw interfaces, no external side effect can be committed without dual valid commit proofs bound to the exact request tuple, while any single policy server view is simulatable from an explicit leakage function.

This claim has two orthogonal parts:

1. Integrity part. Non-bypassable effect commit line at the executor.
2. Privacy part. Leakage-bounded policy outsourcing against one policy server.

SM and SCS are supporting system properties that guarantee no plaintext bypass around this line under stated assumptions.

## 2. System Model

### 2.1 Parties

1. `A`: PPT adversary controlling runtime prompts, tool invocations, and skill code.
2. `G`: trusted gateway.
3. `P0`, `P1`: policy servers.
4. `X`: trusted executor and only side-effect sink.
5. `U`: user confirmation source.
6. `C`: optional capsule boundary for skill confinement.

### 2.2 Interfaces

1. Runtime-to-gateway entrypoint: `act(intent_id, inputs, constraints, caller)`.
2. Policy path: PIR endpoints and MPC endpoints.
3. Effect path: executor `/exec/*`.
4. Capsule path: mediated runtime transport to gateway.

### 2.3 Trust and Non-Goals

1. `G` and `X` are in TCB.
2. At least one policy server is non-colluding for SAP.
3. No claim against kernel-level side channels.
4. No claim if `EXECUTOR_INSECURE_ALLOW=1`.
5. No claim if both policy servers collude.

## 3. Unified Notation

### 3.1 Request and Context Tuples

Bound request tuple:

`rho = (intent_id, caller, session, inputs_eff)`

Commit context tuple:

`ctx = (action_id, program_id, request_sha256)`

Request binding hash:

`ReqHash(rho) = SHA256(CanonJSON({"intent_id", "caller", "session", "inputs"}))`

Artifact implementation:

1. `common/canonical.py:request_sha256_v1`
2. `executor_server/server.py:_validate_commit_proof_common`

### 3.2 Commit Proof Share

For server `s in {0,1}`, a proof share is:

`pi_s = (meta_s, mac_s)`

where:

1. `meta_s` contains `v, kind, server_id, kid, ts, action_id, program_id, request_sha256, outputs, commit_tag_share_b64`.
2. `mac_s = HMAC(K_s, Canon(meta_s))`.

### 3.3 Acceptance Predicate

Executor accepts iff all hold:

1. Structural schema valid.
2. `policy0` and `policy1` server identities are distinct and valid.
3. MAC verification succeeds under keyring `kid`.
4. Freshness `abs(now - ts) <= POLICY_MAC_TTL_S`.
5. Shared `(action_id, program_id, request_sha256)` match.
6. Recomputed `ReqHash(rho(req))` equals proof hash.
7. Replay guard rejects duplicates in replay window.
8. Reconstructed policy bits satisfy `allow_pre=1`.
9. `need_confirm=1` implies explicit confirmation.
10. Sanitization patch constraints hold.

Normative files:

1. `spec/secureclaw_executor_accept_v1.schema.json`
2. `spec/secureclaw_accept_predicate_v1.json`
3. `scripts/verify_accept_predicate.py`

## 4. Unified Security Experiment Template

Define a generic game family:

`Exp^Pi_{A}(lambda; Oracles, Win)`

where:

1. Challenger initializes keys, stores, and trusted services.
2. Adversary gets oracle access defined by property `Pi`.
3. Adversary outputs a terminal action.
4. Win predicate `Win` decides success.

Every property below instantiates this template and uses explicit bad events.

## 5. NBE Game and Theorem

### 5.1 Game `G_NBE`

Oracles:

1. `O_preview_commit(rho)` returns valid dual shares and records authorized binding for `ctx(rho)`.
2. Optional benign service oracles needed for syntax consistency.

State:

1. `S_auth`: set of authorized tuples `(ctx, rho)`.
2. `S_accept`: accepted action identifiers for replay window.

Adversary outputs `(req_star, pi0_star, pi1_star)`.

Win condition `Bad_NBE` is true if executor accepts and one of the following holds:

1. No-auth event. `ctx(req_star)` not in `S_auth`.
2. Binding-break event. `ctx(req_star)` in `S_auth` but `rho(req_star)` differs from all authorized tuples under that context.
3. Replay event. `action_id` already accepted in replay window.

### 5.2 Lemma `L_bind`

If acceptance succeeds for a request whose bound tuple differs from the tuple used to create the accepted proof context, then either:

1. SHA256 collision is found on canonicalized messages, or
2. Canonicalization consistency is violated.

Reason:

Accepted proof hash equals recomputed `ReqHash(rho(req))`.
Different tuples with equal hash imply collision or serialization inconsistency.

### 5.3 Theorem `T_NBE`

Assume:

1. HMAC is EUF-CMA secure.
2. `ReqHash` is collision resistant and canonicalization is consistent.
3. Executor implements acceptance predicate exactly.
4. Replay store semantics hold in configured replay window.

Then for any PPT adversary `A`:

`Pr[Bad_NBE] <= Adv_euf_cma(B0) + Adv_euf_cma(B1) + Adv_coll(C) + eps_replay + negl(lambda)`

where:

1. `B0`, `B1` are reductions against each policy-server MAC key.
2. `C` is a collision finder reduction.
3. `eps_replay` captures non-cryptographic replay-store failures.

Proof sketch by exhaustive cases:

1. No-auth. Acceptance with unseen context implies at least one fresh MAC forgery.
2. Binding-break. Acceptance on changed `rho` with same proof hash implies `L_bind` violation.
3. Replay. Any second acceptance in replay window is replay-store failure.

Corollary:

Without dual valid proofs, side effects cannot be committed except with negligible advantage plus replay-store failure probability.

## 6. SM Game and Theorem

### 6.1 Game `G_SM`

Sensitive value space `S`.

Oracles:

1. `O_act` for runtime calls into gateway.
2. Declassification oracle subject to policy and confirmation.

Adversary controls all runtime interactions.
Challenger stores one of two equal-length secrets behind a handle.

Win event `Bad_SM`:

Adversary distinguishes which secret is stored with non-negligible advantage without an allowed declassification event that includes this secret in leakage.

### 6.2 Theorem `T_SM`

Assume:

1. Gateway only returns opaque handles for high-sensitivity values by default.
2. Handle identifiers are unguessable and independent of plaintext.
3. Declassification path is explicit, logged, and policy-controlled.

Then runtime view is simulatable from:

`L_SM = (handle ids, labels, ttl, reason codes, explicitly declassified outputs)`

and `Pr[Bad_SM]` is negligible under handle-guessing assumptions.

## 7. SAP Game and Theorem

### 7.1 Game `G_SAP`

Adversary chooses two action traces `W0, W1` such that:

`L_policy(params, W0) = L_policy(params, W1)`

Challenger samples bit `b`, executes `Wb`, and reveals transcript view of one policy server `P_sigma`.

Adversary outputs guess `b_prime`.

Win event:

`Bad_SAP = [b_prime = b]` with non-negligible bias over one half.

### 7.2 Theorem `T_SAP`

Assume:

1. Two-server PIR security against one server for DPF/FSS shares.
2. Honest-but-curious MPC privacy for fixed policy circuit.
3. Fixed-shape routing and shaping are configured as assumed by `L_policy`.
4. At least one policy server is non-colluding.

Then for each `sigma` there exists PPT simulator `Sim_sigma` such that:

`|Pr[D(View(P_sigma))=1] - Pr[D(Sim_sigma(L_policy))=1]| <= negl(lambda)`

for all PPT distinguishers `D`.

Hybrid structure:

1. Replace PIR messages by PIR simulator outputs.
2. Replace MPC transcripts by MPC simulator outputs.
3. Remaining fields are deterministic from leakage terms and public parameters.

## 8. SCS Game and Theorem

### 8.1 Game `G_SCS`

Adversary controls skill code inside capsule boundary and attempts forbidden direct actions:

1. Host secret reads.
2. Arbitrary process execution.
3. Direct internet exfiltration.
4. Direct loopback exfiltration when disallowed.

Win event `Bad_SCS`:

Forbidden direct action succeeds while contract `MC` is declared active.

### 8.2 Theorem `T_SCS`

Assume:

1. Capsule mediation contract `MC` holds.
2. All effectful operations require executor path.
3. NBE and SM hold for gateway-executor path.

Then `Pr[Bad_SCS]` is bounded by capsule-contract violation probability plus negligible cryptographic failure from NBE and SM assumptions.

## 9. Composition Theorem

Define combined bad event:

`Bad_SC = Bad_NBE or Bad_SM or Bad_SAP or Bad_SCS`

### 9.1 Dependency Partition

Property dependency table:

1. `NBE` depends on MAC unforgeability, hash binding consistency, replay store semantics, executor accept implementation.
2. `SM` depends on handle discipline and explicit declassification discipline in gateway.
3. `SAP` depends on PIR one-server privacy, MPC one-party privacy, fixed-shape leakage contract, non-collusion.
4. `SCS` depends on enforceable capsule contract and non-bypass requirement for external effects.

### 9.2 Composition Bound

`Pr[Bad_SC] <= Pr[Bad_NBE] + Pr[Bad_SM] + Pr[Bad_SAP] + Pr[Bad_SCS]`

with each term bounded by its theorem assumptions.

Proof is direct union bound over disjoint event definitions plus per-property theorem bounds.

### 9.3 Proof Structure Diagram

```text
                 +-----------------------+
                 |  Cryptographic Layer  |
                 |  MAC, Hash, PIR, MPC  |
                 +-----------+-----------+
                             |
          +------------------+------------------+
          |                                     |
  +-------v--------+                    +-------v--------+
  | Executor Line  |                    | Policy Privacy |
  | Accept(ctx,rho)|                    | Sim(L_policy)  |
  +-------+--------+                    +-------+--------+
          |                                     |
          +---------------+---------------------+
                          |
                 +--------v--------+
                 | Gateway Handles |
                 |  + Declass Path |
                 +--------+--------+
                          |
                 +--------v--------+
                 | Capsule MC      |
                 | Skill Boundary  |
                 +--------+--------+
                          |
                 +--------v--------+
                 |  Combined Claim |
                 | NBE + SM + SAP  |
                 |      + SCS      |
                 +-----------------+
```

## 10. MC as Verifiable System Assumption

Contract instance:

1. `spec/secureclaw_capsule_contract_v1.json`
2. `spec/secureclaw_capsule_contract_v1.schema.json`

Contract verifier:

1. `capsule/verify_contract.py`
2. `capsule/run_smoke.sh`
3. `capsule/smoke.py`

Semantic interpretation:

1. If contract verifier returns `OK`, SCS assumption is satisfied for tested environment profile.
2. If verifier fails, SCS claim is disabled and deployment must fail closed or downgrade to no-capsule claims.

## 11. Machine-Checked Consistency in Repository

The repository provides bounded mechanization and executable checks:

1. `formal/secureclaw_model_check.py` checks finite-state consistency for NBE, SM, SCS contract shape.
2. `scripts/security_game_nbe_check.py` executes end-to-end NBE adversarial probes.
3. `tests/test_security_games.py` validates replay, hash binding, dual-proof necessity.
4. `scripts/verify_accept_predicate.py` validates semantic accept constraints.
5. `scripts/validate_specs.py` validates schema and spec files.

Run:

```bash
PYTHONPATH=. python formal/secureclaw_model_check.py
PYTHONPATH=. python scripts/security_game_nbe_check.py
python -m unittest discover -s tests -p 'test_security_games.py'
python scripts/validate_specs.py
```

## 12. Explicit Limits

1. Claims are conditional on trusted `G` and `X`.
2. SAP does not hold under full collusion of both policy servers.
3. Capsule claims are conditional and environment-specific.
4. Kernel microarchitectural channels are not covered.
5. Unkeyed `request_sha256` can permit offline guessing on low-entropy fields.

