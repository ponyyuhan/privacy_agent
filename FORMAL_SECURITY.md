# SecureClaw Formal Security Model

This document defines one paper-level thesis and the formal proof skeleton needed to support it.
For presentation, we package the system into three core claims plus one optional privacy mode:

1. C1 (core): Non-Bypassable Effects (NBE)
2. C2 (core): Control-plane privacy via Single-Auditor Privacy (SAP)
3. C3 (core): Confidentiality + multi-principal binding correctness (SM/PEI/SCS/DAS bundle)
4. Optional mode: SAP can be disabled in single-server deployments that accept query exposure

Internally, the proofs still track six properties (NBE, SM, PEI, SCS, DAS, SAP) to keep assumptions explicit.
The model is artifact-faithful and mapped to executable checks in this repository.

## 1. Single Reviewable Proposition

Primary claim:

For the deployed SecureClaw interfaces, no external side effect can be committed without dual valid commit proofs bound to the exact request tuple, and runtime-side plaintext release or cross-principal replay cannot bypass this line under explicit assumptions.

This claim has three orthogonal parts:

1. Integrity part. Non-bypassable effect commit line at the executor.
2. Confidentiality part. Secret myopia plus explicit declassification and executor-enforced sanitization.
3. Multi-principal part. Delegation/federation context bound to request binding digest to prevent cross-context replay.

SAP is an optional deployment mode for leakage-bounded policy outsourcing against one policy server and does not change the integrity line.

### 1.1 Paper-facing contribution packaging

To avoid over-fragmentation in the main paper:

1. NBE is presented as the primary systems guarantee.
2. SAP is presented as the control-plane privacy resolution to outsourced policy evaluation.
3. SM/PEI/SCS/DAS are presented as a combined confidentiality-and-binding envelope.

This packaging changes exposition, not mathematical assumptions.

Canonical evidence anchors (paper/report synchronization):

1. Official fair compare (`C1..C5`): `artifact_out_compare_noprompt/fair_full_report.json`
2. Fair statistics/significance: `artifact_out_compare_noprompt/stats/fair_full_stats.json`
3. `L_policy` leakage sweep: `artifact_out_compare/leakage_sweep/leakage_model_sweep.json`
4. Federation campaign: `artifact_out_compare/multi_agent_federated_eval.json`

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

### 2.4 Evaluation threat-model mapping (fairness boundary)

The repository distinguishes two evaluation threat models:

1. Threat Model A (honest runtime): native guardrail baselines (Codex/OpenClaw and mediated DRIFT/IPIGuard/AgentArmor) are interpreted as runtime-behavior defenses.
2. Threat Model B (compromised runtime): runtime may attempt direct bypass, replay, and cross-context misuse; NBE/SCS/DAS claims are evaluated here.

This separation prevents unfair baseline interpretation and matches `BASELINES_FAIRNESS.md`.

## 3. Unified Notation

### 3.1 Request and Context Tuples

Bound request tuple:

`rho = (intent_id, caller, session, inputs_eff, hctx)`

where `hctx = (external_principal, delegation_jti)` serialized as a JSON object with absent fields omitted (empty object when no delegation context is present).

Commit context tuple:

`ctx = (action_id, program_id, request_sha256, hctx)`

Request binding digest:

`ReqBind(rho) = HMAC(k_bind, CanonJSON(payload(rho)))` if keyed mode is enabled, otherwise
`ReqBind(rho) = SHA256(CanonJSON(payload(rho)))` in legacy mode.

Wire compatibility note: the protocol field name remains `request_sha256` in v1 evidence.

Artifact implementation:

1. `common/canonical.py:request_sha256_v1`
2. `executor_server/server.py:_verify_commit_evidence`

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
6. Recomputed `ReqBind(rho(req))` equals proof digest.
   (in implementation this is `ReqBind`, emitted as `request_sha256` in v1 wire format)
7. Replay guard rejects duplicates in replay window.
8. Reconstructed policy bits satisfy `allow_pre=1`.
9. `need_confirm=1` implies explicit confirmation.
10. Sanitization patch constraints hold.

Operational assumptions for sound freshness and replay claims:

1. Bounded time skew/transport delay: `Delta_clk + Delta_net < POLICY_MAC_TTL_S`.
2. Replay check-and-mark semantics are atomic; replay persistence across restart is either enabled (`EXECUTOR_REPLAY_DB_PATH`) or excluded by an explicit no-restart assumption for the replay window.

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

1. keyed mode: HMAC binding is forged/broken for distinct canonicalized messages, or
2. legacy mode: SHA256 collision is found on canonicalized messages, or
3. Canonicalization consistency is violated.

Reason:

Accepted proof digest equals recomputed `ReqBind(rho(req))`.
Different tuples with equal digest imply binding break/collision or serialization inconsistency.

### 5.3 Theorem `T_NBE`

Assume:

1. HMAC is EUF-CMA secure.
2. Request binding primitive for the configured mode is secure (`HMAC` PRF-style in keyed mode, `SHA256` collision resistance in legacy mode), and canonicalization is consistent.
3. Executor implements acceptance predicate exactly.
4. Time drift and transport delay satisfy `Delta_clk + Delta_net < POLICY_MAC_TTL_S`.
5. Replay check-and-mark is atomic and replay durability assumptions hold for the configured replay window.

Then for any PPT adversary `A`:

`Pr[Bad_NBE] <= Adv_euf_cma(B0) + Adv_euf_cma(B1) + Adv_coll(C) + eps_time + eps_replay_atomic + eps_replay_persist + negl(lambda)`

where:

1. `B0`, `B1` are reductions against each policy-server MAC key.
2. `C` is a collision finder reduction.
3. `eps_time` captures violations of bounded drift/latency assumptions.
4. `eps_replay_atomic` captures check-and-mark atomicity failures.
5. `eps_replay_persist` captures replay-state durability failures (for example restart/fallback outside the claimed durable window).

Proof sketch by exhaustive cases:

1. No-auth. Acceptance with unseen context implies at least one fresh MAC forgery.
2. Binding-break. Acceptance on changed `rho` with same proof hash implies `L_bind` violation.
3. Replay. Any second acceptance in replay window is replay-store atomicity/persistence failure.
4. Time-envelope failure. Acceptance outside intended freshness envelope is captured by `eps_time`.

Corollary:

Without dual valid proofs, side effects cannot be committed except with negligible advantage plus explicit non-cryptographic assumption-failure terms (`eps_time`, `eps_replay_atomic`, `eps_replay_persist`).

### 5.4 PEI Game and Theorem

Game `G_PEI`:

Adversary outputs `(req_star, pi0_star, pi1_star)` and wins `Bad_PEI` if:

1. `Accept(req_star, pi0_star, pi1_star)=1`, and
2. committed payload is not equal to the payload after required sanitize patch transformation.

Theorem `T_PEI`:

Assume:

1. Executor acceptance predicate is implemented as specified.
2. Required patch derivation from proof outputs is deterministic.
3. All effect sinks go through executor.

Then:

`Pr[Bad_PEI] <= eps_impl_patch + negl(lambda)`

where `eps_impl_patch` captures implementation/spec divergence in patch application logic.

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
2. Handle identifiers are independent of plaintext and carry at least 128 bits of entropy (artifact default uses `secrets.token_urlsafe(16)`).
3. Declassification path is explicit, logged, and policy-controlled.

Then runtime view is simulatable from:

`L_SM = (handle ids, labels, ttl, reason codes, explicitly declassified outputs)`

and for any adversary making at most `q_h` online handle guesses in the valid window:

`Pr[Bad_SM] <= q_h / 2^128 + negl(lambda)`

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
3. Fixed-shape routing and shaping are configured as assumed by `L_policy = (L_PIR, L_MPC, L_CONFIRM, L_TIME)`.
4. If intent-category hiding is claimed, observable MPC metadata (`program_id`, endpoint class, batch shape) is constant across covered intents.
5. At least one policy server is non-colluding.

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

### 8.3 DAS Game and Theorem

Game `G_DAS`:

Adversary reuses or swaps delegation/ingress context and wins `Bad_DAS` if executor accepts under a different `(caller, session, hctx)` from the one bound into accepted commit evidence.

Theorem `T_DAS`:

Assume:

1. Delegation token signatures are EUF-CMA secure.
2. `ReqBind` is secure for configured mode and canonicalization is consistent.
3. Executor recomputes request binding digest including `hctx=(external_principal, delegation_jti)`.
4. Replay and freshness assumptions from `T_NBE` hold.

Then:

`Pr[Bad_DAS] <= Pr[Bad_NBE] + Adv_euf_cma(Sig) + Adv_bind + eps_canon + negl(lambda)`

## 9. Composition Theorem

Define combined bad event:

`Bad_SC = Bad_NBE or Bad_SM or Bad_PEI or Bad_SCS or Bad_DAS or Bad_SAP`

### 9.1 Dependency Partition

Property dependency table:

1. `NBE` depends on MAC unforgeability, hash binding consistency (including auth-context binding), bounded clock skew/latency assumptions, replay atomicity/durability semantics, and executor accept implementation.
2. `SM` depends on handle discipline (including handle entropy bound) and explicit declassification discipline in gateway.
3. `PEI` depends on executor patch derivation and mandatory sanitize-then-commit path.
4. `SCS` depends on enforceable capsule contract and non-bypass requirement for external effects.
5. `DAS` depends on delegation token verification, revocation semantics, and auth-context request-hash binding.
6. `SAP` depends on PIR one-server privacy, MPC one-party privacy, fixed-shape leakage contract, non-collusion.

### 9.2 Composition Bound

`Pr[Bad_SC] <= Pr[Bad_NBE] + Pr[Bad_SM] + Pr[Bad_PEI] + Pr[Bad_SCS] + Pr[Bad_DAS] + Pr[Bad_SAP]`

with each term bounded by its theorem assumptions.

Proof is direct union bound plus per-property theorem bounds; disjointness is not required (overlap only affects tightness).

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
                 | NBE + SM + PEI  |
                 | + SCS + DAS     |
                 | (+ SAP optional)|
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

1. `formal/secureclaw_model_check.py` checks finite-state consistency for NBE, SM, PEI, DAS, and SCS contract shape.
2. `scripts/security_game_nbe_check.py` executes end-to-end NBE adversarial probes.
3. `tests/test_security_games.py` validates replay, hash binding, dual-proof necessity.
4. `scripts/verify_accept_predicate.py` validates semantic accept constraints.
5. `scripts/validate_specs.py` validates schema and spec files.
6. `tests/test_accept_predicate_verifier.py` validates accept/confirm and patch-related decision semantics.
7. `tests/test_delegation_and_dual_principal.py` and `tests/test_federated_auth.py` validate delegation and federation context binding.

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
5. If keyed request binding is disabled (legacy mode), `request_sha256` observability can permit offline guessing on low-entropy fields; keyed mode mitigates this by using HMAC commitment with a gateway+executor-only secret.
6. DAS claims rely on delegation key management and revocation-store correctness in deployment.
