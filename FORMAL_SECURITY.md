# Formal Security Claims and Proof Chain (NBE / SM / SAP / SCS)

This document upgrades MIRAGE-OG++'s security story into an **appendix-grade** proof chain:
explicit games, acceptance predicates, and reductions, with direct pointers into this repo.

Scope (artifact-accurate):

- Implementation: the current MIRAGE-OG++ code in this repository.
- Adversary: PPT adversary controlling prompts/skills/runtime inputs and able to send arbitrary requests to the gateway and executor.
- Keys: executor-side MAC verification keys are not compromised.
- Policy servers: honest-but-curious for privacy (SAP), not malicious for integrity. (NBE is about *bypass* by the runtime, not about a malicious policy server authorizing bad actions.)

Code-linked checks:

- Formal NBE harness: `scripts/security_game_nbe_check.py`
- Unit tests: `tests/test_security_games.py`

---

## 0. Parties, APIs, and Trust Boundaries

Parties:

- `A`: adversary controlling the untrusted agent runtime and skills.
- `G`: trusted gateway orchestrating PIR/MPC and issuing `tx_id` in PREVIEW.
- `P0, P1`: two policy servers (honest-but-curious; non-colluding for SAP).
- `E`: trusted executor, the only component allowed to perform side effects.
- `C`: optional capsule enforcing a mediation contract (for SCS).

Executor side-effect endpoints:

- `/exec/send_message`
- `/exec/fetch`
- `/exec/webhook`
- `/exec/skill_install`

Important knob:

- `EXECUTOR_INSECURE_ALLOW=1` bypasses enforcement; **all claims assume `EXECUTOR_INSECURE_ALLOW=0`**.

---

## 1. Syntax and Cryptographic Primitives

Security parameter: `lambda` (implicit).

### 1.1 Canonicalization and Request Binding Hash

Define the request-binding function:

```
ReqHash(intent_id, caller, session, inputs) = SHA256( CanonicalJSON({
  "intent_id": intent_id,
  "caller": caller,
  "session": session,
  "inputs": inputs
}) )
```

Implementation:

- `common/canonical.py:request_sha256_v1`

This hash is recomputed by the executor from the incoming request payload and must match the value bound in commit proofs.
Therefore, security depends on:

- SHA-256 collision resistance, and
- consistent canonicalization (same semantics -> same bytes at both gateway and executor).

### 1.2 Commit Proof Shares (Per Policy Server)

Each policy server `Pi` holds a MAC key `Ki` and outputs a commit proof share:

- `pi_i = (meta_i, mac_i)`
- `mac_i = HMAC(Ki, CanonicalJSON(meta_i))`

Where `meta_i` includes:

- `v = 1`
- `kind = "commit"`
- `server_id in {0,1}`
- `kid` (key identifier, supports rotation)
- `ts` (timestamp, seconds)
- `action_id` (commit identifier)
- `program_id` (policy program identifier)
- `request_sha256 = ReqHash(...)`
- `outputs` (XOR shares of output bits)
- `commit_tag_share_b64` (XOR share of an audit tag)

Implementation:

- Python policy server: `policy_server/server.py` (`/mpc/finalize`)
- Rust policy server: `policy_server_rust/src/main.rs` (`/mpc/finalize`)

---

## 2. Executor Acceptance Predicate (What Must Hold to Commit an Effect)

Define the context tuple:

- `ctx = (action_id, program_id, request_sha256)`.

Given an effect request `req` and two commit proofs `(pi_0, pi_1)`, the executor accepts iff:

1. **Both proofs parse** and have `v=1`, `kind="commit"`.
2. **MAC keys are known** for the claimed `server_id` and `kid` (rotation supported).
3. **MACs verify** under those keys.
4. **Freshness**: `abs(now - ts) <= POLICY_MAC_TTL_S`.
5. **Binding**: both proofs bind exactly the same `ctx`, and `request_sha256` equals the executor's recomputed `ReqHash(...)` on the request.
6. **Replay resistance**: `action_id` has not been used before (best-effort replay cache, optionally persistent).
7. **Policy decision bits** reconstruct to `allow_pre=1`, and `need_confirm` implies user confirmation; sanitize patches are enforced.

Implementation:

- Common proof checks: `executor_server/server.py:_validate_commit_proof_common`
- Dual-proof verify + output reconstruction + commit tag: `executor_server/server.py:_verify_commit_evidence`
- Replay cache: `executor_server/server.py:_ReplayGuard` (`reason_code=REPLAY_DENY`)
- Endpoint enforcement: `executor_server/server.py` `/exec/*`

---

## 3. Security Games

### 3.1 Game `G_NBE` (Non-Bypassable Effects)

Goal: the adversary cannot cause a side effect without dual authorization bound to the exact request context, and cannot replay it.

Let `CommitOracle(ctx)` return valid commit proofs for a context `ctx = (action_id, program_id, request_sha256)`. The challenger records a set `S` of all contexts for which **both** proofs were issued by the oracle.

Experiment `Exp^{NBE}_{Pi,A}(lambda)`:

1. Challenger samples independent MAC keys for policy servers and initializes `S = empty`.
2. `A` adaptively queries `CommitOracle(ctx)`; challenger returns `(pi_0, pi_1)` and records `ctx in S`.
3. `A` outputs a side-effect request `req*` plus `(pi_0*, pi_1*)`.
4. `A` wins iff `Accept_E(req*, pi_0*, pi_1*) = 1` and either:
   - `ctx(req*)` is not in `S` (no dual authorization was obtained for that exact context), or
   - `ctx(req*)` (equivalently `action_id*`) was already accepted before (replay).

### 3.2 Game `G_SM` (Secret Myopia)

Goal: sensitive plaintext does not flow to the untrusted runtime by default.

Experiment `Exp^{SM}_{Pi,A}(lambda)`:

1. `A` interacts with the gateway via `act(intent_id, inputs, constraints, caller)`.
2. The gateway may mint a handle record `(handle, session, caller, ttl, sensitivity, allowed_sinks)` and return only the opaque `handle`.
3. `A` wins if it receives any HIGH-sensitivity plaintext value without satisfying the explicit declassification/confirmation path.

Code points:

- Handle store + bindings: `gateway/handles.py`
- File -> handle minting: `gateway/executors/fsexec.py`
- Declassify path: `gateway/executors/cryptoexec.py`

### 3.3 Game `G_SAP` (Single-Auditor Privacy, Leakage-Aware)

Goal: a single policy server cannot infer queried identities beyond an explicit leakage function `L(.)`.

We use a standard simulation-style definition parameterized by leakage.
The system satisfies `SAP(L)` if for each server `Pi` there exists a PPT simulator `Sim_i` such that for all PPT distinguishers `D`:

```
| Pr[D(View(Pi))=1] - Pr[D(Sim_i(L(params, A)))=1] | <= negl(lambda)
```

Where:

- `View(Pi)` is the transcript observed by `Pi` (PIR + MPC endpoints, sizes, timing).
- `A` is the (secret) sequence of gateway actions.
- `L(params, A)` is the allowed leakage defined in `LEAKAGE_MODEL.md`.

### 3.4 Game `G_SCS` (Skill-Confined Safety, Conditional)

Goal: under a capsule mediation contract, skills cannot bypass `act` to perform forbidden direct actions.

Experiment `Exp^{SCS}_{Pi,A}(lambda)`:

1. `A` controls the skill code and runtime instructions inside capsule `C`.
2. Capsule enforces a mediation contract `MC` (filesystem/network/exec restrictions).
3. `A` wins if it performs a forbidden direct action while `MC` holds (e.g., host secret read, arbitrary exec, direct Internet exfil).

Code points:

- macOS sandbox profile: `capsule/capsule.sb`
- Capsule proxy (UDS preferred): `capsule/mcp_proxy.py`
- Capsule smoke tests: `capsule/smoke.py`

---

## 4. Theorems and Reductions

### Lemma L1 (Binding: Session/Caller/Inputs)

Assume `ReqHash` is collision-resistant and canonicalization is consistent across gateway and executor.

If the executor accepts a request `req*` using commit proofs whose `request_sha256` was produced for a *different* tuple `(intent_id, caller, session, inputs)`, then we obtain either:

- a collision in `ReqHash`, or
- a canonicalization inconsistency.

In particular, because `ReqHash` includes `caller` and `session`, changing `caller` or `session` after PREVIEW invalidates the commit proofs unless a collision exists.

### Theorem T1 (NBE: No Side Effects Without Dual Authorization)

Assume:

1. HMAC-SHA256 is EUF-CMA secure.
2. `ReqHash` is collision-resistant and canonicalization is consistent (Lemma L1).
3. Executor enforces `Accept_E` with `EXECUTOR_INSECURE_ALLOW=0`.

Then there exist PPT reductions `B0, B1, C` such that for any PPT adversary `A`:

```
Pr[Exp^{NBE}_{Pi,A}(lambda)=1]
  <= Adv^{euf-cma}_{HMAC}(B0) + Adv^{euf-cma}_{HMAC}(B1) + Adv^{coll}_{ReqHash}(C) + negl(lambda)
```

Proof (case analysis, reduction-level detail):

Let `A` win `Exp^{NBE}` by outputting `(req*, pi_0*, pi_1*)` accepted by the executor.
By definition of `Accept_E`, both proofs verify and bind to the same context
`ctx* = (action_id*, program_id*, request_sha256*)`.

We consider two exhaustive possibilities for the win condition:

**Case 1: ctx* not in S (no dual authorization was issued by the oracle).**

Because acceptance requires both MAC-valid proofs, at least one of `pi_0*` or `pi_1*`
is a fresh MAC forgery relative to the corresponding server's signing oracle.
Construct `B0` (similarly `B1`) that embeds its UF-CMA challenge key as policy0's key,
answers `CommitOracle` queries by using the UF-CMA signing oracle to MAC canonical payloads,
and outputs `pi_0*` as the forgery when `A` wins in Case 1.

**Case 2: ctx* in S, but req* differs in any bound field from the request whose hash was authorized.**

Executor acceptance implies `request_sha256*` equals the executor recomputation on `req*`.
If `req*` differs in any bound field (`caller`, `session`, or effectful inputs), Lemma L1 yields
a collision in `ReqHash` or canonicalization inconsistency. Construct collision finder `C`
by outputting the two distinct canonical inputs producing the same `request_sha256*`.

Combining the cases yields the bound.

Implementation mapping:

- MAC verification: `executor_server/server.py:_verify_mac`
- Context binding: `executor_server/server.py:_validate_commit_proof_common`
- Request hash recomputation: `common/canonical.py:request_sha256_v1`

### Theorem T2 (Replay: No Double-Commit of the Same action_id)

Assume the executor runs the replay guard check-and-mark on `action_id` exactly when
an effect commit is accepted, and rejects any future commit with that `action_id`
within the replay TTL (`EXECUTOR_REPLAY_TTL_S`).

Then an adversary cannot cause the executor to accept the same `(action_id, program_id, request_sha256)`
twice within the replay TTL (except with probability due to replay store failure/crash).

Implementation:

- `executor_server/server.py:_ReplayGuard.check_and_mark`
- Enforced in each `/exec/*` endpoint (returns `REPLAY_DENY` on duplicates)

### Theorem T3 (Composition: PIR + MPC + Executor Evidence Chain + Capsule)

The artifact composes the following mechanisms:

- PIR/FSS membership for outsourced policy DB reads (privacy goal SAP),
- 2PC/MPC evaluation for fixed policy circuits (decision bits secret-shared),
- executor dual-authorization (T1) to enforce NBE at the effect boundary,
- optional capsule mediation contract to conditionally enforce SCS.

Under the joint assumptions of:

- T1/T2 for executor enforcement,
- SAP(L) for the policy-server transcript (with `L(.)` defined in `LEAKAGE_MODEL.md`), and
- capsule mediation contract `MC` (for SCS),

the composed system satisfies NBE, SM, SAP(L), and conditional SCS simultaneously.

The combination argument is a standard hybrid: each property is enforced at a different trust boundary
(executor for NBE; gateway handle store for SM; PIR/MPC transcript design for SAP; capsule for SCS),
so the overall failure probability is bounded by the sum of component advantages.

---

## 5. Reproducibility (Formal Checks)

Run:

```bash
PYTHONPATH=. python scripts/security_game_nbe_check.py
python -m unittest discover -s tests -p 'test_security_games.py'
```

Expected:

- Dual valid commit proofs accept once.
- Missing proof / tampered MAC / mismatched request hash / expired proof are rejected.
- Replay is rejected with `reason_code=REPLAY_DENY`.

---

## 6. Explicit Limits (Do Not Overclaim)

- `request_sha256` is an *unkeyed* hash. A malicious policy server that observes it may attempt
  dictionary attacks if the underlying bound inputs are low-entropy. A production design can use
  a keyed commitment shared by gateway+executor instead.
- NBE prevents bypass by the untrusted runtime; it does not stop a malicious policy server from
  authorizing an unsafe action (out of scope in this artifact's model).
- Traffic analysis is only addressed up to the explicit leakage function `L(.)` (see `LEAKAGE_MODEL.md`).
- If the executor is misconfigured into insecure allow mode, NBE is intentionally disabled.

