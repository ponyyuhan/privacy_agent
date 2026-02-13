# MIRAGE-OG++: Algorithms and Protocols (Artifact, English)

This document isolates the **paper-writeable algorithms/protocols** implemented in this repository.
It intentionally does **not** claim standard primitives as contributions (e.g., DPF/DCF/FSS, GMW/Beaver
triples). Instead, it specifies what is new in MIRAGE-OG++ at the system/protocol/compiler layer:

1. Proof-carrying, non-bypassable effect commits (dual authorization tokens).
2. Intent-shadowed unified policy program compilation (one constant-shape program for multiple intents).
3. Oblivious bundle selection and constant-shape PIR query planning (hide logical DB / intent category).
4. PIR traffic shaping (microbatch mixing + padding + optional cover traffic).
5. AND-depth round scheduling and batch MPC evaluation (reduce interaction from O(#AND) to O(depth)).
6. An explicit leakage model boundary for what the policy servers are allowed to learn.

All algorithms below are backed by concrete code and **unit/integration checks** in this repo; see
the **Validation** section for the exact commands and files.

---

## 0. System Model

### Entities

- G: Gateway (policy client). Constructs privacy-preserving queries, obtains proofs, and forwards an effect request.
- P0, P1: Two policy servers. They hold policy databases and evaluate policy logic, returning shares plus MAC proofs.
- E: Executor. The only component allowed to commit external side effects (send message, fetch, webhook, enable skill).

### Threat Model (Artifact Scope)

- The adversary controls prompts, skills, and runtime inputs. It may also control the gateway process and attempt to bypass policy.
- E is trusted to enforce effect gating and holds verification keys for P0/P1 MAC proofs.
- P0/P1 are assumed honest for correctness.
- For privacy, we assume **non-collusion** between P0 and P1 (the usual 2-server PIR setting): we aim for "single-server privacy".
- Traffic shaping is partial; the allowed leakage is described explicitly as a leakage function L(.) in `LEAKAGE_MODEL.md`.

---

## 1. Notation and Data Structures

### 1.1 XOR Secret Sharing (Bits)

For a bit x in {0,1}, represent it as (x0, x1) such that:

- x = x0 XOR x1

Each server Pi sees only xi.

### 1.2 Context Binding

We bind every authorization to an immutable context:

- action_id: opaque identifier minted by G (unique per action).
- program_id: policy program identifier (e.g., "policy_unified_v1").
- request_sha256: hash of a canonicalized request (intent_id, caller, session, inputs).

In code, request_sha256 is computed by `common/canonical.py:request_sha256_v1`.

### 1.3 MAC Proofs

Each policy server Pi holds a MAC key Ki (HMAC-SHA256 in this artifact).
Whenever Pi responds to G for an action_id, it returns:

- Answer shares (PIR bit shares, MPC output shares).
- A proof object proof_i = payload_i || mac_b64, where:
  - mac_b64 = HMAC(Ki, CanonicalJSON(payload_i))
  - CanonicalJSON sorts keys and uses stable separators (see executor verifier).

Proof types used by this artifact:

- Signed PIR bit-batch proof (kind="bit"):
  - Binds (action_id, db, keys_sha256, resp_sha256, ts, kid, server_id).
- Signed MPC commit proof (kind="commit"):
  - Binds (action_id, program_id, request_sha256, outputs, commit_tag_share_b64, ts, kid, server_id).

Executor verification is implemented in `executor_server/server.py`.

---

## 2. Algorithm A1: Dual-MAC Proof-Carrying Commit (Non-Bypassable Effects)

### Goal

Ensure that **no external side effect can be committed** unless both policy servers participated and issued valid,
fresh, context-bound authorization proofs.

### Interface

Inputs to E (effect endpoint call):

- An effect request req (send message / fetch / webhook / skill install).
- action_id, caller, session.
- commit evidence: {policy0: proof0, policy1: proof1}, where each proof is kind="commit".

Output:

- OK with sanitized/approved side effect data, or DENY with a reason code.

### Protocol

Algorithm A1.GatewayPreviewCommit (high level):

1. G computes request_sha256 := H(canonical(intent_id, caller, session, inputs)).
2. G runs privacy-preserving policy evaluation (PIR for features; MPC for boolean program outputs).
3. Each Pi returns a commit proof share commit_proof_i (MAC-signed) bound to (action_id, program_id, request_sha256).
4. G forwards (req, action_id, commit={policy0:commit_proof_0, policy1:commit_proof_1}) to E.

Algorithm A1.ExecutorVerifyCommit:

1. Recompute request_sha256 locally from (intent_id, caller, session, inputs) in req.
2. Verify each proof independently:
   - parse fields, check kind="commit", check freshness |now - ts| <= TTL;
   - check equality of (action_id, program_id, request_sha256);
   - verify MAC under the correct server key id (kid) and server id (server_id).
3. Reconstruct clear outputs by XOR-ing output shares from P0/P1.
4. Enforce decision:
   - if allow_pre=0 then DENY.
   - if need_confirm=1 and user_confirm absent then DENY (optionally return a preview).
5. Apply the sanitize patch (if any) and commit the effect.

### Correctness

If P0/P1 are honest and issued proofs for the same (action_id, program_id, request_sha256), then E will accept iff
the reconstructed outputs satisfy the local decision predicate (e.g., allow_pre=1 and confirm constraints).

### Security Claim (NBE)

Any adversary that causes E to accept without obtaining both valid commit proofs for the executed context must either:

- Forge a MAC under an unknown policy server key, or
- Break the request binding (e.g., find a collision so that two different requests share the same request_sha256).

Formal games and the code-linked theorem are in `FORMAL_SECURITY.md`.

### Implementation Map

- Commit proof generation: `policy_server/server.py:/mpc/finalize` and `policy_server_rust/src/main.rs` (MPC finalize).
- Commit proof verification: `executor_server/server.py:_verify_commit_evidence`.
- Formal check harness: `scripts/security_game_nbe_check.py`, unit tests in `tests/test_security_games.py`.

---

## 3. Algorithm A2: Oblivious Policy Bundle Layout and Index Shift (Hide Logical DB Name)

### Goal

Hide which logical policy table is being queried (e.g., allow_recipients vs banned_tokens) by always querying a
single physical bundled DB ("policy_bundle") and shifting indices into disjoint subranges.

### Bundle Parameters

Let:

- N_base: base logical domain size (power of two).
- stride: distance between two bundles (>= total subrange span for one bundle).
- bundle_id: which bundle instance to select (e.g., "default", "prod", "expA").
- offset[L]: logical offset for each logical DB name L.
- N_bundle: physical bundled domain size (power of two), covering all bundles.

The policy server exposes these via /meta (loaded by the gateway) and also stores the bundled DB on disk.

### Mapping Function

Algorithm A2.ShiftIndex

Input:
- L: logical DB name
- i: raw index in [0, N_base)

Output:
- j: shifted index in [0, N_bundle)

Definition:

1. base := bundle_id * stride
2. j := base + offset[L] + (i mod N_base)

### Correctness

Assuming the physical DB is constructed such that, for each logical DB L, the bit at position
base + offset[L] + i equals the logical bit DB_L[i], then ShiftIndex preserves membership semantics:

- PIR(policy_bundle, ShiftIndex(L,i)) reconstructs to DB_L[i].

### Security / Leakage

From a single policy server view, db_name is constant ("policy_bundle") and does not directly reveal L.
Remaining leakage (domain size, batch size, timing, etc.) is captured explicitly by L(.) in `LEAKAGE_MODEL.md`.

### Implementation Map

- Shift: `gateway/policy_unified.py:_bundle_shift`.
- Meta loading: `gateway/policy_unified.py:_load_bundle_cfg`, policy server `/meta`.
- Bundled DB build: `policy_server/build_dbs.py`.

---

## 4. Algorithm A3: Constant-Shape Unified PIR Query Plan (Fixed Key Count)

### Goal

For every action (send/fetch/webhook/skill-install), issue a **single signed PIR query** to a single bundled DB with a
**fixed number of DPF keys**, independent of actual message length, skill metadata size, or domain list length.

This reduces intent/category leakage at the PIR surface and produces signed transcripts usable by E for verification/audit.

### Parameters

- T: max token slots (constant).
- D: max skill domain slots (constant).
- N_base: base domain size.
- Bundle layout: (bundle_id, stride, offset[.], N_bundle) from Algorithm A2.

### Plan Construction

Algorithm A3.BuildFixedShapePlan

Input:
- recipient (string), domain (string), text (string)
- skill_domains (list of strings), skill_md (string)
- action_id (string)
- T, D, N_base, bundle parameters

Output:
- idxs: list of shifted indices of length K = 2 + T + D + T
- evidence: signed PIR transcript (per-server MAC proofs)
- features: (recipient_ok, domain_ok, dlp_hit, ioc_hit, install_hit)

Steps:

1. Pad skill_domains to exactly D entries:
   - truncate to D if longer
   - append dummy domains if shorter
2. Extract install tokens from skill_md and pad to exactly T tokens:
   - truncate/pad with dummy tokens
3. Compute raw indices under the base domain:
   - rec_raw := StableIndex(recipient, N_base)
   - dom_raw := StableIndex(domain, N_base)
   - tok_raw[0..T-1] := FourgramIndices(text, N_base, T)
   - ioc_raw[0..D-1] := StableIndex(skill_domains[k], N_base)
   - inst_raw[0..T-1] := StableIndex(install_tokens[k], N_base)
4. Shift each raw index into the bundled DB:
   - idxs :=
     - ShiftIndex("allow_recipients", rec_raw)
     - ShiftIndex("allow_domains", dom_raw)
     - for k in 0..T-1: ShiftIndex("banned_tokens", tok_raw[k])
     - for k in 0..D-1: ShiftIndex("ioc_domains", ioc_raw[k])
     - for k in 0..T-1: ShiftIndex("banned_install_tokens", inst_raw[k])
5. Issue a single signed PIR query (bit batch) to the bundled DB:
   - bits[0..K-1], ev := SignedPIRBitBatch(db="policy_bundle", idxs, action_id, domain_size=N_bundle)
6. Derive fixed-shape feature bits:
   - recipient_ok := bits[0]
   - domain_ok := bits[1]
   - dlp_hit := OR(bits[2 : 2+T])
   - ioc_hit := OR(bits[2+T : 2+T+D])
   - install_hit := OR(bits[2+T+D : 2+T+D+T])

### Correctness

Assuming correctness of the underlying 2-server PIR reconstruction, each returned bit equals the membership bit of its
corresponding logical table and raw index. Therefore the derived feature bits equal their intended predicates (membership
or OR of membership bits).

### Constant-Shape Property

K = 2 + 2T + D is a constant determined only by (T, D). It is independent of:

- text length
- skill_md length
- number of provided domains
- chosen intent category

Combined with Algorithm A2, the policy server view sees a constant db name ("policy_bundle") and constant key count K.

### Implementation Map

- Plan + feature reconstruction: `gateway/policy_unified.py:_pir_unified_plan`.
- Stable/fourgram indexing: `gateway/guardrails.py:stable_idx`, `gateway/guardrails.py:fourgram_indices`.
- Signed PIR client calls: `gateway/fss_pir.py:query_bits_signed`.

---

## 5. Algorithm A4: PIR Microbatch Mixing, Padding, and Optional Cover Traffic

### Goal

Reduce policy-server-visible traffic shape leakage by:

- batching multiple signed PIR subrequests into one HTTP call per server,
- padding to a fixed subrequest count per tick (pad_to),
- optionally emitting dummy-only batches when idle (cover traffic).

This mechanism is intentionally narrow: it targets **signed bit-batch PIR** (constant-shape subrequests) so it can be
used as a drop-in wrapper around Algorithm A3.

### Parameters (Mixer Config)

- interval_ms: flush interval (tick).
- pad_to: number of subrequests sent per tick (real + dummy).
- fixed_n_keys: number of DPF keys per subrequest (must be constant; provided by Algorithm A3).
- db_name: physical DB name (typically "policy_bundle").
- domain_size: bundled domain size N_bundle.
- cover_traffic: whether to send dummy-only batches when no real work is pending.

### Protocol

Algorithm A4.MixAndSendSignedPIR

State:
- A queue Q of pending subrequests.
- Each subrequest contains:
  - action_id
  - dpf_keys_b64 (for that server), length fixed_n_keys

Every tick (every interval_ms):

1. Pop up to pad_to real subrequests from Q.
2. If cover_traffic is enabled and there are fewer than pad_to real items, pad with dummy subrequests:
   - dummy action_id is random
   - dummy DPF keys are generated for random indices (indistinguishable from real keys under DPF security)
3. Send one HTTP request to each policy server:
   - POST /pir/query_batch_multi_signed
   - payload: {db: db_name, requests: [{action_id, dpf_keys_b64}, ...] } with exactly pad_to requests
4. Each server returns per-subrequest (ans_shares, proof). For each real action_id:
   - reconstruct bits by XOR-ing the two servers' ans_shares
   - return a combined evidence record containing both MAC proofs and the answer shares

### Correctness

Functional correctness is immediate: /pir/query_batch_multi_signed is equivalent to iterating over /pir/query_batch_signed
for each subrequest (the server computes the same PIR parity share per key and MAC-signs the response payload).
Therefore, for each real subrequest, the reconstructed bit vector equals the direct signed query result.

### Security / Leakage

With cover_traffic enabled, the policy server observes a **constant** number of subrequests per tick and a constant key
count per subrequest (fixed_n_keys). Remaining leakage is explicitly enumerated by the leakage model L(.) in
`LEAKAGE_MODEL.md` (tick interval, padding rate, etc.).

### Implementation Map

- Mixer: `gateway/fss_pir.py:_SignedBitBatchMixer`, `gateway/fss_pir.py:MixedPirClient`.
- Multi-signed endpoint (Python): `policy_server/server.py:/pir/query_batch_multi_signed`.
- Multi-signed endpoint (Rust): `policy_server_rust/src/main.rs` (same route).

---

## 5.1 Algorithm A4b: Sparse Bitset PIR Evaluation (Precomputed 1-Indices)

### Goal

Make the PIR server evaluation path practical at larger domain sizes by exploiting the fact that many policy databases
(allowlists, IOC sets, install markers) are **sparse** when represented as a bitset.

The PIR answer share for a bitset DB is:

- `ans_share = XOR_i (DB[i] & f_party(i))`.

If `DB[i]=1` only for `i` in a set `S`, then:

- `ans_share = XOR_{i in S} f_party(i)`.

This reduces work from `O(N)` full-domain expansion to `O(|S| log N)` point evaluations.

### Protocol (Server-Side Kernel)

Algorithm A4b.PrecomputeOnes

Input:
- bitset DB `DB` over domain size `N`

Output:
- `S = { i : DB[i] = 1 }` as a sorted integer list

Algorithm A4b.SparseParityShare

Input:
- DPF key share `k_party`
- `S` (precomputed)

Output:
- `ans_share` bit

Steps:
1. `ans_share <- 0`
2. For each `i in S`:
   - `ans_share <- ans_share XOR DPFEvalPoint(k_party, i)`
3. Return `ans_share`

### Correctness

Immediate from algebra:
`XOR_i (DB[i] & f(i))` equals `XOR_{i in S} f(i)` because `DB[i]=0` for all `i not in S`.

### Leakage

This is an **internal evaluation strategy** at the policy server; it does not add new explicit transcript fields.
Any timing differences are still accounted for under the system's explicit leakage boundary `L(.)`.

### Implementation Map

- Precompute set-bit indices:
  - Python: `policy_server/db.py:BitsetDB.load` (`self._ones`)
  - Rust: `policy_server_rust/src/main.rs:bitset_ones` (`bitset_ones` map in state)
- Sparse parity share evaluation:
  - Python: `fss/dpf.py:eval_dpf_pir_parity_share_sparse`
  - Rust: `policy_server_rust/src/main.rs:eval_parity_share_sparse`
- Validation:
  - `tests/test_ogpp.py:test_sparse_parity_share_matches_dense`

---

## 6. Algorithm A5: AND-Depth Round Scheduling and Batch MPC Evaluation

### Goal

Evaluate a boolean policy program with many AND gates using **batched interaction**:

- Instead of one interactive round per AND gate (O(#AND) rounds),
- Evaluate all AND gates in the same AND-depth layer together, yielding O(depth) interactive rounds.

This is crucial for intent-shadowed unified programs that contain multiple intents but must remain constant-shape.

### Circuit Model

We represent a boolean circuit as:

- W wires (indexed 0..W-1) holding XOR-shared bits.
- A list of gates, each gate is one of: XOR, NOT, CONST, AND.
- XOR/NOT/CONST are evaluated locally under XOR-sharing.
- AND is evaluated interactively using Beaver triples.

### AND-Depth and Rounds

Algorithm A5.ComputeAndRounds

For each wire, define and_depth[wire]:

- Inputs have depth 0.
- CONST outputs have depth 0.
- XOR/NOT outputs have depth max(depth(inputs)).
- AND outputs have depth max(depth(inputs)) + 1.

Group AND gates by their output depth d=1..Dmax to obtain rounds:

- rounds[d] = { gate_index of AND gates with output depth d }.

Property:

- For any AND gate in round d, both its input wires have and_depth <= d-1.

### Batched Beaver Evaluation

Algorithm A5.RoundBatchedMPC

Participants:
- G orchestrates; P0 and P1 hold shares.

Inputs:
- action_id, program_id, request_sha256
- circuit (gates, outputs)
- input shares for each party
- and_rounds computed by A5.ComputeAndRounds

Protocol:

1. G sends /mpc/init to both servers with identical circuit and their respective input shares.
2. For each round r in and_rounds:
   - For each AND gate g in round r, G samples a Beaver triple (a,b,c=a AND b) in the clear and secret-shares it.
   - G sends each server its list of triple shares via /mpc/and_mask_batch.
   - Each server returns d_share = x_share XOR a_share and e_share = y_share XOR b_share for each gate.
   - G opens (d,e) per gate by XOR-ing the servers' shares and sends opens back via /mpc/and_finish_batch.
   - Each server computes its output share z_share of x AND y and writes it to the gate's output wire.
   - Each server evaluates any newly-ready local gates (XOR/NOT/CONST) opportunistically.
3. G calls /mpc/finalize on both servers to obtain output shares and MAC-signed commit proofs.

### Correctness (Per-AND Gate)

For XOR-sharing and Beaver triples, the standard identity holds:

- Let x = x0 XOR x1 and y = y0 XOR y1.
- Let a = a0 XOR a1, b = b0 XOR b1, c = c0 XOR c1 with c = a AND b.
- Each party computes:
  - d_i = x_i XOR a_i, e_i = y_i XOR b_i
  - open d = d_0 XOR d_1 = x XOR a, and e = e_0 XOR e_1 = y XOR b
  - z_i = c_i XOR (d AND b_i) XOR (e AND a_i), and party 0 additionally XORs (d AND e)
- Then z = z0 XOR z1 = x AND y.

Since the schedule respects AND-depth, all AND inputs are ready when evaluated, and local gates preserve XOR-sharing
semantics. Therefore the reconstructed outputs at the end equal the clear evaluation of the circuit.

### Implementation Map

- Circuit compiler + and_rounds: `gateway/policy_unified.py:_compute_and_rounds`.
- Gateway round batching calls: `gateway/policy_unified.py:_mpc_eval_and_rounds`.
- Policy server MPC session (Python): `policy_server/mpc_engine.py` (+ batch APIs).
- Policy server MPC session (Rust): `policy_server_rust/src/main.rs`.

---

## 7. Algorithm A6: Intent-Shadowed Unified Policy Program Compilation

### Goal

Compile multiple policy intents/categories into a **single constant-shape** MPC program so that:

- policy surface does not branch on intent at the server side,
- the same program_id can be used for all covered intents,
- intent/category leakage is reduced to what is explicitly allowed by L(.).

### Inputs and Outputs

The unified program uses a fixed input vector containing:

- One-hot intent selector bits, e.g., intent_send, intent_fetch, intent_webhook, intent_skill_install.
- Capability bits, e.g., cap_send, cap_fetch, cap_webhook, cap_skill_install.
- Feature bits derived from the fixed-shape PIR plan (recipient_ok, domain_ok, dlp_hit, ioc_hit, install_hit, etc.).

It outputs a fixed output tuple:

- allow_pre, need_confirm, patch0, patch1 (patch bits encode a sanitize patch id).

### Compilation Rule (Oblivious Mux)

Algorithm A6.CompileUnifiedProgram

Given per-intent boolean expressions Expr_i for each output:

1. Allocate fixed input wires for all input bits listed above.
2. For each intent i:
   - compile Expr_i into a boolean subcircuit over the fixed inputs.
3. Obliviously select the active intent's outputs using a one-hot mux:
   - out = XOR_i ( intent_bit_i AND Expr_i )

If exactly one intent_bit is 1 (one-hot), then XOR selection equals OR selection and yields the chosen intent's result.
The circuit shape is constant across intents because all intent branches are present and evaluated in secret-shared form.

### Correctness

Under the one-hot precondition on intent selector bits, for each output wire:

- out equals Expr_j for the unique intent j with intent_bit_j = 1.

### Implementation Map

- Compiler and default unified circuit: `gateway/policy_unified.py:build_policy_unified_v1_circuit_*`.
- Program id default: env `MIRAGE_POLICY_PROGRAM_ID` (default "policy_unified_v1").

---

## 8. Leakage Model Boundary (Explicit L(.))

MIRAGE-OG++ is designed around an explicit "allowed leakage" interface L(.) for what each policy server is permitted
to learn from its own transcript view. The artifact includes:

- Transcript logging at the policy-client boundary (gateway side) for PIR metadata.
- A written leakage model in `LEAKAGE_MODEL.md` (what is currently shaped vs not shaped).

This algorithms document relies on that leakage boundary rather than making informal "leaks nothing" claims.

---

## 9. Validation (Correctness Checks)

The algorithms above are validated by executable checks in this repository.

### 9.1 Unit Tests (Fast, Offline)

Run:

```bash
python -m unittest discover -s tests -q
```

This includes:

- Commit-proof verification checks (Algorithm A1): `tests/test_security_games.py`
- DPF/PIR correctness plumbing, handles, guardrails: `tests/test_ogpp.py`
- MCP gateway handle behavior: `tests/test_mcp_gateway.py`
- Algorithm-level invariants (A2/A3/A4/A5/A6): `tests/test_algorithms.py`

### 9.2 Formal Game Harness (NBE)

Run:

```bash
PYTHONPATH=. python scripts/security_game_nbe_check.py
```

This exercises the NBE game logic and produces a machine-readable result under `artifact_out/`.

### 9.3 Rust Backend Build (Optional, Performance Path)

Run:

```bash
cd policy_server_rust
cargo build --release
```

This ensures the Rust backend implements the same endpoints and proof formats as the Python backend.

---

## 10. Code References (Quick Index)

- Unified policy engine and compilation:
  - `gateway/policy_unified.py`
- PIR client, signed proofs, and mixer:
  - `gateway/fss_pir.py`
- Python policy server endpoints:
  - `policy_server/server.py`
  - `policy_server/mpc_engine.py`
- Rust policy server backend:
  - `policy_server_rust/src/main.rs`
- Executor verification and effect gating:
  - `executor_server/server.py`
- Formal claims and games:
  - `FORMAL_SECURITY.md`
- Leakage model:
  - `LEAKAGE_MODEL.md`
