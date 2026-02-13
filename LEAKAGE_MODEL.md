# Leakage Model (Traffic Shaping, Intent/DB Obfuscation)

This document makes the **allowed leakage** of the current MIRAGE-OG++ implementation explicit.

Scope:

- This is a *protocol-level* leakage model for what a **single policy server** learns from its
  network transcript (PIR/FSS + MPC endpoints), assuming the two policy servers do not collude.
- It is written to match the current code paths:
  - Gateway: unified policy engine (`gateway/policy_unified.py`)
  - PIR/FSS: DPF-based 2-server PIR (`gateway/fss_pir.py`, `policy_server/*`)
  - MPC: GMW-style XOR sharing + Beaver triples (`policy_server/mpc_engine.py`, `policy_server_rust/src/main.rs`)

Non-goals:

- This document does not claim to hide leakage visible to the gateway or executor (they are in the TCB).
- This document does not claim to hide coarse system-level signals (host load, kernel scheduling, etc.).

---

## 1. Parties and Views

Parties:

- `G`: trusted gateway (runs the agent-facing MCP server and orchestrates PIR/MPC).
- `P0, P1`: policy servers (honest-but-curious; non-colluding for PIR privacy).
- `E`: executor (enforces side effects by verifying dual commit proofs).

For a single policy server `Pi`, define its **view** `View(Pi)` as the full transcript of:

1. **PIR/FSS traffic** to `/pir/*` endpoints:
   - URL path (endpoint), request/response sizes, timing.
   - JSON payload fields: `db`, per-subrequest `action_id`, and lists of `dpf_keys_b64`.
   - Returned `ans_shares` and per-subrequest MAC proofs (which include hashes such as `keys_sha256`, `resp_sha256`).
2. **MPC traffic** to `/mpc/*` endpoints:
   - `action_id`, `program_id`, `request_sha256`, circuit/gate metadata, `input_shares`.
   - Beaver triple shares sent by `G`, and opened values `d,e` returned by `G`.
   - Final per-server commit proof share (MAC) and output shares.

---

## 2. Security Goal: What We Want to Hide

The *privacy* goal against a single policy server is to hide:

- The agent's **intent category** (egress send/fetch/webhook vs skill install).
- The **logical DB name** being queried (recipients vs domains vs tokens vs IOCs vs install markers).
- The concrete **query indices** (recipient/domain/token strings, domains in SKILL.md, etc.).
- Message length within configured caps (e.g., token batch length) and other shape signals.

The *integrity* goal is handled separately (dual MAC proofs in `FORMAL_SECURITY.md`).

---

## 3. Modes and Their Leakage

### 3.1 Unshaped Mode (for comparison)

If the gateway issues minimal PIR queries per intent (different endpoints/DBs/batch sizes), then `View(Pi)` leaks:

- `intent_class` (from which DBs are queried and how many queries occur).
- Which logical DB was used (`db` field), if bundles are not used.
- Approximate message length (from the number of PIR keys), if token batches are not padded.

This is the baseline the paper's leakage evaluation compares against.

### 3.2 Oblivious Bundling + Unified Policy Program (Current Default)

Current implementation defaults to:

- **Oblivious bundle selection**: gateway queries only `db="policy_bundle"` and shifts indices inside the bundle.
- **Unified program id**: gateway uses a single `program_id` for multiple intent classes (default: `policy_unified_v1`).
- **Fixed-shape PIR plan per action**: each policy check uses a single bundled PIR query with a constant number of keys:

```
fixed_n_keys = 2 + max_tokens(dlp) + max_domains(ioc) + max_tokens(install)
            = 2 + 2*max_tokens + max_domains
```

This eliminates direct `intent_id` / logical-DB leakage from PIR transcript shape and from `program_id`.

### 3.3 Batch Mixing + Cover Traffic (Optional, Configurable)

When enabled (`PIR_MIX_ENABLED=1` with `PIR_MIX_PAD_TO>1` and `PIR_COVER_TRAFFIC=1`), the gateway:

- microbatches PIR subrequests and sends them via `/pir/query_batch_multi_signed`,
- pads each batch to a constant number of subrequests (`pad_to`) with dummy subrequests,
- emits dummy-only batches even when there are no real requests (cover traffic).

This further reduces leakage of *load shape* from PIR traffic (bursty vs steady; number of real subrequests).

Important implementation note:

- The current cover traffic implementation applies to **PIR**. MPC cover traffic is not implemented yet;
  therefore, the number and timing of `/mpc/*` sessions remain observable by `Pi`.

---

## 4. Allowed Leakage Function `L`

We define an explicit leakage function `L` for the policy server view. The point is not that `Pi` learns *nothing*,
but that the learned information is *constrained and deliberate*.

Let the global configuration be:

- `params = (domain_size, bundle_domain_size, fixed_n_keys, PIR_MIX_INTERVAL_MS, PIR_MIX_PAD_TO, program_id, MAC_TTL, ...)`.

Let the (possibly empty) sequence of gateway actions be:

- `A = [(a_1, I_1, x_1), ..., (a_T, I_T, x_T)]` where:
  - `a_t` is a gateway-generated `action_id`,
  - `I_t` is the intent category,
  - `x_t` are the secret inputs (recipient/domain/text/skill_md/...).

### 4.1 Leakage for PIR Channel (Unify + Mix + Cover)

Define `L_PIR(params, A)` as:

- The fixed endpoint name: `"/pir/query_batch_multi_signed"`.
- The fixed DB name: `db = "policy_bundle"`.
- The public schedule parameters: `(interval_ms, pad_to, fixed_n_keys)`.
- The number of ticks `N_ticks` that elapsed while the system was running.
- For each tick `k ∈ [1..N_ticks]`:
  - the multiset of **subrequest action ids** carried in that tick (real and dummy are indistinguishable),
  - and the fact that each subrequest contains exactly `fixed_n_keys` PIR keys.

Crucially, `L_PIR` does **not** reveal:

- which action ids are real vs dummy,
- any query indices,
- any logical DB name,
- the intent class.

### 4.2 Leakage for MPC Channel (Unified Program, No MPC Cover Yet)

Define `L_MPC(params, A)` as:

- The endpoint names used: `"/mpc/init"`, `"/mpc/and_mask_batch"`, `"/mpc/and_finish_batch"`, `"/mpc/finalize"`.
- The fixed `program_id` string.
- For each real action `a_t` (because MPC cover is not implemented):
  - the existence and timing of that MPC session,
  - `request_sha256(a_t)` as sent by the gateway,
  - the circuit size metadata (`n_wires`, `gates` length) which is constant under a fixed `program_id`,
  - the number of AND rounds and the set of AND gate indices per round (constant for the fixed circuit).

`L_MPC` does **not** reveal:

- intent class directly via `program_id` (unified),
- any plaintext predicate inputs (only XOR shares are sent),
- any PIR indices.

### 4.3 Full Allowed Leakage

The full leakage function is:

```
L(params, A) = (params, L_PIR(params, A), L_MPC(params, A))
```

This is the leakage target for any future simulation-style privacy argument about policy-server transcripts.

---

## 5. What Is Still Leaked (By Design or Not Yet Implemented)

Even in the strongest currently-implemented shaping mode, a single policy server still learns:

- The fact that MPC sessions occurred (action count / timing), since MPC cover traffic is not implemented.
- The values `request_sha256` (hashes) sent in MPC init; a determined server may attempt dictionary attacks
  if the underlying inputs are low-entropy. Mitigation would require a keyed commitment or a different binding design.
- Whether DFA confirm traffic occurred (if `DLP_MODE=dfa` and confirm is only run on the coarse-hit path).

These items must be treated as part of the explicit leakage model until mitigated.

---

## 6. Configuration Knobs (Gateway)

Relevant env vars (gateway-side):

- `UNIFIED_POLICY=1`: enable the unified policy program (`policy_unified_v1`) and unified PIR plan.
- `USE_POLICY_BUNDLE=1`: require bundled DB (`policy_bundle`) so `db_name` is hidden.
- `POLICY_BUNDLE_NAME=default`: bundle selection (oblivious; index shift only).
- `MIRAGE_POLICY_PROGRAM_ID=policy_unified_v1`: program id bound into commit proofs.

PIR mixing / cover traffic:

- `PIR_MIX_ENABLED=1`: enable PIR microbatching client.
- `PIR_MIX_INTERVAL_MS=50`: flush interval.
- `PIR_MIX_PAD_TO=1`: subrequests per tick; set `>1` to mix/pad (production).
- `PIR_COVER_TRAFFIC=0`: set to `1` to emit dummy-only ticks (production cover traffic).

Policy server backend note:

- Python policy server cannot sustain large `PIR_MIX_PAD_TO` with cover traffic. Use the Rust backend for production-scale shaping.

