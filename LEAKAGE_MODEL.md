# Leakage Model (L(.)) for MIRAGE-OG++ (PIR + MPC + Confirm Path + Traffic Shaping)

This document defines a **paper-citable** leakage function `L(.)` for what a *single*
policy server learns from its transcript in MIRAGE-OG++.

This is the artifact-accurate model corresponding to the current code:

- Gateway: `gateway/mcp_server.py`, `gateway/egress_policy.py`, `gateway/policy_unified.py`, `gateway/fss_pir.py`
- Policy servers: `policy_server/server.py`, `policy_server_rust/src/main.rs`
- Optional DFA confirm path: `gateway/guardrails.py:ObliviousGuardrails._dfa_match`

Non-goals:

- We do not attempt to hide leakage visible to the gateway or executor (they are in the TCB).
- We do not claim protection against host-level side channels (kernel scheduling, CPU contention, etc.).

---

## 1. Parties and Views

Parties:

- `G`: trusted gateway.
- `P0, P1`: policy servers (honest-but-curious; non-colluding for privacy).
- `E`: executor (trusted effect gate; not part of SAP leakage).

For a single policy server `Pi`, define its transcript view `View(Pi)` as everything it observes on inbound HTTP:

- request path (endpoint), headers, and body fields,
- response sizes and timings,
- any local computation-time variability (not explicitly modeled unless noted).

We partition the transcript into channels:

- PIR bit queries (DPF/FSS): `/pir/query_batch_signed`, `/pir/query_batch_multi_signed`, etc.
- PIR block queries (DFA confirm): `/pir/query_block_batch_signed` (repeated per DFA step).
- MPC policy evaluation: `/mpc/init`, `/mpc/and_*`, `/mpc/finalize`.

---

## 2. Secrets We Aim to Hide (Against a Single Policy Server)

Against one policy server, we aim to hide:

- The **queried identity**: recipient/domain/token/IOC index being tested.
- The **intent category**: egress send vs fetch vs webhook vs skill install (and any finer category).
- The **logical DB name** (recipient allowlist vs IOC vs DLP tokens vs install markers), when bundling is enabled.
- Action load shape (bursts vs idle) to the extent allowed by shaping mode.

Integrity (preventing bypass) is handled separately in `FORMAL_SECURITY.md` and is not part of `L(.)`.

---

## 3. Public Parameters (Configuration) and Action Sequence

Let public configuration parameters be:

- `domain_size`, `bundle_domain_size`
- `program_id` (fixed string in unified mode)
- `fixed_n_keys` (constant #keys per PIR subrequest in unified plan)
- PIR shaping: `PIR_MIX_INTERVAL_MS`, `PIR_MIX_PAD_TO`, `PIR_COVER_TRAFFIC`
- MPC shaping: `MPC_MIX_INTERVAL_MS`, `MPC_MIX_PAD_TO`, `MPC_COVER_TRAFFIC`, `MPC_MIX_MULTI_ENDPOINTS`
- `POLICY_MAC_TTL_S` (freshness)
- DFA params (if enabled): `MAX_DFA_SCAN_CHARS`, `PAD_DFA_STEPS`, `block_size`

Let the secret action sequence be:

- `A = [(a_1, I_1, x_1), ..., (a_T, I_T, x_T)]`,
  where `a_t` is an `action_id`, `I_t` is the intent category, and `x_t` are sensitive inputs (recipient/domain/text/skill_md/...).

---

## 4. Leakage Function L(.)

We define an explicit leakage function:

```
L(params, A) = (params, L_PIR(params, A), L_MPC(params, A), L_CONFIRM(params, A))
```

Where each component captures exactly the information a single policy server learns from that channel *under the configured shaping mode*.

### 4.1 PIR Bit-Query Leakage (DPF/FSS)

Mechanisms:

- Two-server DPF/FSS hides the queried index from each server (cryptographic assumption).
- Oblivious bundling (`USE_POLICY_BUNDLE=1`) uses a single DB name `policy_bundle` and shifts indices inside the bundle.
- Unified fixed-shape plan uses a constant number of keys per action (`fixed_n_keys`).
- Optional gateway-side microbatching + padding + cover traffic uses constant-shape ticks via `/pir/query_batch_multi_signed`.

Define `L_PIR(params, A)` as:

- The endpoint(s) used (`/pir/query_batch_signed` or `/pir/query_batch_multi_signed`).
- The DB name(s) observed (in full mode, a single bundled db such as `policy_bundle`).
- The shaping schedule parameters `(interval_ms, pad_to, fixed_n_keys)`.
- For each PIR tick `k`:
  - the fact that exactly `pad_to` subrequests were sent (some may be dummy),
  - the multiset of `action_id` values included in that tick (random tokens; dummy and real have the same shape),
  - and that each subrequest contains exactly `fixed_n_keys` DPF keys.

Crucially, `L_PIR` does **not** reveal:

- which subrequests are real vs dummy,
- any queried indices (DPF security),
- logical DB selection (when bundled),
- intent category (when unified plan is used).

### 4.2 MPC Leakage (Policy Circuit Evaluation)

Mechanisms:

- Inputs are XOR-secret-shared; a single server sees only shares.
- Unified program uses a constant circuit and a constant `program_id`.
- Optional MPC microbatching + padding + cover traffic runs constant-shape ticks of MPC sessions.

Define `L_MPC(params, A)` as:

- The endpoint names used (subset of `/mpc/init`, `/mpc/and_mask_*`, `/mpc/and_finish_*`, `/mpc/finalize`).
- The public `program_id`.
- The shaping schedule parameters `(interval_ms, pad_to, cover_traffic, multi_endpoints)`.
- Circuit shape metadata visible to the server (e.g., `n_wires`, `n_gates`, and AND-round structure), which is constant for a fixed program.
- For each MPC tick:
  - the fact that exactly `pad_to` sessions are executed (some may be dummy),
  - the multiset of `action_id` values included in that tick.

Under MPC cover traffic, `L_MPC` does **not** reveal:

- how many *real* actions occurred in that interval (only constant tick shape),
- intent category via circuit shape (circuit is fixed in unified mode),
- any plaintext predicate inputs (only one-time shares).

Residual exposure (explicitly allowed unless mitigated):

- `request_sha256` is sent in `/mpc/init`. It is a hash commitment, but unkeyed; low-entropy guessing attacks are possible in principle.

### 4.3 Confirm-Path Leakage (DFA / Block PIR)

If DFA confirm is enabled (`DLP_MODE=dfa`), the gateway may perform a DFA scan using PIR **block** queries.

Current artifact behavior (important):

- The DFA scan is **conditional** in some paths: it may run only when a coarse filter hits.
- The scan performs up to `MAX_DFA_SCAN_CHARS` steps, optionally padded with `PAD_DFA_STEPS=1`.

Define `L_CONFIRM(params, A)` as:

- Whether a DFA scan was invoked for an action (branch leakage, if conditional).
- The number of DFA steps executed (unless padded).
- The DFA endpoint and block size (public).

Mitigation knobs:

- `PAD_DFA_STEPS=1` makes the number of steps constant (still does not hide whether the scan was invoked unless the system always runs it).
- A stronger constant-shape design would always run DFA scans (possibly with cover traffic), but this is expensive and not the default in the artifact.

---

## 5. Modes (What Changes in L(.))

This repo supports several configurations. Reviewer-relevant ones:

- **Unshaped**: intent/db/length leak via endpoint/DB choice and batch sizes.
- **Bundled + Unified (default full mode)**: hides logical DB name and intent category from PIR/MPC structure.
- **+ PIR mixing/padding/cover**: reduces load-shape leakage at PIR channel.
- **+ MPC mixing/padding/cover**: reduces load-shape leakage at MPC channel.
- **DFA confirm**: introduces additional block-query leakage unless padded/always-run.

---

## 6. Configuration Knobs (Gateway)

Unified policy + bundling:

- `UNIFIED_POLICY=1`
- `USE_POLICY_BUNDLE=1`
- `MIRAGE_POLICY_PROGRAM_ID=policy_unified_v1`

PIR mixing / cover:

- `PIR_MIX_ENABLED=1`
- `PIR_MIX_INTERVAL_MS=50`
- `PIR_MIX_PAD_TO=1` (set >1 to mix/pad)
- `PIR_COVER_TRAFFIC=0` (set 1 for dummy-only ticks)

MPC mixing / cover:

- `MPC_MIX_ENABLED=0` (set 1 to enable constant-shape MPC ticks)
- `MPC_MIX_INTERVAL_MS=50`
- `MPC_MIX_PAD_TO=1` (set >1 to mix/pad)
- `MPC_COVER_TRAFFIC=0` (set 1 for dummy-only ticks)
- `MPC_MIX_MULTI_ENDPOINTS=1` (use `/mpc/and_*_multi`)

DFA padding:

- `DLP_MODE=dfa`
- `MAX_DFA_SCAN_CHARS=256`
- `PAD_DFA_STEPS=1` (constant steps)

---

## 7. What Is Still Leaked (Explicitly)

Even in the strongest implemented shaping mode, a single policy server may still learn:

- coarse system timing signals (tick-to-tick jitter),
- `request_sha256` values used in MPC init (hash commitments),
- any confirm-path invocation (unless always-run),
- host-level side channels not modeled by `L(.)`.

This is intentional: `L(.)` is the contract of what we *allow* to leak; anything not mitigated is treated as explicit leakage until addressed.

