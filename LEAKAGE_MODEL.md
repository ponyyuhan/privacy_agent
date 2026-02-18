# Leakage Model (L(.)) for MIRAGE-OG++ (PIR + MPC + Confirm Path + Traffic Shaping)

This document defines two related leakage functions:

- `L_policy(.)`: what a **single policy server** learns from PIR/MPC transcripts.
- `L_sys(.)`: what the **full system** leaks across AgentLeak-style channels `C1..C7`.

`L_policy(.)` is used for single-server privacy claims.
`L_sys(.)` is used for end-to-end channel claims and evaluation reporting.

This is the artifact-accurate model corresponding to the current code:

- Gateway: `gateway/mcp_server.py`, `gateway/egress_policy.py`, `gateway/policy_unified.py`, `gateway/fss_pir.py`
- Policy servers: `policy_server/server.py`, `policy_server_rust/src/main.rs`
- Optional DFA confirm path: `gateway/guardrails.py:ObliviousGuardrails._dfa_match`

Non-goals:

- We do not attempt to hide leakage visible to the gateway or executor (they are in the TCB).
- We do not claim protection against host-level side channels (kernel scheduling, CPU contention, etc.).

---

## 0. System-Wide Leakage Function `L_sys(.)` (C1..C7)

For action sequence `A`, define:

```
L_sys(params, A) = (L_C1, L_C2, L_C3, L_C4, L_C5, L_C6, L_C7)
```

Per-channel leakage functions are:

- `L_C1 = (reason_code, patch_id, tx_id, |safe_text|, t_bucket)`
- `L_C2 = (from_agent, to_agent, msg_count, timing_bucket, payload_handle_ids)`
- `L_C3 = (intent_id_or_shadow_class, input_key_names, reason_code, t_bucket)`
- `L_C4 = (tool_status, tool_summary_len, output_handle_ids, t_bucket)`
- `L_C5 = (namespace, key_id, record_count, memory_handle_ids, t_bucket)`
- `L_C6 = (event_type, intent_id, caller_id, session_id, reason_code, input_key_names, hash_chain_meta)`
- `L_C7 = (skill_digest, ioc_hit_bit, install_marker_bit, reason_code, t_bucket)`

Here `t_bucket` is an explicitly coarse timing bucket (quantized latency / tick index),
not raw per-event wall-clock timestamps.

Channel-to-source decomposition (what mechanism contributes the leakage):

- `C1`: output gate + sanitize path + leakage budget accounting.
- `C2`: inter-agent handle bus + declassify gate + timing.
- `C3`: egress policy preview/commit (PIR + MPC + timing).
- `C4`: tool output handleization + optional declassify + timing.
- `C5`: memory service handleization + optional declassify + timing.
- `C6`: audit logger schema (metadata only).
- `C7`: skill ingress policy (IOC/install PIR + MPC + timing).

No channel is allowed to leak raw HIGH-sensitivity plaintext by default.

Leakage budgets:

- `LEAKAGE_BUDGET_C1..C7` define per-session/caller limits (default enforced for `C1/C2/C5`).
- Exceeding budget results in `LEAKAGE_BUDGET_EXCEEDED`.

Evaluation binding:

- `scripts/agentleak_channel_eval.py` reports per-channel block/leak/allow rates and writes:
  - `artifact_out/agentleak_eval/agentleak_channel_summary.json`
  - `artifact_out/agentleak_eval/agentleak_eval_rows.csv`

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

### 4.4 Timing / Scheduler Leakage

Define:

- `Delta` = configured tick interval (`PIR_MIX_INTERVAL_MS` / `MPC_MIX_INTERVAL_MS`),
- `P` = configured pad size (`*_PAD_TO`),
- `K` = number of ticks observed in window `T`,
- `J_k` = jitter bucket for tick `k` (coarsened arrival-time offset).

Then:

```
L_TIME(params, A) = (K, (J_1, ..., J_K), Delta, P, cover_flag)
```

Interpretation:

- with fixed schedule + cover traffic, server always sees constant-size ticks;
  only coarse timing jitter and fixed metadata remain.
- without cover traffic, server additionally learns an activity bit per tick
  (`real_work_present`), which is explicitly allowed leakage.

### 4.5 Unified Policy-Server Leakage Contract

For a single policy server:

```
L_policy(params, A) = (L_PIR, L_MPC, L_CONFIRM, L_TIME)
```

Residual leakage terms that remain explicit in the current artifact:

- `request_sha256` in MPC init (unkeyed commitment),
- confirm-path invocation bit when DFA is conditional,
- coarse timing jitter buckets.

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

---

## 8. Residual Leakage Upper Bounds and Validation

### 8.1 Upper-Bound Style Statements (Artifact Model)

- PIR/MPC index privacy:
  each single policy server receives only one DPF/FSS share; queried index leakage is bounded by the DPF security assumption (negligible distinguishing advantage).
- Bundled DB selection privacy:
  when `USE_POLICY_BUNDLE=1`, logical DB identity is hidden; server observes only bundled DB name (`policy_bundle`) and shifted indices.
- Fixed-shape scheduler leakage:
  with cover traffic enabled, per-tick request count is fixed to `P`; real-load leakage is reduced to timing coarse buckets `J_k` plus run length `K`.
- Confirm-path branch leakage:
  if DFA is conditional, one invocation bit per action may leak (`confirm_invoked`); with always-run DFA this term can be removed.

### 8.2 Experiment Mapping (How We Validate `L(.)`)

- Channel-level leakage/utility (`L_sys`, C1..C7):
  `scripts/agentleak_channel_eval.py`
  outputs `artifact_out/agentleak_eval/agentleak_channel_summary.json`.
- Official AgentLeak only defines channels `C1..C5`. For `C6/C7`, we use the repo's synthetic channel suite:
  `OUT_DIR=artifact_out_compare/leakage_sys_synth_v2 AGENTLEAK_CASESET=synthetic python scripts/agentleak_channel_eval.py`
  outputs `artifact_out_compare/leakage_sys_synth_v2/agentleak_eval/agentleak_channel_summary.json`.
- Fixed-shape traffic evaluation (`L_policy` timing/shaping terms):
  `scripts/bench_e2e_shaping_curves.py`
  outputs `artifact_out/shaping_perf/e2e_shaping_curves.json`.
- Policy-server single-host scaling and transport effects (implementation practicality under fixed leakage shape):
  `scripts/bench_policy_server_scaling.py`
  outputs `artifact_out/policy_perf/policy_server_scaling.json`.
- Policy-server distinguishability (explicit `L_policy` validation via MI / simple classifier):
  `scripts/leakage_model_sweep.py`
  outputs `artifact_out_compare/leakage_sweep/leakage_model_sweep.json`.

### 8.3 Current Empirical Snapshot (from this repo runs)

- Official AgentLeak full-case harness (`artifact_out_full_official_v3`):
  `mirage_full` achieves `attack_leak_rate=0.0` with `benign_allow_rate=1.0`
  under case-isolated context and benign confirm-aware evaluation.
- Official fair-baseline report (same cases, same seed, same metrics for MIRAGE + Codex + OpenClaw):
  `artifact_out_compare/fair_full_report.json` (see `systems.mirage_full`).
- Synthetic full-channel run (covers `C1..C7` including `C6/C7` not in the official dataset):
  `artifact_out_compare/leakage_sys_synth_v2/agentleak_eval/agentleak_channel_summary.json` shows `mirage_full` has `attack_leak_rate=0.0` for every channel.
  (This repo previously had a benign `C7` utility gap under case-isolated callers; it is fixed by adding an `artifact:*` caller rule in `gateway/capabilities.yaml`.)
- Fixed-shape + cover curve (`artifact_out_perf_v3/shaping_perf/e2e_shaping_curves.json`):
  `pad_to=2/4` keeps throughput near baseline while enforcing constant-shape ticks.
- Policy-server scaling (`artifact_out_perf_v3/policy_perf/policy_server_scaling.json`):
  Rust+binary path reaches near-2x key-throughput from 1 thread to 8 threads in this artifact setup.
- Policy-server intent distinguishability (`artifact_out_compare/leakage_sweep/leakage_model_sweep.json`):
  using 3 intent labels (`send/fetch/webhook`) and transcript features visible to a single policy server, the unshaped baseline has non-zero distinguishability
  (PIR MI ~= 0.414 bits, MAP accuracy ~= 0.514 vs chance 0.333), while shaped modes reduce MI to 0.0 for both PIR and MPC under this feature set.
