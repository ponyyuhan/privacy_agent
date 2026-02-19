# SecureClaw Leakage Model

This document defines the leakage contract used by SecureClaw claims.
It specifies allowed leakage functions and maps each term to implementation paths and configuration switches.

Two leakage levels are defined:

1. `L_policy` for one policy server transcript privacy.
2. `L_sys` for end-to-end application channels `C1..C7`.

## 1. Scope and Adversary View

### 1.1 Parties

1. `G` trusted gateway.
2. `P0`, `P1` policy servers.
3. `X` trusted executor.
4. `A` adversarial runtime and skill code.

### 1.2 Views

Policy leakage view:

`View(Pi)` is the complete HTTP transcript visible to a single policy server `Pi`, including endpoint names, body fields, message sizes, and coarse timing.

System leakage view:

`View_sys(A)` is what adversarial runtime and connected channels can observe through outputs, handles, logs, and timing metadata.

### 1.3 Non-Goals

1. No claim for leakage to trusted `G` and `X`.
2. No claim for kernel and hardware side channels.
3. No claim when both policy servers collude.

## 2. Unified Leakage Definitions

For action trace `W`, define:

`L_sys(params, W) = (L_C1, L_C2, L_C3, L_C4, L_C5, L_C6, L_C7)`

`L_policy(params, W) = (L_PIR, L_MPC, L_CONFIRM, L_TIME)`

Each `L_*` below is an allowlist function.
Any observed signal outside this allowlist is considered leakage violation.

## 3. Policy-Server Leakage `L_policy`

### 3.1 `L_PIR`

Allowed terms:

1. Endpoint class in use.
2. Public domain size and public key count shape.
3. Bundled database name if bundling is enabled.
4. Tick schedule parameters and padded batch size per tick.
5. Coarse tick identity and opaque action batching tokens.

Forbidden terms:

1. True queried index.
2. Logical unbundled db identity when bundling is enabled.
3. Intent category if unified route is enabled.

Primary code paths:

1. `gateway/fss_pir.py`
2. `gateway/router.py`
3. `policy_server/server.py`
4. `policy_server_rust/src/main.rs`

Primary switches:

1. `USE_POLICY_BUNDLE`
2. `UNIFIED_POLICY`
3. `PIR_MIX_ENABLED`
4. `PIR_MIX_PAD_TO`
5. `PIR_COVER_TRAFFIC`
6. `PIR_MIX_INTERVAL_MS`

### 3.2 `L_MPC`

Allowed terms:

1. Fixed MPC endpoint class.
2. Public `program_id`.
3. Circuit shape metadata.
4. Tick schedule metadata and padded session count.
5. Coarse timing and batch occupancy at padded shape.

Forbidden terms:

1. Plaintext predicate inputs.
2. Intent identity through circuit shape when unified circuit is used.

Primary code paths:

1. `gateway/policy_unified.py`
2. `gateway/egress_policy.py`
3. `policy_server/server.py`
4. `policy_server_rust/src/main.rs`

Primary switches:

1. `MIRAGE_POLICY_PROGRAM_ID`
2. `MPC_MIX_ENABLED`
3. `MPC_MIX_PAD_TO`
4. `MPC_COVER_TRAFFIC`
5. `MPC_MIX_INTERVAL_MS`
6. `MPC_MIX_MULTI_ENDPOINTS`

### 3.3 `L_CONFIRM`

Allowed terms:

1. Confirm path invocation marker if confirm path is conditional.
2. Confirm scan step count after any configured padding.
3. Public DFA and block parameters.

Forbidden terms:

1. Raw secret text scanned by confirm path.

Primary code paths:

1. `gateway/guardrails.py`
2. `gateway/mcp_server.py`
3. `policy_server/server.py` block PIR endpoints

Primary switches:

1. `DLP_MODE`
2. `MAX_DFA_SCAN_CHARS`
3. `PAD_DFA_STEPS`

### 3.4 `L_TIME`

Allowed terms:

1. Coarsened timing bucket per tick.
2. Number of observed ticks in a window.
3. Public scheduler parameters.

Forbidden terms:

1. Fine-grained per-request timestamps beyond bucket precision.

Primary code paths:

1. `gateway/fss_pir.py` mixer scheduling
2. `gateway/policy_unified.py` MPC mixer scheduling

Primary switches:

1. `PIR_MIX_INTERVAL_MS`
2. `MPC_MIX_INTERVAL_MS`
3. `PIR_COVER_TRAFFIC`
4. `MPC_COVER_TRAFFIC`

## 4. System Leakage `L_sys` by Channel

### 4.1 Allowed Leakage Function Table

| Channel | Allowed leakage `L_Ci` | Main source | Primary code path | Primary controls |
|---|---|---|---|---|
| `C1` final output | `(reason_code, tx_id, patch_id, output_len_bucket, timing_bucket)` | final response gate and sanitize path | `gateway/mcp_server.py`, `gateway/egress_policy.py` | `LEAKAGE_BUDGET_C1`, sanitize policy bits |
| `C2` inter-agent messages | `(from_agent, to_agent, msg_count_bucket, handle_ids, timing_bucket)` | handle bus and routing metadata | `gateway/router.py`, `gateway/handles.py` | `LEAKAGE_BUDGET_C2`, handle TTL and bindings |
| `C3` tool inputs | `(intent_shadow_or_id, input_key_names, reason_code, timing_bucket)` | preview and route metadata | `gateway/mcp_server.py`, `gateway/policy_unified.py` | `UNIFIED_POLICY`, `USE_POLICY_BUNDLE` |
| `C4` tool outputs | `(tool_status, summary_len_bucket, output_handle_ids, timing_bucket)` | tool wrapper response metadata | `gateway/executors/fsexec.py`, `gateway/executors/webexec.py`, `gateway/executors/httpexec.py` | handleization path, declass policy |
| `C5` memory | `(namespace, key_id, record_count_bucket, memory_handle_ids, timing_bucket)` | memory API metadata | `gateway/executors/memoryexec.py`, `gateway/handles.py` | `LEAKAGE_BUDGET_C5`, handle constraints |
| `C6` logs and audit | `(event_type, caller_id, session_id, reason_code, req_hash_meta, hash_chain_meta)` | structured audit pipeline | `gateway/audit.py`, `executor_server/server.py` | audit schema and hash-chain policy |
| `C7` skill ingress | `(skill_digest, ioc_hit_bit, install_marker_bit, reason_code, timing_bucket)` | skill policy ingress checks | `gateway/mcp_server.py`, `gateway/policy_unified.py`, `gateway/capabilities.yaml` | skill install policy, IOC db, caller capability |

### 4.2 Forbidden Cross-Channel Leakage

Forbidden by default for all channels:

1. Raw high-sensitivity plaintext values.
2. Unapproved secret declassification.
3. Unsanitized tool output bypassing handle path.

Allowed only via explicit policy path:

1. User-confirmed declassification events.
2. Approved output transforms recorded in audit.

## 5. Leakage Function to Code Mapping

### 5.1 Global Mapping Table

| Leakage term | Meaning | Code path | Config and spec anchor |
|---|---|---|---|
| `request_sha256` visibility | hash commitment in MPC init | `gateway/policy_unified.py`, `policy_server/server.py` | request hash canonicalization in `common/canonical.py` |
| `program_id` | fixed policy circuit id | `gateway/policy_unified.py`, `executor_server/server.py` | `MIRAGE_POLICY_PROGRAM_ID`, `spec/secureclaw_accept_predicate_v1.json` |
| `commit outputs bits` | allow and confirm semantics | `policy_server/server.py`, `executor_server/server.py` | `required_output_keys` in accept spec |
| `batch shape` | padded per-tick request counts | `gateway/fss_pir.py`, `gateway/policy_unified.py` | `PIR_*`, `MPC_*` mixer switches |
| `confirm branch metadata` | DFA invocation and step shape | `gateway/guardrails.py` | `DLP_MODE`, `PAD_DFA_STEPS` |
| `reason_code` | denial and decision class | `gateway/mcp_server.py`, `executor_server/server.py` | reason-code registry in protocol RFC |
| `audit hash chain metadata` | append-only linkage info | `gateway/audit.py` | audit persistence policy |
| `skill digest and IOC bit` | skill ingress risk signal | `gateway/policy_unified.py`, skill install route | IOC and install marker policy db |

### 5.2 Leakage Budget Controls

Leakage budgets enforce bounded disclosure for selected channels.
Budget exceedance must map to explicit deny code.

Code path:

1. `gateway/leakage_budget.py`

Typical switches:

1. `LEAKAGE_BUDGET_C1`
2. `LEAKAGE_BUDGET_C2`
3. `LEAKAGE_BUDGET_C5`

## 6. Residual Leakage Contract

Residual terms explicitly allowed in current artifact:

1. Coarse scheduler timing buckets.
2. Confirm-path invocation bit when confirm path is conditional.
3. Unkeyed hash commitment observability in MPC initialization.

Residual terms not allowed but out of model:

1. Kernel-level scheduling and cache channels.
2. Host-level side channels outside process model.

## 7. Expected Distinguishability Behavior

With shaping disabled:

1. Intent and workload shape can be distinguishable from endpoint and batch metadata.

With unified bundle and fixed-shape mixers enabled:

1. Distinguishability from transcript features should collapse toward chance under defined feature space.
2. Remaining distinguishability should be attributable to allowed residual terms in Section 6.

## 8. Validation and Reproducibility Hooks

### 8.1 Channel-Level Evaluation

Script:

1. `scripts/agentleak_channel_eval.py`

Artifacts:

1. `artifact_out/agentleak_eval/agentleak_channel_summary.json`
2. `artifact_out/agentleak_eval/agentleak_eval_rows.csv`

### 8.2 Leakage Distinguishability Sweep

Script:

1. `scripts/leakage_model_sweep.py`

Artifact:

1. `artifact_out_compare/leakage_sweep/leakage_model_sweep.json`

### 8.3 Shaping Performance Under Fixed Leakage Shape

Scripts:

1. `scripts/bench_e2e_shaping_curves.py`
2. `scripts/bench_policy_server_scaling.py`

Artifacts:

1. `artifact_out/shaping_perf/e2e_shaping_curves.json`
2. `artifact_out/policy_perf/policy_server_scaling.json`

## 9. Configuration Profiles

### 9.1 Stronger Leakage-Hiding Profile

1. `UNIFIED_POLICY=1`
2. `USE_POLICY_BUNDLE=1`
3. `PIR_MIX_ENABLED=1`
4. `PIR_MIX_PAD_TO>=2`
5. `PIR_COVER_TRAFFIC=1`
6. `MPC_MIX_ENABLED=1`
7. `MPC_MIX_PAD_TO>=2`
8. `MPC_COVER_TRAFFIC=1`
9. `PAD_DFA_STEPS=1`

### 9.2 Lower-Overhead Profile

1. Keep unified bundle.
2. Reduce padding sizes.
3. Disable cover traffic if throughput is critical.
4. Explicitly document resulting increase in allowed leakage terms.

## 10. Claim Boundary

Claimed SAP statement:

For each single policy server, transcripts are simulatable from `L_policy` under PIR and MPC assumptions and configured shaping constraints.

Claimed end-to-end leakage statement:

Application-level runtime-observable leakage is bounded by `L_sys` tables above, subject to the same trust and non-goal assumptions.

