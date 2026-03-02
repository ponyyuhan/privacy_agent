# Multi-Track Agent Security Evaluation (2026-02-20)

## Scope

This report keeps the existing main comparison and adds:

1. Privacy leakage track: AgentLeak / MAGPIE / TOP-Bench mapping.
2. Injection robustness track: AgentDojo / ASB / WASP / VPI-Bench mapping.
3. Protocol implementation track: MCP/A2A attack-surface tests.

Defense baselines added (without anti-leak prompt tuning):
- `codex_drift`
- `codex_ipiguard`
- `codex_agentarmor`

Primary outputs:
- `artifact_out_compare_noprompt/fair_full_report.json`
- `artifact_out_compare_noprompt/stats/fair_full_stats.json`
- `artifact_out_compare_noprompt/multi_track_eval.json`

## Main Comparison (kept unchanged)

Official C1..C5, same manifest (`n_attack=744`, `n_benign=2520`):

| System | Attack leak | Attack block | Benign allow | Hard deny FP | Availability fail |
|---|---:|---:|---:|---:|---:|
| `mirage_full` | 0.0000 | 1.0000 | 0.8000 | 0.2000 | 0.0000 |
| `codex_native` | 0.0161 | 0.9839 | 1.0000 | 0.0000 | 0.0000 |
| `openclaw_native` | 0.0148 | 0.9852 | 0.0000 | 0.0000 | 1.0000 |

Notes:
- OpenClaw run quality was affected by provider quota / parse failures (`BLOCK_ERROR:parse_failed`); in this run benign collapse is fully attributed to availability, not hard policy deny.

## Added Defense Baselines

| System | Attack leak | Attack block | Benign allow | Hard deny FP |
|---|---:|---:|---:|---:|
| `codex_drift` | 0.0134 | 0.9866 | 1.0000 | 0.0000 |
| `codex_ipiguard` | 0.0161 | 0.9839 | 1.0000 | 0.0000 |
| `codex_agentarmor` | 0.0134 | 0.9866 | 0.9484 | 0.0516 |

Significance vs `mirage_full` (`artifact_out_compare_noprompt/stats/fair_full_stats.json`):
- `codex_drift` attack leak: `p=0.00189`
- `codex_ipiguard` attack leak: `p=0.000467`
- `codex_agentarmor` attack leak: `p=0.00189`
- `openclaw_native` benign hard-deny vs `mirage_full`: `p=2.64e-164`

## Track Status

1. Privacy leakage track:
   - Local primary eval completed from `fair_full_report.json`.
   - Includes main comparison + defense baselines.
2. Injection robustness track:
   - Local proxy eval completed on the same official attack subset.
   - External benchmark real-run report integrated:
     `artifact_out_external_runtime/external_runs/20260220_fullpipeline/external_benchmark_unified_report.json`
   - ASB is run-tag isolated (`requested_run_tag=20260220_official`, all three files `selection=run_tag_exact`, `rows=400` each).
   - DRIFT rows are sourced from the same external run root (`drift_total_files=100`).
   - IPIGuard in this run root is currently missing (`ipiguard_total_rows=0`), and is explicitly surfaced in `multi_track_eval.json` as part of `external_real_run.snapshot`.
3. Protocol implementation track:
   - `pytest -q tests/test_mcp_gateway.py tests/test_delegation_and_dual_principal.py tests/test_federated_auth.py tests/test_security_games.py`
   - Result: `15 passed`
   - `scripts/multi_agent_federated_eval.py` output generated at:
     `artifact_out_compare_noprompt/multi_agent_federated_eval.json`

## Open-source baseline integration status

- DRIFT official code integrated at: `third_party/DRIFT` (GitHub: `SaFo-Lab/DRIFT`).
- In this environment, direct upstream DRIFT pipeline execution requires additional dependencies and API credentials.
- Current comparable baseline results are produced via the repository-integrated
  **official-equivalent, oracle-free** runtime defense mode:
  `scripts/native_official_baseline_eval.py --defense drift|ipiguard|agentarmor`.
- Oracle-free contract:
  - no dataset truth label (`kind`) in defense decisions,
  - no payload oracle fields (`token`, `secret_field`) in sink cleaning decisions.
