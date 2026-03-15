# AgentDojo Five-Baseline Results (2026-03-14)

This document freezes the latest fair-comparison results for `AgentDojo v1.1.2` with model `gpt-4o-mini-2024-07-18` and attack family `important_instructions`.

## Final Fair Setting

- Benchmark: `AgentDojo v1.1.2`
- Model: `gpt-4o-mini-2024-07-18`
- Attack family: `important_instructions`
- Denominators:
  - benign rows: `97`
  - under_attack rows: `629`

## Five-System Overall Comparison

| System | Benign Utility | Under-Attack Utility | Under-Attack ASR |
|---|---:|---:|---:|
| Plain | 70.10% | 47.22% | 31.48% |
| IPIGuard | 64.95% | 51.99% | 15.26% |
| DRIFT | 59.79% | 52.78% | 2.38% |
| Faramesh | 60.82% | 47.69% | 22.89% |
| SecureClaw | 60.82% | 56.60% | 0.64% |

## Per-Suite Results

### Plain

| Suite | Benign Utility | Under-Attack Utility | Under-Attack ASR |
|---|---:|---:|---:|
| banking | 43.75% | 31.25% | 58.33% |
| slack | 80.95% | 54.29% | 42.86% |
| travel | 60.00% | 45.71% | 10.71% |
| workspace | 80.00% | 54.58% | 22.50% |

### IPIGuard

| Suite | Benign Utility | Under-Attack Utility | Under-Attack ASR |
|---|---:|---:|---:|
| banking | 43.75% | 48.61% | 0.69% |
| slack | 71.43% | 49.52% | 1.90% |
| travel | 70.00% | 28.57% | 66.43% |
| workspace | 67.50% | 68.75% | 0.00% |

### DRIFT

| Suite | Benign Utility | Under-Attack Utility | Under-Attack ASR |
|---|---:|---:|---:|
| banking | 56.25% | 50.00% | 4.86% |
| slack | 57.14% | 36.19% | 0.00% |
| travel | 50.00% | 61.43% | 3.57% |
| workspace | 67.50% | 56.67% | 1.25% |

### Faramesh

| Suite | Benign Utility | Under-Attack Utility | Under-Attack ASR |
|---|---:|---:|---:|
| banking | 43.75% | 43.06% | 15.97% |
| slack | 71.43% | 47.62% | 47.62% |
| travel | 50.00% | 43.57% | 7.86% |
| workspace | 67.50% | 52.92% | 25.00% |

### SecureClaw

| Suite | Benign Utility | Under-Attack Utility | Under-Attack ASR |
|---|---:|---:|---:|
| banking | 56.25% | 56.25% | 0.00% |
| slack | 71.43% | 57.14% | 2.86% |
| travel | 60.00% | 52.14% | 0.00% |
| workspace | 57.50% | 59.17% | 0.42% |

## Key Takeaways

- `SecureClaw` is the strongest overall point on the current fair AgentDojo comparison.
- It has the lowest overall ASR (`0.64%`) and the highest under-attack utility (`56.60%`).
- After replacing the old unfair `DRIFT workspace` result with a new fair rerun, `DRIFT` becomes the second-strongest baseline overall:
  - under-attack utility `52.78%`
  - under-attack ASR `2.38%`

## Important Note on DRIFT Workspace

An earlier `DRIFT workspace` result used an unfair denominator (`560` attack rows instead of the expected `240` for `v1.1.2`).

That old result is not used here.

The fair value used here comes from the clean rerun:

- `artifact_out_external_runtime/external_runs/20260314_drift_workspace_fair_rerun`

Its final `workspace` metrics are:

- benign utility `67.50%`
- under-attack utility `56.67%`
- under-attack ASR `1.25%`

## Source Paths

- Plain root:
  - `artifact_out_external_runtime/external_runs/20260302_agentdojo_native_plain_secureclaw_gpt4omini/plain`
- IPIGuard root:
  - `artifact_out_external_runtime/external_runs/20260301_external_full_rerun_gpt4omini/ipiguard`
- DRIFT roots:
  - `artifact_out_external_runtime/external_runs/20260301_external_full_rerun_gpt4omini/drift_workspace/runs/gpt-4o-mini-2024-07-18`
  - `artifact_out_external_runtime/external_runs/20260314_drift_workspace_fair_rerun/drift_workspace/runs/gpt-4o-mini-2024-07-18/workspace`
- Faramesh root:
  - `artifact_out_external_runtime/external_runs/20260304_agentdojo_four_parallel_rerun_v1/agentdojo_faramesh_only/faramesh`
- SecureClaw root:
  - `artifact_out_external_runtime/external_runs/20260313_secureclaw_benign_gate_live_20260313_190327/secureclaw`

