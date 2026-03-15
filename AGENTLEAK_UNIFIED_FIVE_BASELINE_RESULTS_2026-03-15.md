# AgentLeak Unified Five-Baseline Results (2026-03-15)

This document merges the current `AgentLeak` five-baseline results in this workspace.

The five systems are:

1. `Plain`
2. `IPIGuard`
3. `DRIFT`
4. `Faramesh`
5. `SecureClaw`

## Scope and Fairness Notes

This unified summary combines:

- `C1/C2/C5`:
  - official parity-style multi-agent lane
  - includes utility
  - source:
    - `AGENTLEAK_PARITY_FIVE_BASELINE_RESULTS_2026-03-15.md`
- `C3/C4/C6`:
  - channel-level comparison lanes
  - source:
    - `AGENTLEAK_CHANNEL_FIVE_BASELINE_PROGRESS_2026-03-14.md`

Important caveats:

- The tables below are replacement compositions:
  - `Plain` / `Faramesh` / `SecureClaw` remain from the earlier completed five-baseline runs
  - `IPIGuard` / `DRIFT` are replaced with the native/original AgentLeak reruns completed on `2026-03-15`
- `C3` and `C4` are official dataset-mode channel comparisons.
- `C6` is an extension lane, not an official standalone IEEE lane.
- `C7` is not included because the reproducible package in this workspace does not expose it as a comparable standalone lane.
- `Faramesh` is evaluated through a real local runtime, not a stub.
- `SecureClaw` is evaluated as the full system: gateway + dual policy servers + executor boundary.
- `IPIGuard` and `DRIFT` are now **native/original** AgentLeak integrations on top of their original control logic; the older equivalent/oracle-free AgentLeak-side numbers should no longer be cited.
- Native reruns were sharded and merged. After OpenAI quota exhaustion, the remaining native calls were resumed through an OpenRouter-compatible OpenAI endpoint with the same model id `gpt-4o-mini-2024-07-18`.

## A. Main Parity Lane: `C1/C2/C5`

Setting:

- Native replacement report:
  - `artifact_out_compare_noprompt/20260315_agentleak_c125_native_ipiguard_drift_sharded_v1_merged/paper_parity_agentleak_eval/paper_parity_report.json`
- Unchanged `Plain` / `Faramesh` / `SecureClaw` source:
  - `artifact_out_compare_noprompt/20260314_agentleak_c125_parity_five_baselines_v1/paper_parity_agentleak_eval/paper_parity_report.json`
- Denominators:
  - total scenarios: `996`
  - benign scenarios: `500`
  - attack scenarios: `496`

Metrics:

- `Benign Leak` = benign `scenario_or_leak_rate`
- `Attack ASR` = attack `scenario_or_leak_rate`
- `Utility Success` and `Utility Score` use the official strict evaluator path

| System | Overall Utility Success | Overall Utility Score | Benign Leak | Attack ASR |
|---|---:|---:|---:|---:|
| Plain | 77.51% | 0.7176 | 91.60% | 93.95% |
| IPIGuard | 76.31% | 0.7460 | 76.00% | 78.63% |
| DRIFT | 68.27% | 0.6874 | 69.80% | 72.18% |
| Faramesh | 77.51% | 0.7176 | 91.60% | 93.95% |
| SecureClaw | 75.80% | 0.6746 | 15.20% | 15.12% |

### Attack Utility / ASR

| System | Attack Utility Success | Attack Utility Score | Attack ASR |
|---|---:|---:|---:|
| Plain | 77.02% | 0.7129 | 93.95% |
| IPIGuard | 76.21% | 0.7492 | 78.63% |
| DRIFT | 67.94% | 0.6858 | 72.18% |
| Faramesh | 77.02% | 0.7129 | 93.95% |
| SecureClaw | 74.60% | 0.6681 | 15.12% |

### Attack Per-Channel Leak Rates

| System | C1 Leak | C2 Leak | C5 Leak |
|---|---:|---:|---:|
| Plain | 33.47% | 92.74% | 51.61% |
| IPIGuard | 56.25% | 50.00% | 57.06% |
| DRIFT | 51.21% | 47.98% | 53.63% |
| Faramesh | 33.47% | 92.74% | 51.61% |
| SecureClaw | 15.12% | 0.00% | 0.00% |

## B. Channel Lane: `C3` Official

Setting:

- Native replacement report:
  - `artifact_out_compare_noprompt/20260315_agentleak_c3_native_ipiguard_drift_sharded_v1_merged/report.json`
- Unchanged `Plain` / `Faramesh` / `SecureClaw` source:
  - `artifact_out_compare_noprompt/20260314_agentleak_c3_official_five_baselines_v2/report.json`
- Denominators:
  - attack: `129`
  - benign: `504`

| System | Attack Block Rate | Attack Leak Rate | Benign Allow Rate |
|---|---:|---:|---:|
| Plain | 0.00% | 100.00% | 100.00% |
| IPIGuard | 75.97% | 24.03% | 100.00% |
| DRIFT | 93.02% | 6.98% | 99.21% |
| Faramesh | 0.00% | 100.00% | 100.00% |
| SecureClaw | 100.00% | 0.00% | 100.00% |

## C. Channel Lane: `C4` Official

Setting:

- Native replacement report:
  - `artifact_out_compare_noprompt/20260315_agentleak_c4_native_ipiguard_drift_sharded_v1_merged/report.json`
- Unchanged `Plain` / `Faramesh` / `SecureClaw` source:
  - `artifact_out_compare_noprompt/20260314_agentleak_c4_official_five_baselines_v2/report.json`
- Denominators:
  - attack: `122`
  - benign: `504`

| System | Attack Block Rate | Attack Leak Rate | Benign Allow Rate |
|---|---:|---:|---:|
| Plain | 0.00% | 100.00% | 100.00% |
| IPIGuard | 66.39% | 33.61% | 100.00% |
| DRIFT | 85.25% | 14.75% | 99.80% |
| Faramesh | 0.00% | 100.00% | 100.00% |
| SecureClaw | 100.00% | 0.00% | 100.00% |

## D. Channel Lane: `C6` Extension

Setting:

- Native replacement report:
  - `artifact_out_compare_noprompt/20260315_agentleak_c6_native_ipiguard_drift_sharded_v1_merged/report.json`
- Unchanged `Plain` / `Faramesh` / `SecureClaw` source:
  - `artifact_out_compare_noprompt/20260314_agentleak_c6_synth_five_baselines_v2/report.json`
- Denominators:
  - attack: `1000`
  - benign: `1000`

| System | Attack Block Rate | Attack Leak Rate | Benign Allow Rate |
|---|---:|---:|---:|
| Plain | 0.00% | 100.00% | 100.00% |
| IPIGuard | 100.00% | 0.00% | 100.00% |
| DRIFT | 100.00% | 0.00% | 98.90% |
| Faramesh | 0.00% | 100.00% | 100.00% |
| SecureClaw | 100.00% | 0.00% | 99.90% |

## Cross-Lane Takeaways

- `SecureClaw` remains the strongest overall privacy point across the currently available `AgentLeak` coverage in this workspace.
- On the main `C1/C2/C5` parity lane:
  - `SecureClaw` keeps the best privacy by a large margin
  - native `IPIGuard` improves meaningfully over `Plain` / `Faramesh`
  - native `DRIFT` is more privacy-conservative than native `IPIGuard`, but pays more utility
- On `C3`:
  - native `DRIFT` is much stronger than native `IPIGuard`
  - `SecureClaw` still dominates with `100%` block and `100%` benign allow
- On `C4`:
  - native `DRIFT` again clearly outperforms native `IPIGuard`
  - `SecureClaw` still fully blocks attacks while keeping `100%` benign allow
- On `C6`:
  - native `IPIGuard` and native `DRIFT` both fully block attacks
  - native `IPIGuard` keeps `100%` benign allow
  - native `DRIFT` keeps `98.90%` benign allow
- The old equivalent/oracle-free AgentLeak-side `IPIGuard` / `DRIFT` numbers materially overstated channel protection and should be treated as superseded.

## Source Paths

- `C1/C2/C5` parity:
  - native replacement:
  - `artifact_out_compare_noprompt/20260315_agentleak_c125_native_ipiguard_drift_sharded_v1_merged/paper_parity_agentleak_eval/paper_parity_report.json`
  - unchanged old five-baseline source:
    - `artifact_out_compare_noprompt/20260314_agentleak_c125_parity_five_baselines_v1/paper_parity_agentleak_eval/paper_parity_report.json`
- `C3` official:
  - native replacement:
  - `artifact_out_compare_noprompt/20260315_agentleak_c3_native_ipiguard_drift_sharded_v1_merged/report.json`
  - unchanged old five-baseline source:
    - `artifact_out_compare_noprompt/20260314_agentleak_c3_official_five_baselines_v2/report.json`
- `C4` official:
  - native replacement:
  - `artifact_out_compare_noprompt/20260315_agentleak_c4_native_ipiguard_drift_sharded_v1_merged/report.json`
  - unchanged old five-baseline source:
    - `artifact_out_compare_noprompt/20260314_agentleak_c4_official_five_baselines_v2/report.json`
- `C6` extension:
  - native replacement:
  - `artifact_out_compare_noprompt/20260315_agentleak_c6_native_ipiguard_drift_sharded_v1_merged/report.json`
  - unchanged old five-baseline source:
    - `artifact_out_compare_noprompt/20260314_agentleak_c6_synth_five_baselines_v2/report.json`
