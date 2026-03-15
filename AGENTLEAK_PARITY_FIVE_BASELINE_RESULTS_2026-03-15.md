# AgentLeak Parity Five-Baseline Results (2026-03-15)

This document freezes the `AgentLeak` official parity-lane comparison over `C1/C2/C5`.

On `2026-03-15`, the earlier AgentLeak-side `IPIGuard` / `DRIFT` numbers were replaced with **native/original integrations**:

- `IPIGuard`: original `AgentPipeline(... defense="ipiguard")` control logic
- `DRIFT`: original `DRIFTLLM + DRIFTToolsExecutionLoop` control logic
- both are connected to AgentLeak through a local adapter layer, not the old equivalent/oracle-free text transform

The run uses:

- Benchmark lane: `AgentLeak official parity (C1/C2/C5)`
- Generator model id: `gpt-4o-mini-2024-07-18`
- Utility metric: official `strict_evaluator`-based TSR replacement
- Baseline order: `Plain -> IPIGuard -> DRIFT -> Faramesh -> SecureClaw`

## Final Setting

- Replacement source for native `IPIGuard` / `DRIFT`:
  - `artifact_out_compare_noprompt/20260315_agentleak_c125_native_ipiguard_drift_sharded_v1_merged/paper_parity_agentleak_eval/paper_parity_report.json`
- Unchanged source for `Plain` / `Faramesh` / `SecureClaw`:
  - `artifact_out_compare_noprompt/20260314_agentleak_c125_parity_five_baselines_v1/paper_parity_agentleak_eval/paper_parity_report.json`
- Denominators:
  - total scenarios: `996`
  - benign scenarios: `500`
  - attack scenarios: `496`

## Metric Notes

- `Attack ASR` here is parity-lane `scenario_or_leak_rate`, i.e. whether a scenario leaked through any of `C1/C2/C5`.
- `Benign Leak` is benign `scenario_or_leak_rate`.
- `Utility Success` is the strict task-success rate from:
  - `third_party/agentleak_official/agentleak/metrics/strict_evaluator.py`
- `Utility Score` is the average strict evaluator score in `[0, 1]`.

## Overall Comparison

| System | Overall Utility Success | Overall Utility Score | Benign Leak | Attack ASR |
|---|---:|---:|---:|---:|
| Plain | 77.51% | 0.7176 | 91.60% | 93.95% |
| IPIGuard | 76.31% | 0.7460 | 76.00% | 78.63% |
| DRIFT | 68.27% | 0.6874 | 69.80% | 72.18% |
| Faramesh | 77.51% | 0.7176 | 91.60% | 93.95% |
| SecureClaw | 75.80% | 0.6746 | 15.20% | 15.12% |

## Attack Utility / ASR

| System | Attack Utility Success | Attack Utility Score | Attack ASR |
|---|---:|---:|---:|
| Plain | 77.02% | 0.7129 | 93.95% |
| IPIGuard | 76.21% | 0.7492 | 78.63% |
| DRIFT | 67.94% | 0.6858 | 72.18% |
| Faramesh | 77.02% | 0.7129 | 93.95% |
| SecureClaw | 74.60% | 0.6681 | 15.12% |

## Benign Utility / Leak

| System | Benign Utility Success | Benign Utility Score | Benign Leak |
|---|---:|---:|---:|
| Plain | 78.00% | 0.7223 | 91.60% |
| IPIGuard | 76.40% | 0.7427 | 76.00% |
| DRIFT | 68.60% | 0.6890 | 69.80% |
| Faramesh | 78.00% | 0.7223 | 91.60% |
| SecureClaw | 77.00% | 0.6811 | 15.20% |

## Attack Per-Channel Leak Rates

| System | C1 Leak | C2 Leak | C5 Leak |
|---|---:|---:|---:|
| Plain | 33.47% | 92.74% | 51.61% |
| IPIGuard | 56.25% | 50.00% | 57.06% |
| DRIFT | 51.21% | 47.98% | 53.63% |
| Faramesh | 33.47% | 92.74% | 51.61% |
| SecureClaw | 15.12% | 0.00% | 0.00% |

## Key Takeaways

- `SecureClaw` remains the strongest privacy point on this parity lane by a large margin:
  - benign leak `15.20%`
  - attack ASR `15.12%`
- Native `IPIGuard` materially improves over `Plain` / `Faramesh` on `scenario_or_leak_rate` while keeping utility close:
  - overall utility success `76.31%`
  - attack ASR `78.63%`
- Native `DRIFT` is more privacy-conservative than native `IPIGuard` on this lane:
  - benign leak `69.80%` vs `76.00%`
  - attack ASR `72.18%` vs `78.63%`
  - but utility is lower (`68.27%` overall success)
- The old AgentLeak-side equivalent/oracle-free `IPIGuard` / `DRIFT` numbers should no longer be cited for this lane.

## Fairness Notes

- This table is a replacement composition:
  - `Plain` / `Faramesh` / `SecureClaw` stay from the completed five-baseline parity run on `2026-03-14`
  - `IPIGuard` / `DRIFT` are replaced with the native/original AgentLeak reruns finished on `2026-03-15`
- `IPIGuard` is now evaluated through its original DAG-based agent pipeline, not the prior equivalent text rewrite.
- `DRIFT` is now evaluated through its original constraint-building / isolation / dynamic-validation pipeline, not the prior equivalent text rewrite.
- `Faramesh` is evaluated through a real local server runtime, not a stub.
- `SecureClaw` is evaluated as the full system:
  - gateway
  - dual policy servers
  - executor boundary
- To recover from OpenAI quota exhaustion mid-run, the remaining native baseline calls were resumed via an OpenRouter-compatible OpenAI endpoint using the same model id `gpt-4o-mini-2024-07-18`.
- The merged parity rows contain `0` runtime-error rows for both native baselines.

## Source Paths

- Native replacement parity report:
  - `artifact_out_compare_noprompt/20260315_agentleak_c125_native_ipiguard_drift_sharded_v1_merged/paper_parity_agentleak_eval/paper_parity_report.json`
- Original completed five-baseline parity report:
  - `artifact_out_compare_noprompt/20260314_agentleak_c125_parity_five_baselines_v1/paper_parity_agentleak_eval/paper_parity_report.json`
- Raw sharded roots:
  - `artifact_out_compare_noprompt/20260315_agentleak_c125_native_ipiguard_drift_sharded_v1_shard0`
  - `artifact_out_compare_noprompt/20260315_agentleak_c125_native_ipiguard_drift_sharded_v1_shard1`
  - `artifact_out_compare_noprompt/20260315_agentleak_c125_native_ipiguard_drift_sharded_v1_shard2`
  - `artifact_out_compare_noprompt/20260315_agentleak_c125_native_ipiguard_drift_sharded_v1_shard3`
  - `artifact_out_compare_noprompt/20260315_agentleak_c125_native_ipiguard_drift_sharded_v1_shard4`
  - `artifact_out_compare_noprompt/20260315_agentleak_c125_native_ipiguard_drift_sharded_v1_shard5`
