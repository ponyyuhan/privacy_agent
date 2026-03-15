# AgentLeak Channel Five-Baseline Progress (updated 2026-03-15)

This document tracks the channel-level five-baseline comparisons used for `AgentLeak`.

On `2026-03-15`, the earlier AgentLeak-side `IPIGuard` / `DRIFT` channel results were replaced with **native/original integrations**:

- `IPIGuard`: original `AgentPipeline(... defense="ipiguard")`
- `DRIFT`: original `DRIFTLLM + DRIFTToolsExecutionLoop`

The current numbers below are the merged outputs from sharded native reruns. `Plain`, `Faramesh`, and `SecureClaw` remain unchanged from the earlier completed runs.

## 1. Fairness Notes

- The tables below are replacement compositions:
  - `Plain` / `Faramesh` / `SecureClaw` remain from the completed `2026-03-14` five-baseline channel runs
  - `IPIGuard` / `DRIFT` are replaced by the native/original sharded reruns completed on `2026-03-15`
- `SecureClaw` is run as the **full system**, i.e. gateway + dual policy servers + executor boundary.
- `Faramesh` is run as a **real runtime baseline**, not a stub.
- `IPIGuard` and `DRIFT` are now real native integrations on AgentLeak-side adapters, not the old equivalent/oracle-free channel transforms.
- To bypass OpenAI quota exhaustion, native reruns were resumed through an OpenRouter-compatible OpenAI endpoint with the same model id `gpt-4o-mini-2024-07-18`.
- The merged channel rows contain `0` runtime-error rows for the native baselines.

## 2. Completed: Official `C3`

Run root:

- `artifact_out_compare_noprompt/20260315_agentleak_c3_native_ipiguard_drift_sharded_v1_merged`

Case counts:

- attack: `129`
- benign: `504`

| System | Attack Block Rate | Attack Leak Rate | Benign Allow Rate |
|---|---:|---:|---:|
| Plain | 0.00% | 100.00% | 100.00% |
| IPIGuard | 75.97% | 24.03% | 100.00% |
| DRIFT | 93.02% | 6.98% | 99.21% |
| Faramesh | 0.00% | 100.00% | 100.00% |
| SecureClaw | 100.00% | 0.00% | 100.00% |

## 3. Completed: Official `C4`

Run root:

- `artifact_out_compare_noprompt/20260315_agentleak_c4_native_ipiguard_drift_sharded_v1_merged`

Case counts:

- attack: `122`
- benign: `504`

| System | Attack Block Rate | Attack Leak Rate | Benign Allow Rate |
|---|---:|---:|---:|
| Plain | 0.00% | 100.00% | 100.00% |
| IPIGuard | 66.39% | 33.61% | 100.00% |
| DRIFT | 85.25% | 14.75% | 99.80% |
| Faramesh | 0.00% | 100.00% | 100.00% |
| SecureClaw | 100.00% | 0.00% | 100.00% |

## 4. Completed: `C6`

Run root:

- `artifact_out_compare_noprompt/20260315_agentleak_c6_native_ipiguard_drift_sharded_v1_merged`

Case counts:

- attack: `1000`
- benign: `1000`

| System | Attack Block Rate | Attack Leak Rate | Benign Allow Rate |
|---|---:|---:|---:|
| Plain | 0.00% | 100.00% | 100.00% |
| IPIGuard | 100.00% | 0.00% | 100.00% |
| DRIFT | 100.00% | 0.00% | 98.90% |
| Faramesh | 0.00% | 100.00% | 100.00% |
| SecureClaw | 100.00% | 0.00% | 99.90% |

## 5. Notes on Coverage

The reproducible package in this workspace exposes:

- `C1/C2/C5` parity lane
- `C3/C4` official dataset-mode channel lanes
- `C6` extension lane

So the currently comparable native-five-baseline picture is:

- official parity for `C1/C2/C5`
- official dataset channel compare for `C3/C4`
- extension harness for `C6`

## 6. Source Paths

- Native replacement `C3` report:
  - `artifact_out_compare_noprompt/20260315_agentleak_c3_native_ipiguard_drift_sharded_v1_merged/report.json`
- Native replacement `C4` report:
  - `artifact_out_compare_noprompt/20260315_agentleak_c4_native_ipiguard_drift_sharded_v1_merged/report.json`
- Native replacement `C6` report:
  - `artifact_out_compare_noprompt/20260315_agentleak_c6_native_ipiguard_drift_sharded_v1_merged/report.json`
- Original completed five-baseline reports with unchanged `Plain` / `Faramesh` / `SecureClaw`:
  - `artifact_out_compare_noprompt/20260314_agentleak_c3_official_five_baselines_v2/report.json`
  - `artifact_out_compare_noprompt/20260314_agentleak_c4_official_five_baselines_v2/report.json`
  - `artifact_out_compare_noprompt/20260314_agentleak_c6_synth_five_baselines_v2/report.json`
