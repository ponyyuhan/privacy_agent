# Cross-Benchmark Evaluation Status (updated 2026-03-15)

This document records the current **completed** fair-comparison status across the benchmarks that are locally runnable in this workspace.

There is currently **no active cross-benchmark background run**.

The locally frozen five-baseline set is:

1. `Plain`
2. `IPIGuard`
3. `DRIFT`
4. `Faramesh`
5. `SecureClaw`

## 1. Current Completed Benchmarks

The current completed same-caliber five-baseline comparisons are:

- `AgentDojo v1.1.2`
- `AgentLeak`
  - main parity lane: `C1/C2/C5`
  - channel lanes: `C3`, `C4`, `C6`

Important fairness note for `AgentLeak`:

- `Plain` / `Faramesh` / `SecureClaw` remain from the earlier completed five-baseline runs.
- `IPIGuard` / `DRIFT` were **replaced** on `2026-03-15` with **native/original integrations**:
  - `IPIGuard`: original `AgentPipeline(... defense="ipiguard")`
  - `DRIFT`: original `DRIFTLLM + DRIFTToolsExecutionLoop`
- The older equivalent/oracle-free AgentLeak-side `IPIGuard` / `DRIFT` numbers are superseded.

## 2. Frozen Fair Result: AgentDojo v1.1.2

Setting:

- Benchmark: `AgentDojo v1.1.2`
- Model: `gpt-4o-mini-2024-07-18`
- Attack family: `important_instructions`
- Source:
  - `AGENTDOJO_FIVE_BASELINE_RESULTS_2026-03-14.md`

### Overall Table

| System | Benign Utility | Under-Attack Utility | Under-Attack ASR |
|---|---:|---:|---:|
| Plain | 70.10% | 47.22% | 31.48% |
| IPIGuard | 64.95% | 51.99% | 15.26% |
| DRIFT | 59.79% | 52.78% | 2.38% |
| Faramesh | 60.82% | 47.69% | 22.89% |
| SecureClaw | 60.82% | 56.60% | 0.64% |

### AgentDojo Conclusion

- `SecureClaw` is the strongest overall point on the fair `AgentDojo` comparison.
- It has both:
  - the best under-attack utility
  - the lowest ASR
- `DRIFT` is the next strongest baseline on `AgentDojo`.

## 3. Frozen Fair Result: AgentLeak Main Parity (`C1/C2/C5`)

Setting:

- Benchmark lane: `AgentLeak official parity (C1/C2/C5)`
- Model id: `gpt-4o-mini-2024-07-18`
- Utility metric: official `strict_evaluator`
- Source:
  - `AGENTLEAK_PARITY_FIVE_BASELINE_RESULTS_2026-03-15.md`

### Overall Table

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

### Per-Channel Attack Leak

| System | C1 Leak | C2 Leak | C5 Leak |
|---|---:|---:|---:|
| Plain | 33.47% | 92.74% | 51.61% |
| IPIGuard | 56.25% | 50.00% | 57.06% |
| DRIFT | 51.21% | 47.98% | 53.63% |
| Faramesh | 33.47% | 92.74% | 51.61% |
| SecureClaw | 15.12% | 0.00% | 0.00% |

### AgentLeak Parity Conclusion

- `SecureClaw` remains the strongest privacy point on this lane by a large margin.
- Native `IPIGuard` improves over `Plain` / `Faramesh` while staying close on utility.
- Native `DRIFT` leaks less than native `IPIGuard`, but utility is lower.

## 4. Frozen Fair Result: AgentLeak Channel Lanes

Source:

- `AGENTLEAK_CHANNEL_FIVE_BASELINE_PROGRESS_2026-03-14.md`

### `C3` Official

| System | Attack Block Rate | Attack Leak Rate | Benign Allow Rate |
|---|---:|---:|---:|
| Plain | 0.00% | 100.00% | 100.00% |
| IPIGuard | 75.97% | 24.03% | 100.00% |
| DRIFT | 93.02% | 6.98% | 99.21% |
| Faramesh | 0.00% | 100.00% | 100.00% |
| SecureClaw | 100.00% | 0.00% | 100.00% |

### `C4` Official

| System | Attack Block Rate | Attack Leak Rate | Benign Allow Rate |
|---|---:|---:|---:|
| Plain | 0.00% | 100.00% | 100.00% |
| IPIGuard | 66.39% | 33.61% | 100.00% |
| DRIFT | 85.25% | 14.75% | 99.80% |
| Faramesh | 0.00% | 100.00% | 100.00% |
| SecureClaw | 100.00% | 0.00% | 100.00% |

### `C6` Extension

| System | Attack Block Rate | Attack Leak Rate | Benign Allow Rate |
|---|---:|---:|---:|
| Plain | 0.00% | 100.00% | 100.00% |
| IPIGuard | 100.00% | 0.00% | 100.00% |
| DRIFT | 100.00% | 0.00% | 98.90% |
| Faramesh | 0.00% | 100.00% | 100.00% |
| SecureClaw | 100.00% | 0.00% | 99.90% |

### Channel-Lane Conclusion

- On `C3` and `C4`, native `DRIFT` is clearly stronger than native `IPIGuard`.
- On `C6`, both native `IPIGuard` and native `DRIFT` fully block attacks.
- `SecureClaw` remains the strongest overall channel baseline once utility-preserving benign allow is considered jointly across lanes.

## 5. Complete Cross-Benchmark Comparison

### A. AgentDojo

| System | Benign Utility | Under-Attack Utility | ASR |
|---|---:|---:|---:|
| Plain | 70.10% | 47.22% | 31.48% |
| IPIGuard | 64.95% | 51.99% | 15.26% |
| DRIFT | 59.79% | 52.78% | 2.38% |
| Faramesh | 60.82% | 47.69% | 22.89% |
| SecureClaw | 60.82% | 56.60% | 0.64% |

### B. AgentLeak `C1/C2/C5`

| System | Utility Success | Utility Score | Benign Leak | Attack ASR |
|---|---:|---:|---:|---:|
| Plain | 77.51% | 0.7176 | 91.60% | 93.95% |
| IPIGuard | 76.31% | 0.7460 | 76.00% | 78.63% |
| DRIFT | 68.27% | 0.6874 | 69.80% | 72.18% |
| Faramesh | 77.51% | 0.7176 | 91.60% | 93.95% |
| SecureClaw | 75.80% | 0.6746 | 15.20% | 15.12% |

### C. AgentLeak `C3`

| System | Block | Leak | Benign Allow |
|---|---:|---:|---:|
| Plain | 0.00% | 100.00% | 100.00% |
| IPIGuard | 75.97% | 24.03% | 100.00% |
| DRIFT | 93.02% | 6.98% | 99.21% |
| Faramesh | 0.00% | 100.00% | 100.00% |
| SecureClaw | 100.00% | 0.00% | 100.00% |

### D. AgentLeak `C4`

| System | Block | Leak | Benign Allow |
|---|---:|---:|---:|
| Plain | 0.00% | 100.00% | 100.00% |
| IPIGuard | 66.39% | 33.61% | 100.00% |
| DRIFT | 85.25% | 14.75% | 99.80% |
| Faramesh | 0.00% | 100.00% | 100.00% |
| SecureClaw | 100.00% | 0.00% | 100.00% |

### E. AgentLeak `C6`

| System | Block | Leak | Benign Allow |
|---|---:|---:|---:|
| Plain | 0.00% | 100.00% | 100.00% |
| IPIGuard | 100.00% | 0.00% | 100.00% |
| DRIFT | 100.00% | 0.00% | 98.90% |
| Faramesh | 0.00% | 100.00% | 100.00% |
| SecureClaw | 100.00% | 0.00% | 99.90% |

## 6. Current Bottom Line

- `SecureClaw` is still the strongest overall system across the completed local benchmarks.
- `AgentDojo`:
  - `SecureClaw` is best on both attack utility and ASR.
- `AgentLeak`:
  - on the main `C1/C2/C5` lane, `SecureClaw` dominates privacy;
  - native `IPIGuard` is utility-stronger than native `DRIFT`;
  - native `DRIFT` is privacy-stronger than native `IPIGuard` on the official channel lanes `C3/C4`;
  - on `C6`, both native baselines fully block attacks, with native `IPIGuard` keeping the better benign-allow rate.

## 7. Source Documents

- `AGENTDOJO_FIVE_BASELINE_RESULTS_2026-03-14.md`
- `AGENTLEAK_PARITY_FIVE_BASELINE_RESULTS_2026-03-15.md`
- `AGENTLEAK_CHANNEL_FIVE_BASELINE_PROGRESS_2026-03-14.md`
- `AGENTLEAK_UNIFIED_FIVE_BASELINE_RESULTS_2026-03-15.md`
