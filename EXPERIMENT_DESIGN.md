# SecureClaw Experiment Design (Polish Closure)

This document translates the `polish.md` evaluation requirements into executable experiment protocols.
It separates measured tracks from extension tracks and enforces threat-model fairness constraints.

## 1. Threat Models and Baseline Validity

### 1.1 Threat Model A: Honest Runtime

Scope:

1. Runtime follows platform execution model (no direct executor bypass).
2. Attacks come from prompt/tool content, not privileged runtime compromise.

Valid baseline families:

1. Native runtimes (`codex_native`, `openclaw_native`).
2. Runtime mediation defenses (DRIFT, IPIGuard, AgentArmor).

### 1.2 Threat Model B: Compromised Runtime

Scope:

1. Runtime may attempt direct effect bypass.
2. Runtime may replay/retarget commit evidence.
3. Runtime may attempt out-of-band exfiltration.

Valid baseline families:

1. SecureClaw ablations (`no_nbe`, `no_capsule`, degraded transport).
2. Executor acceptance/security-game harnesses.

### 1.3 Fairness Constraints (Hard Requirements)

1. No dataset truth label (`kind`) in defense decisions.
2. No payload oracle fields (`token`, `secret_field`) in defense logic.
3. Baselines are evaluated on the same case manifest and model settings.
4. Threat-model mismatch must be disclosed (A vs B).

---

## 2. Completed Measured Tracks

### 2.1 E1: Compromised-Runtime Bypass Suite (Completed)

Question:

Can an adversarial runtime commit side effects by bypassing PREVIEW->COMMIT or by replay/context swap?

Artifacts:

1. `artifact_out/compromised_bypass_report.json`
2. `artifact_out/compromised_bypass_report.md`
3. `artifact_out/security_game_nbe.json`

Current result snapshot:

1. `n_rows=16`, `n_pass=16`, `pass_rate=1.0`.
2. Fail-closed denials observed for missing proof, one-server proof, replay/context mismatch.
3. Expected bypass openings observed only in intentionally insecure/degraded baselines.

### 2.2 E2: SAP Single-Auditor Distinguishability (Completed)

Question:

Can one policy server infer hidden intent/query attributes from transcript metadata?

Artifacts:

1. `artifact_out_compare/leakage_sweep/leakage_model_sweep.json`
2. `artifact_out_compare_noprompt/leakage_channel_report.json`

Current result snapshot:

1. Unshaped PIR MI: `0.4143` bits.
2. Shaped (`pad4+cover`) PIR MI: `0.0` bits.
3. Shaped (`pad4+cover`) MPC MI: `2.08e-06` bits.

Interpretation:

1. Distinguishable signal exists without shaping.
2. Signal collapses under unified fixed-shape routing, consistent with SAP game intent.

### 2.3 Official Main Comparison (C1..C5, Completed)

Primary artifact:

1. `artifact_out_compare_noprompt/fair_full_report.json`

Current result snapshot:

1. `SecureClaw(mirage_full): attack_leak_rate=0.0, attack_block_rate=1.0, benign_allow_rate=0.8`.

---

## 3. Extension Protocols (Designed and Ready)

### 3.1 E3: AP2 Prompt-Injection Case Study

Objective:

1. Evaluate SecureClaw on agent payment workflows.
2. Demonstrate gap between prompt/DLP-only controls and non-bypassable commit enforcement.

Systems:

1. Vanilla AP2 flow.
2. AP2 + prompt/DLP shield.
3. AP2 + SecureClaw (SAP off).
4. AP2 + SecureClaw (SAP on).

Metrics:

1. Unauthorized mandate rate.
2. Sensitive-data leakage rate.
3. Benign utility completion.
4. Authorization latency p50/p95.

Acceptance criteria:

1. Unauthorized mandate rate at SecureClaw <= all non-boundary baselines.
2. Any remaining leaks are attributable to declared non-goal channels.

### 3.2 E4: AgentDojo Exfiltration Extension

Objective:

1. Reproduce personal-data exfiltration workflows with explicit data-flow attacks.
2. Compare identical manifests across systems.

Systems:

1. Vanilla agent.
2. Shielded baseline.
3. SecureClaw full.
4. SecureClaw ablations (`policy_only`, `sandbox_only`, `single_server_policy`).

Metrics:

1. Attack leak rate.
2. Attack block rate.
3. Benign allow/utility.

Acceptance criteria:

1. SecureClaw full dominates attack leak/block metrics under same manifest.
2. Utility degradation is bounded and attributable by ablation.

### 3.3 E5: VPI-Bench Mediated Subset

Objective:

1. Stress-test multimodal/GUI prompts where effectful outcomes are mappable to executor-mediated actions.
2. Quantify residual risk when UI side effects bypass executor path.

Systems:

1. Native CUA baseline.
2. CUA + SecureClaw mediated effect path.

Metrics:

1. Unauthorized effect success.
2. Leakage indicators in mediated channels.
3. Utility and latency.

Acceptance criteria:

1. Unauthorized mediated effects are fail-closed under SecureClaw.
2. Unmediated UI residuals are explicitly documented as scope limits.

### 3.4 E6: Enterprise DLP-Proxy Privacy-Sink Baseline

Objective:

1. Emulate a centralized AI-gateway/DLP deployment that inspects/logs policy inputs.
2. Contrast observability of single-auditor transcript features against SAP-shaped routing.

Systems:

1. Single-server centralized policy proxy with full plaintext query inspection.
2. SecureClaw SAP mode with fixed-shape PIR+MPC and declared `L_policy`.

Metrics:

1. Single-auditor distinguishability (MI/classifier accuracy).
2. Sensitive-value recoverability from policy-plane logs.
3. Utility/latency parity under equal task manifests.

Acceptance criteria:

1. Proxy baseline exposes separable signal and/or direct sensitive-value visibility.
2. SAP mode restricts single-auditor view to declared leakage contract with near-chance distinguishers.

---

## 4. Execution and Reporting Checklist

1. Freeze manifest and model settings before each track.
2. Record baseline implementation source (`real_only` vs any downgraded mode).
3. Report confidence intervals for rate metrics.
4. Keep measured vs designed tracks explicitly separated.
5. Sync final numbers into `README.md`, `LEAKAGE_EVIDENCE.md`, and paper tables only after artifact freeze.
