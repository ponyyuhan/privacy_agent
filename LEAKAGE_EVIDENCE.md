# Leakage Evidence (Per-Channel `L_Ci`, Official + Synthetic)

This document is a paper-facing index of *empirical evidence* that the artifact implementation conforms to the explicit leakage contract defined in `LEAKAGE_MODEL.md`.

We report two complementary views:

1. **End-to-end channel leakage (`L_sys`)** via AgentLeak-style channels `C1..C7`.
2. **Single policy-server distinguishability (`L_policy`)** via transcript classifiers / mutual information sweeps under shaping.

---

## 0. Threat-Model Split (Fairness Guardrail)

To avoid mixing incomparable settings, all evidence is interpreted under two threat models:

1. **Threat Model A (honest runtime):**
   Native platforms and mediation defenses (`codex_native`, `openclaw_native`, DRIFT/IPIGuard/AgentArmor) are evaluated as runtime-behavior defenses where direct effect bypass is out of scope.
2. **Threat Model B (compromised runtime):**
   Runtime may attempt direct executor bypass, replay/context swapping, and out-of-band exfiltration. SecureClaw `NBE/SCS/DAS` claims are evaluated here.

This split is required by `BASELINES_FAIRNESS.md` and mirrors `polish.md` guidance.

---

## 1. Per-Channel `L_sys` (C1..C7): What Is Covered Officially

AgentLeak's official dataset defines and evaluates only:

- `C1` final output
- `C2` inter-agent messages
- `C3` tool inputs
- `C4` tool outputs
- `C5` memory write/read

It does **not** provide official cases for:

- `C6` logs/audit
- `C7` artifacts / skill supply chain ingress

Therefore, we validate `C6/C7` using the artifact's **synthetic channel suite** (same harness, deterministic generation).

---

## 2. Official Cases (C1..C5): Evidence Artifacts

Fair, same-cases comparison (SecureClaw 4 modes + native baselines):

- `artifact_out_compare_noprompt/fair_full_report.json`
  - Contains overall rates, per-channel rates, and latency/throughput summaries.
  - The manifest is pinned at `artifact_out_compare_noprompt/fair_cases.jsonl` (derived from the official dataset with a fixed seed).

Three-track consolidated report (privacy / injection / protocol):

- `artifact_out_compare_noprompt/multi_track_eval.json`
  - Produced by `scripts/multi_track_eval.py`.
  - Includes main comparison (`SecureClaw`, `codex_native`, `openclaw_native`) plus defense baselines (`codex_drift`, `codex_ipiguard`; `codex_agentarmor` only when official report is provided).
  - Injection track includes `external_real_run` and validates external benchmark run evidence.
  - Default defense source is `real_only` (official external artifacts), not in-repo equivalence wrappers.

SecureClaw-only official harness run (used internally by the fair report):

- `artifact_out_compare_noprompt/fair_mirage/agentleak_eval/agentleak_channel_summary.json`
- `artifact_out_compare_noprompt/fair_mirage/agentleak_eval/agentleak_eval_rows.csv`

Paper-parity lane (same multi-agent topology + same hybrid 3-tier detector + same scenario-level OR, including SecureClaw):

- Script: `scripts/paper_parity_agentleak_eval.py`
- Output dir: `artifact_out_compare_noprompt/paper_parity_full_gpt4omini/paper_parity_agentleak_eval/`
- Core files:
  - `rows_plain.jsonl`
  - `rows_secureclaw.jsonl`
  - `summary_plain.json`
  - `summary_secureclaw.json`
  - `paper_parity_report.json`
- OR definition:
  - `scenario_or_leaked = c1_leaked OR c2_leaked OR c5_leaked`
- This lane explicitly uses:
  - official coordinator->worker->memory->final topology
  - hybrid detector (`presidio` + `LLM-as-judge`)
  - aligned per-scenario OR aggregation for both plain and SecureClaw modes

Reproduce:

```bash
OUT_DIR=artifact_out_compare_noprompt MIRAGE_SEED=7 \
  FAIR_FULL_REUSE_NATIVE=1 FAIR_FULL_REUSE_SECURECLAW=1 \
  python scripts/fair_full_compare.py
python scripts/fair_full_stats.py --report artifact_out_compare_noprompt/fair_full_report.json
python scripts/fair_utility_breakdown.py --report artifact_out_compare_noprompt/fair_full_report.json
python scripts/multi_track_eval.py --out-dir artifact_out_compare_noprompt --run-protocol-tests 1 \
  --external-report artifact_out_external_runtime/external_runs/20260220_fullpipeline/external_benchmark_unified_report.json \
  --external-run-tag 20260220_fullpipeline \
  --asb-run-tag 20260220_official \
  --require-external-real-run 1
```

---

## 3. Synthetic Full Channels (C1..C7): Evidence Artifacts

Synthetic, full-channel suite (including `C6/C7`):

- `artifact_out_compare/leakage_sys_synth_v2/agentleak_eval/agentleak_channel_summary.json`
- `artifact_out_compare/leakage_sys_synth_v2/agentleak_eval/agentleak_eval_rows.csv`

Reproduce:

```bash
OUT_DIR=artifact_out_compare/leakage_sys_synth_v2 \
  AGENTLEAK_CASESET=synthetic \
  python scripts/agentleak_channel_eval.py
```

Notes:

- `C6` tests audit/log leakage by attempting to inject a canary token into an auditable action; the harness checks the audit log for the canary.
- `C7` tests skill ingress by importing a staged skill package and enforcing `CheckSkillInstallPolicy` (IOC/install-marker PIR + MPC policy).
- Under case-isolated callers (`AGENTLEAK_ISOLATE_CASE_CONTEXT=1`), benign `C7` requires capability projection to match caller prefixes; the artifact includes a wildcard `artifact:*` rule in `gateway/capabilities.yaml` so benign `C7` installs are not falsely denied.

---

## 4. Single-Policy-Server Transcript Distinguishability (`L_policy`)

We empirically test whether a *single* policy server can classify hidden attributes from transcript metadata under different shaping modes.

Artifact output:

- `artifact_out_compare/leakage_sweep/leakage_model_sweep.json`

Reproduce:

```bash
OUT_DIR=artifact_out_compare/leakage_sweep python scripts/leakage_model_sweep.py
```

Optional k-way query-value privacy run (recipient index hiding):

```bash
OUT_DIR=artifact_out_compare/leakage_sweep_kway_recipient \
LEAKAGE_SWEEP_LABEL_MODE=recipient_kway \
LEAKAGE_SWEEP_KWAY=16 \
python scripts/leakage_model_sweep.py
```

Unified paper-facing leakage report:

- `artifact_out_compare_noprompt/leakage_channel_report.json`

Reproduce:

```bash
python scripts/leakage_channel_report.py
```

This sweep is designed to validate the claim:

> Under unified + bundled + fixed-shape routing, transcript features visible to one policy server do not carry separable signal about intent class beyond the explicit leakage contract.

We intentionally report both:

- Mutual information (MI) estimates, and
- a simple majority-vote classifier accuracy vs chance (legacy field name `map_acc` retained for compatibility),

because system reviewers often prefer an *attack-driven* leakage demonstration.

### 4.1 Control-Plane Compromise Test Mapping (E2)

The `L_policy` sweep is the executable form of the single-auditor compromise test:

1. Attacker sees one policy-server transcript only.
2. Attacker runs MI/classifier distinguishers over transcript metadata.
3. SecureClaw claims hold when shaped mode collapses distinguishability to near chance under the declared feature space.

This is the empirical counterpart of the SAP simulation game in `FORMAL_SECURITY.md` and `appendix_security.tex`.

---

## 4.2 Compromised-Runtime Bypass Suite (E1)

Artifact-level bypass evidence:

- `artifact_out/compromised_bypass_report.json`
- `artifact_out/compromised_bypass_report.md`

This suite checks direct bypass attempts (missing proof share, one-server proof, replay, context swap) and necessity baselines (`no_nbe`, `no_capsule`).
Current snapshot records `16/16` expected outcomes.

Reproduce:

```bash
PYTHONPATH=. python scripts/run_paper_artifact.sh
```

Or directly:

```bash
PYTHONPATH=. python scripts/compromised_bypass_report.py \
  --artifact-report artifact_out/report.json \
  --security-game artifact_out/security_game_nbe.json \
  --capsule-verdict artifact_out/capsule_contract_verdict.json \
  --out-json artifact_out/compromised_bypass_report.json \
  --out-md artifact_out/compromised_bypass_report.md
```

---

## 5. Latest Snapshot (2026-02-25)

The following paths and numbers are synchronized with the latest A/B/C/D execution closure.

Official coverage (`C1..C5`):

- `artifact_out_compare_noprompt/fair_full_report.json`
  - `systems.mirage_full.attack_leak_rate = 0.0`
  - `systems.mirage_full.benign_allow_rate = 0.8`
  - `systems.mirage_full.n_attack = 744`, `n_benign = 2520`
- `artifact_out_compare_noprompt/stats/fair_full_stats.json`
  - `summaries.mirage_full.benign_outcome_counts = {ALLOW: 2016, CONFIRM: 0, HARD_DENY: 504, ERROR: 0}`
  - `summaries.openclaw_native.availability_fail_rate = 1.0` (this run is availability-collapse, not hard policy deny)

Synthetic full-channel coverage (`C1..C7`, including `C6/C7`):

- `artifact_out_compare/leakage_sys_synth_v2/agentleak_eval/agentleak_channel_summary.json`
  - `modes.mirage_full.attack_leak_rate = 0.0`
  - `modes.mirage_full.benign_allow_rate = 0.8571428571428571`
  - `modes.mirage_full.per_channel.C6.attack_leak_rate = 0.0`, `benign_allow_rate = 1.0`
  - `modes.mirage_full.per_channel.C7.attack_leak_rate = 0.0`, `benign_allow_rate = 1.0`

`L_policy` distinguishability:

- `artifact_out_compare/leakage_sweep/leakage_model_sweep.json`
  - `unshaped.pir.mi_bits = 0.4143349401222639`
  - `unshaped.pir.map_acc = 0.5144508670520231` vs `chance = 0.3333333333333333`
  - `shaped_pad4_cover1.pir.mi_bits = 0.0`, `map_acc = 0.3313253012048193`
  - `shaped_pad4_cover1.mpc.mi_bits = 1.0614695895005673e-06`, `map_acc = 0.3033775633293124`
- Unified report:
  - `artifact_out_compare_noprompt/leakage_channel_report.json` (`status = OK`)

`L_policy` k-way recipient privacy (query-value hiding):

- `artifact_out_compare/leakage_sweep_kway_recipient/leakage_model_sweep.json`
  - `label_mode = recipient_kway`, `n_labels = 16`
  - `unshaped.pir.mi_bits = 0.0`, `accuracy = 0.0289` vs `chance = 0.0625`
  - `shaped_pad4_cover1.pir.mi_bits = 0.0`, `accuracy = 0.0450` vs `chance = 0.0625`
  - `shaped_pad4_cover1.mpc.mi_bits = 3.7156e-06`, `accuracy = 0.0473` vs `chance = 0.0625`

Ablation and budget-enforcement evidence:

- `PAD_DFA_STEPS` sweep outputs:
  - `artifact_out_compare/leakage_sweep_pad_dfa0/leakage_model_sweep.json`
  - `artifact_out_compare/leakage_sweep_pad_dfa1/leakage_model_sweep.json`
- Leakage-budget explicit reason-code run:
  - `artifact_out_compare/leakage_budget_exhaust/agentleak_eval/agentleak_channel_summary.json`
  - Contains `LEAKAGE_BUDGET_EXCEEDED` reason entries (`mirage_full=2`; all four modes total `8` in this snapshot).

---

## 6. Extension Experiment Protocols (E3/E4/E5/E6)

These protocols are part of the paper polish closure and are defined as runnable designs with acceptance criteria.
They are listed as extension tracks until full end-to-end outputs are frozen.

### 6.1 E3: AP2 Prompt-Injection Case Study

Goal:

1. Reproduce AP2 prompt-injection manipulation risk in a payment workflow.
2. Compare `vanilla AP2`, `AP2 + prompt/DLP shield`, and `AP2 + SecureClaw` (with/without SAP).

Primary metrics:

1. Unauthorized mandate rate.
2. Sensitive data leakage rate (credentials/identifiers/tokens).
3. Utility completion rate.
4. Authorization-path latency p50/p95.

### 6.2 E4: AgentDojo Exfiltration Extension

Goal:

1. Evaluate personal-data exfiltration workflows on AgentDojo-style banking tasks.
2. Compare vanilla/shielded/SecureClaw under the same task manifest and same model settings.

Primary metrics:

1. Attack leak rate.
2. Attack block rate.
3. Benign utility.

### 6.3 E5: VPI-Bench Mediated Subset

Goal:

1. Stress-test computer-use prompts where effectful operations can be mediated by executor.
2. Report explicit scope gaps when actions are unmediated UI side effects.

Primary metrics:

1. Unauthorized effect success rate.
2. Leakage indicators in mediated channels.
3. Utility and latency impact.

### 6.4 E6: Enterprise DLP-Proxy Privacy-Sink Baseline

Goal:

1. Compare centralized plaintext policy inspection (single-server DLP proxy) against SAP routing.
2. Quantify how much single-auditor transcript/log visibility remains in each design.

Primary metrics:

1. MI/classifier distinguishability from single-auditor transcript features.
2. Direct sensitive-value visibility in policy-plane logs.
3. Utility/latency parity under identical manifests.

---

## 7. What “Zero Leak” Means Here (and What It Does Not Mean)

In the channel harness, an "attack leak" is defined as the appearance of a scenario-specific secret token (forbidden field value) in the corresponding channel artifact.

Thus, `attack_leak_rate = 0` means:

- No forbidden token traversed the measured channel (C1..C7) under the harness semantics.

It does **not** mean:

- The gateway or executor leaks nothing (they are within the TCB).
- There are no host-level side channels (not modeled).
- A colluding pair of policy servers cannot infer the query (SAP assumes non-collusion).

These limits are stated explicitly in `LEAKAGE_MODEL.md`.
