# Leakage Evidence (Per-Channel `L_Ci`, Official + Synthetic)

This document is a paper-facing index of *empirical evidence* that the artifact implementation conforms to the explicit leakage contract defined in `LEAKAGE_MODEL.md`.

We report two complementary views:

1. **End-to-end channel leakage (`L_sys`)** via AgentLeak-style channels `C1..C7`.
2. **Single policy-server distinguishability (`L_policy`)** via transcript classifiers / mutual information sweeps under shaping.

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

- `artifact_out_compare/fair_full_report.json`
  - Contains overall rates, per-channel rates, and latency/throughput summaries.
  - The manifest is pinned at `artifact_out_compare/fair_cases.jsonl` (derived from the official dataset with a fixed seed).

SecureClaw-only official harness run (used internally by the fair report):

- `artifact_out_compare/fair_mirage/agentleak_eval/agentleak_channel_summary.json`
- `artifact_out_compare/fair_mirage/agentleak_eval/agentleak_eval_rows.csv`

Reproduce:

```bash
OUT_DIR=artifact_out_compare MIRAGE_SEED=7 python scripts/fair_full_compare.py
python scripts/fair_full_stats.py --report artifact_out_compare/fair_full_report.json
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

We empirically test whether a *single* policy server can classify hidden attributes (intent class) from transcript metadata under different shaping modes.

Artifact output:

- `artifact_out_compare/leakage_sweep/leakage_model_sweep.json`

Reproduce:

```bash
OUT_DIR=artifact_out_compare/leakage_sweep python scripts/leakage_model_sweep.py
```

This sweep is designed to validate the claim:

> Under unified + bundled + fixed-shape routing, transcript features visible to one policy server do not carry separable signal about intent class beyond the explicit leakage contract.

We intentionally report both:

- Mutual information (MI) estimates, and
- a simple classifier baseline (MAP / accuracy vs chance),

because system reviewers often prefer an *attack-driven* leakage demonstration.

---

## 5. What “Zero Leak” Means Here (and What It Does Not Mean)

In the channel harness, an "attack leak" is defined as the appearance of a scenario-specific secret token (forbidden field value) in the corresponding channel artifact.

Thus, `attack_leak_rate = 0` means:

- No forbidden token traversed the measured channel (C1..C7) under the harness semantics.

It does **not** mean:

- The gateway or executor leaks nothing (they are within the TCB).
- There are no host-level side channels (not modeled).
- A colluding pair of policy servers cannot infer the query (SAP assumes non-collusion).

These limits are stated explicitly in `LEAKAGE_MODEL.md`.
