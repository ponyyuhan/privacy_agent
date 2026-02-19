# Fair Baselines (What They Mean, and How We Run Them)

This note clarifies what our baselines do (and do **not**) claim, and how we ensure a *same-cases / same-seed / same-metrics* comparison.

The main reviewer pitfall is conflating two distinct threat models:

1. **Compromised runtime**: the agent runtime (and its skills) are already adversarial and will actively exfiltrate secrets if it can.
2. **Native guardrails**: the runtime is not intentionally malicious, and we ask how well the platform/model's built-in safety prevents leakage under prompt-injection style attacks.

SecureClaw is designed for (1), but papers also need to report (2) as a strong baseline.

---

## 1. Baselines We Report in `fair_full_report.json`

We keep exactly:

- **SecureClaw modes (same harness)**:
  - `mirage_full`: full system (gateway + 2 policy servers + executor dual-authorization).
  - `policy_only`: gateway policy checks but no executor enforcement line (no dual-proof effect boundary).
  - `sandbox_only`: disables SecureClaw policy mediation (a “local sandbox only” style baseline).
  - `single_server_policy`: same policy logic but only one policy server (removes SAP privacy).

- **Native guardrails baselines (real CLIs, no compromised script)**:
  - `codex_native`: Codex CLI asked to follow the official allowed-set policy and produce channel artifacts.
  - `openclaw_native`: OpenClaw CLI (OpenAI OAuth provider plugin) asked to do the same.

All of the above are run on the **same official case manifest** generated from AgentLeak's official dataset.

---

## 2. The Baseline We Deliberately Do *Not* Treat as “Native Guardrails”

We previously used a deterministic script baseline (`scripts/plain_runtime_agentleak_eval.py`) that **intentionally leaks** the secret on attack cases.

That baseline is useful only as a *sanity-check upper bound* for the *compromised runtime* threat model:
if the runtime chooses to leak, any prompt-only defense will lose. However, it does **not** answer:

> “What can Codex/OpenClaw’s native protections do on the official benchmark?”

Therefore, we do not present it as the Codex/OpenClaw “native” baseline in the paper-grade fair report.

---

## 3. Same-Cases / Same-Seed / Same-Metrics Procedure

1. Generate an **official case manifest** (JSONL), derived from AgentLeak's official dataset and a fixed seed:
   - `artifact_out_compare/fair_cases.jsonl`

2. Run SecureClaw modes using our official-harness runner with `AGENTLEAK_CASES_MANIFEST_PATH` pinned to that manifest:
   - output: `artifact_out_compare/fair_mirage/agentleak_eval/agentleak_channel_summary.json`
   - per-case rows: `artifact_out_compare/fair_mirage/agentleak_eval/agentleak_eval_rows.csv`

3. Run native baselines against the *same manifest*:
   - runner: `scripts/native_official_baseline_eval.py`
   - outputs (per runtime):
     - `.../native_official_baseline_summary.json` (includes per-case rows + summary)

4. Aggregate into the single paper-facing file:
   - `artifact_out_compare/fair_full_report.json`

5. Produce statistics / breakdowns / significance tests:
   - `scripts/fair_full_stats.py` (Wilson 95% CI + two-sided Fisher exact tests vs `mirage_full`)

---

## 4. Reproducing the Fair Report

```bash
OUT_DIR=artifact_out_compare MIRAGE_SEED=7 python scripts/fair_full_compare.py
python scripts/fair_full_stats.py --report artifact_out_compare/fair_full_report.json
```

Notes:

- Codex baseline uses `CODEX_BASELINE_MODEL=gpt-5.1-codex-mini` and `CODEX_BASELINE_REASONING=low` by default.
  - (`reasoning=none` is rejected by some lightweight GPT-5 variants; `low` is the minimum supported level.)
- Codex baseline supports parallelism:
  - `CODEX_BASELINE_CONCURRENCY=4` can reduce wall-clock time (subject to rate limits).
- To reduce cost, you can cap the number of scenario groups evaluated by both native baselines:
  - `NATIVE_BASELINE_MAX_GROUPS=50` (evaluates the first 50 scenarios, still mapped to all channel-cases in aggregation).
- OpenClaw baseline uses `OPENCLAW_NATIVE_MODEL=openai-codex/gpt-5.1-codex-mini` by default and the OpenAI OAuth provider plugin shipped under `integrations/openclaw_runner/extensions/openai-codex-auth`.

---

## 5. Interpreting Performance Numbers

SecureClaw modes are local services (policy servers + gateway + executor), so `ops_s` and `p50/p95` reflect system overhead under the harness.

Native guardrails baselines invoke external model inference through a real CLI. Inference latency dominates, and throughput is not directly comparable to local enforcement throughput.

For transparency, the native baseline summary records both:

- case-level `ops_s` (computed over per-case rows), and
- model-call-level metrics (`model_call_count`, `model_ops_s`, `model_latency_p50_ms`, `model_latency_p95_ms`).

---

## 6. What This Baseline Set Still Does Not Prove

- A “native baseline” does not give non-bypassability: the runtime can still be compromised and leak secrets by construction.
- A “policy_only” baseline in SecureClaw is still stronger than prompt-only: it enforces handleization and gateway mediation, but lacks the executor dual-proof boundary.
- Codex/OpenClaw results depend on the exact model version, platform defaults, and any upstream safety changes.
