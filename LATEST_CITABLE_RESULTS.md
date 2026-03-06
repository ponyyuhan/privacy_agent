# Latest Citable Results

Last updated: 2026-03-06 CET

This file includes only runs with complete, parseable summary outputs that can be cited directly.

As of 2026-03-06 CET, the 20260304 fair four-baseline rerun remains in progress under a detached sequential supervisor; its partial rows are intentionally excluded here until all denominators close.

## Unified Table

| ID | Experiment | System / Setting | Model | Sample size | Attack metric | Benign / Utility metric | Source |
|---|---|---|---|---|---|---|---|
| R1-Plain | AgentLeak-official parity (C1/C2/C5, 3-tier detector, scenario-level OR) | plain | gpt-4o-mini-2024-07-18 | n_total=103, n_attack=50, n_benign=53 | attack scenario OR leak rate = 0.9200 | benign scenario OR leak rate = 0.9811 | `artifact_out_compare_noprompt/paper_parity_agentleak_gpt4o_full_20260303/paper_parity_agentleak_eval/paper_parity_report.json` |
| R1-DRIFT | AgentLeak-official parity (same as above) | drift equivalent mode | gpt-4o-mini-2024-07-18 | n_total=103, n_attack=50, n_benign=53 | attack scenario OR leak rate = 0.5800 | benign scenario OR leak rate = 0.9811 | `artifact_out_compare_noprompt/paper_parity_agentleak_gpt4o_full_20260303/paper_parity_agentleak_eval/paper_parity_report.json` |
| R1-IPIGuard | AgentLeak-official parity (same as above) | ipiguard equivalent mode | gpt-4o-mini-2024-07-18 | n_total=102, n_attack=49, n_benign=53 | attack scenario OR leak rate = 0.6327 | benign scenario OR leak rate = 0.9811 | `artifact_out_compare_noprompt/paper_parity_agentleak_gpt4o_full_20260303/paper_parity_agentleak_eval/paper_parity_report.json` |
| R1-SecureClaw | AgentLeak-official parity (same as above) | secureclaw | gpt-4o-mini-2024-07-18 | n_total=102, n_attack=49, n_benign=53 | attack scenario OR leak rate = 0.0000 | benign scenario OR leak rate = 0.3585 | `artifact_out_compare_noprompt/paper_parity_agentleak_gpt4o_full_20260303/paper_parity_agentleak_eval/paper_parity_report.json` |
| R2 | External DRIFT full rerun audit | DRIFT (official pipeline rerun) | gpt-4o-mini-2024-07-18 | under-attack total=949 | ASR = 16/949 = 1.6860% | attack utility success rate = 513/949 = 54.0569% | `artifact_out_external_runtime/external_runs/20260301_external_full_rerun_gpt4omini/drift_post_audit.json` |
| R3 | External IPIGuard fixed run | IPIGuard under_attack/workspace | gpt-4o-mini-2024-07-18 | under-attack total=240 | ASR = 2/240 = 0.8333% | utility = 135/240 = 56.2500% | `artifact_out_external_runtime/external_runs/20260303_ipiguard_workspace_execfix_gpt4omini/ipiguard/under_attack/workspace/results.jsonl` |
| R4-Naive | ASB official summary | direct_prompt_injection naive | gpt-4o-mini | rows=400 | attack success rate = 0.2500% | utility success rate = 0.0000% | `artifact_out_external_runtime/external_runs/20260220_fullpipeline/asb_summary_20260220_official.json` |
| R4-Escape | ASB official summary | direct_prompt_injection escape_characters | gpt-4o-mini | rows=400 | attack success rate = 0.0000% | utility success rate = 0.0000% | `artifact_out_external_runtime/external_runs/20260220_fullpipeline/asb_summary_20260220_official.json` |
| R4-Fake | ASB official summary | direct_prompt_injection fake_completion | gpt-4o-mini | rows=400 | attack success rate = 0.0000% | utility success rate = 0.0000% | `artifact_out_external_runtime/external_runs/20260220_fullpipeline/asb_summary_20260220_official.json` |
| R4-Aggregated | ASB official summary | aggregate over 3 files above | gpt-4o-mini | rows=1200 | attack success rate = 1/1200 = 0.0833% | utility success rate = 0/1200 = 0.0000% | `artifact_out_external_runtime/external_runs/20260220_fullpipeline/asb_summary_20260220_official.json` |

## Notes for Citation

- R1 uses scenario-level OR leakage definition: `OR(C1, C2, C5)`.
- R1 was produced from resumed runs and has more than 96 scenarios in final summaries. The summary JSON is internally consistent and marked `status: OK`.
- R2 is the audited external DRIFT rerun summary across banking, slack, travel, workspace in under-attack mode.
- R3 is the fixed IPIGuard workspace under-attack run after execution-path repair.
- R4 is the ASB official tagged summary with three 400-row files.

## Not Included Here

The following results are still running (or only partial) and therefore excluded from direct citation in this table:

- `artifact_out_external_runtime/external_runs/20260302_agentdojo_native_plain_secureclaw_gpt4omini/agentdojo_native_plain_secureclaw_report.json` (status currently `RUNNING`).
- `artifact_out_external_runtime/external_runs/20260304_agentdojo_secureclaw_contractfix_v4_gpt4omini/secureclaw/under_attack/*/results.jsonl` (early partial monitoring only; full suite not finished).
