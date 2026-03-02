# 实验结果总览（快照）

- 快照时间：`2026-03-02 15:33:37 CET`
- 快照范围：`artifact_out_compare_noprompt`、`artifact_out_external_runtime/external_runs`
- 说明：本文件是“结果索引 + 最新状态”，用于快速定位每类实验的最新产物与当前进展。

## 1) 当前正在进行的实验

1. `IPIGuard` 单任务恢复（按你的要求仅跑一条，防止 RPD 风暴）
- 任务：`under_attack/workspace`
- 运行方式：单进程串行，带 429 退避重试
- 有效结果文件：`artifact_out_external_runtime/external_runs/20260301_external_full_rerun_gpt4omini/ipiguard/under_attack/workspace/results.jsonl`
- 当前进度（快照）：`24/240`（随后日志已到 `25/240`）
- 备注：旧脏数据已移出当前统计输入，备份在同目录 `results.preclean_*.jsonl`

## 2) 最新“可用结果”与对应实验

## 2.1 AgentLeak 官方口径（3264 case）模型评测

| 实验 | 模型 | n_total | 攻击泄露率 attack_leak_rate | 良性通过率 benign_allow_rate | 结果文件 |
|---|---:|---:|---:|---:|---|
| SecureClaw（model-track） | gpt-4o-mini-2024-07-18 | 3264 | 0.0094086 | 1.0000 | `artifact_out_compare_noprompt/fair_secureclaw_model_gpt4o_mini/secureclaw_model_official_summary.json` |
| SecureClaw（model-track） | gpt-5.1-codex-mini | 3264 | 0.0053763 | 0.9869 | `artifact_out_compare_noprompt/fair_secureclaw_model_gpt5_codex_mini/secureclaw_model_official_summary.json` |
| codex native（无防护） | gpt-5.1-codex-mini | 3264 | 0.0161290 | 1.0000 | `artifact_out_compare_noprompt/fair_codex_native_guardrails/native_official_baseline_summary.json` |
| DRIFT baseline（codex） | gpt-5.1-codex-mini | 3264 | 0.0134409 | 1.0000 | `artifact_out_compare_noprompt/fair_codex_drift_baseline/native_official_baseline_summary.json` |
| IPIGuard baseline（codex） | gpt-5.1-codex-mini | 3264 | 0.0161290 | 1.0000 | `artifact_out_compare_noprompt/fair_codex_ipiguard_baseline/native_official_baseline_summary.json` |
| AgentArmor baseline（codex） | gpt-5.1-codex-mini | 3264 | 0.0134409 | 0.9484 | `artifact_out_compare_noprompt/fair_codex_agentarmor_baseline/native_official_baseline_summary.json` |
| openclaw native | openai-codex/gpt-5.1-codex-mini | 3264 | 0.0147849 | 0.0000 | `artifact_out_compare_noprompt/fair_openclaw_native_guardrails/native_official_baseline_summary.json` |

## 2.2 外部基线（ASB / DRIFT / IPIGuard）

### ASB（官方 3 组，各 400）
- 结果文件：`artifact_out_external_runtime/external_runs/20260220_fullpipeline/asb_summary_20260220_official.json`
- `naive-all_lowmem_20260220_official.csv`: rows=400, attack_success_rate=0.0025
- `escape_characters-all_lowmem_20260220_official.csv`: rows=400, attack_success_rate=0.0
- `fake_completion-all_lowmem_20260220_official.csv`: rows=400, attack_success_rate=0.0

### DRIFT（最新完整可用审计）
- 结果文件：`artifact_out_external_runtime/external_runs/20260301_external_full_rerun_gpt4omini/drift_post_audit.json`
- `banking`: ASR=7/144=0.0486, USR=72/144=0.5000
- `slack`: ASR=0/105=0.0000, USR=38/105=0.3619
- `travel`: ASR=5/140=0.0357, USR=86/140=0.6143
- `workspace`: ASR=4/560=0.0071, USR=317/560=0.5661

### IPIGuard（最新重跑，workspace 正在补齐）
- 根目录：`artifact_out_external_runtime/external_runs/20260301_external_full_rerun_gpt4omini/ipiguard`
- benign：
  - `banking`: 16/16 完成，Utility=43.75%
  - `slack`: 21/21 完成，Utility=71.43%
  - `travel`: 20/20 完成，Utility=70.00%
  - `workspace`: 40/40 完成，Utility=67.50%
- under_attack：
  - `banking`: 144/144 完成，结果摘要行存在
  - `slack`: 105/105 完成，结果摘要行存在
  - `travel`: 140/140 完成，结果摘要行存在
  - `workspace`: **进行中**（快照 `24/240`，随后日志到 `25/240`）

## 2.3 AgentDojo native（plain/secureclaw）

- 结果文件：`artifact_out_external_runtime/external_runs/20260302_agentdojo_native_plain_secureclaw_gpt4omini/agentdojo_native_plain_secureclaw_report.json`
- 当前状态：`RUNNING`
- plain：`benign/banking/slack/travel/workspace` 全部完成
- secureclaw：尚未开始写入（entries=0）

## 2.4 parity（同拓扑 + 三层检测 + OR）

- GPT-4o-mini keyed：
  - `artifact_out_compare_noprompt/paper_parity_full_gpt4omini_keyed/paper_parity_agentleak_eval/rows_plain.jsonl`：39
  - `artifact_out_compare_noprompt/paper_parity_full_gpt4omini_keyed/paper_parity_agentleak_eval/rows_secureclaw.jsonl`：39
- GPT-4o-mini（非 keyed 目录）：
  - `artifact_out_compare_noprompt/paper_parity_full_gpt4omini/paper_parity_agentleak_eval/rows_plain.jsonl`：39
  - `artifact_out_compare_noprompt/paper_parity_full_gpt4omini/paper_parity_agentleak_eval/rows_secureclaw.jsonl`：39
- codex-mini low keyed：
  - `artifact_out_compare_noprompt/paper_parity_full_codexmini_low_keyed/paper_parity_agentleak_eval/rows_plain.jsonl`：19
  - `artifact_out_compare_noprompt/paper_parity_full_codexmini_low_keyed/paper_parity_agentleak_eval/rows_secureclaw.jsonl`：19
- codex-mini low localcodex：
  - `artifact_out_compare_noprompt/paper_parity_full_codexmini_low_localcodex/paper_parity_agentleak_eval/rows_plain.jsonl`：21
  - `artifact_out_compare_noprompt/paper_parity_full_codexmini_low_localcodex/paper_parity_agentleak_eval/rows_secureclaw.jsonl`：21

## 2.5 其他验证实验（已产出）

1. 泄露可区分性（MI + classifier）
- `artifact_out_compare_noprompt/leakage_channel_report.json`
- 关键：`unshaped` 可区分显著；`shaped` 接近 chance。

2. 性能与生产参数
- `artifact_out_compare_noprompt/perf_production_report.json`
- 关键：`target_ops_s=25` 已达标；`best_mixed_cover_ops_s=79.139`。

3. 多 agent 联邦授权
- `artifact_out_compare_noprompt/multi_agent_federated_eval.json`
- 关键：7/7 通过，`pass_rate=1.0`。

4. 文档一致性扫描
- `artifact_out_compare_noprompt/docs_consistency_report.json`
- 关键：`status=OK`, `n_missing_paths=0`, `n_stale_tokens=0`。

## 3) 已阅读的历史结果与“最新采用口径”

### 3.1 已阅读历史 run
- `artifact_out_external_runtime/external_runs/20260220_fullpipeline`
- `artifact_out_external_runtime/external_runs/20260228_drift_openai_rerun`
- `artifact_out_external_runtime/external_runs/20260301_drift_intent_aligned_attack_only`
- `artifact_out_external_runtime/external_runs/20260301_drift_intent_aligned_v2`
- `artifact_out_external_runtime/external_runs/20260301_external_full_rerun_gpt4omini`
- `artifact_out_external_runtime/external_runs/20260302_agentdojo_native_plain_secureclaw_gpt4omini`

### 3.2 当前建议“主引用”的最新结果
1. SecureClaw 两模型主结果：
- `artifact_out_compare_noprompt/fair_secureclaw_model_gpt4o_mini/secureclaw_model_official_summary.json`
- `artifact_out_compare_noprompt/fair_secureclaw_model_gpt5_codex_mini/secureclaw_model_official_summary.json`
2. codex/openclaw 对照基线：
- `artifact_out_compare_noprompt/fair_codex_*_baseline/native_official_baseline_summary.json`
- `artifact_out_compare_noprompt/fair_openclaw_native_guardrails/native_official_baseline_summary.json`
3. 外部 DRIFT/IPIGuard 最新重跑：
- `artifact_out_external_runtime/external_runs/20260301_external_full_rerun_gpt4omini/drift_post_audit.json`
- `artifact_out_external_runtime/external_runs/20260301_external_full_rerun_gpt4omini/ipiguard/**/results.jsonl`

## 4) 注意事项（避免误读）

1. `fair_full_report.json` 目前仍引用较老 external 报告（`20260220_fullpipeline`），不代表你刚启动/补跑中的最新 IPIGuard workspace 状态。
2. `IPIGuard under_attack/workspace` 当前为进行中，不应与已完成 suite 做最终汇总对比。
3. `results.preclean_*.jsonl` 是历史脏数据备份，不参与当前统计。
