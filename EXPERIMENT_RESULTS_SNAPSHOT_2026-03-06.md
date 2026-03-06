# 实验结果总览（快照）

- 快照时间：`2026-03-06`
- 说明：本文件记录 03-06 对 DRIFT/IPIGuard 串行续跑、后台监督与论文叙事改写的最新状态。

## 1) DRIFT / IPIGuard 当前后台状态

- 后台 supervisor：`scripts/supervise_drift_ipiguard_seq_resume.sh`
- 状态文件：`artifact_out_external_runtime/external_runs/20260304_agentdojo_four_parallel_rerun_v1/drift_ipiguard_seq_resume_status.md`
- 监督日志：`artifact_out_external_runtime/external_runs/20260304_agentdojo_four_parallel_rerun_v1/logs/drift_ipiguard_seq_resume_supervisor.log`
- 运行策略：严格串行，`DRIFT` 全部完成后自动启动 `IPIGuard`。

截至本快照生成时（Europe/Berlin）：

1. `DRIFT`
- benign：全部完成
- under_attack：
  - `banking 144/144`
  - `slack 96/105`
  - `travel 0/140`
  - `workspace 0/240`

2. `IPIGuard`
- benign：全部完成
- under_attack：
  - `banking 47/144`
  - `slack 0/105`
  - `travel 0/140`
  - `workspace 0/240`

## 2) 当天完成的运行时修复

1. `scripts/run_drift_ipiguard_full_lowmem.sh`
- 恢复更稳健的 DRIFT 默认重试参数：
  - `DRIFT_OPENAI_MAX_RETRIES=8`
  - `DRIFT_CHAT_RETRIES=6`
  - `DRIFT_CHAT_RETRY_BACKOFF_S=1.5`
- 修正 IPIGuard 重试环境变量与实际源码读取名不一致的问题：
  - 改为传递 `IPIGUARD_LLM_RETRY_BACKOFF_S`
  - 改为传递 `IPIGUARD_LLM_RETRY_HINT_SCALE`
  - 保留旧 `IPIGUARD_LLM_RETRY_MULTIPLIER` 作为兼容别名输入来源

2. `scripts/supervise_drift_ipiguard_seq_resume.sh`
- 新增 detached supervisor：
  - 自动判断 DRIFT / IPIGuard 完成度
  - 失败后自动重启下一轮 pass
  - 每分钟写一次 Markdown / JSON 状态文件
  - 便于后续会话直接接续，不依赖当前终端

## 3) 结果口径

1. 本快照中的 DRIFT/IPIGuard 数字仍是 `RUNNING/partial`，不可直接进入主文可引用结果表。
2. `LATEST_CITABLE_RESULTS.md` 继续只保留已完成、可解析、可复核的结果。
3. 当前串行续跑的主要目的是在高频 `429` 环境下稳定跑满公平分母，而不是提前输出不完整最终结论。

## 4) 论文改动（03-06）

1. `neurips_2025.tex`
- 摘要改为显式三支柱主线：
  - 非旁路执行边界
  - 隐私保护的策略外包
  - 运行时明文盲

2. `paper_full_body.tex`
- Introduction 重写：加入 running example、前置 thesis、提前说明为什么现有方法不够。
- Evaluation 重写口径：主表不再混放不可比延迟，延迟单独放入 RQ4 讨论。
- Related Work 重写：按 runtime guardrails / execution boundaries / privacy-preserving outsourcing / plaintext confinement 的逻辑重组，并更明确地区分 Faramesh 与 SecureClaw。

## 5) 清理与仓库整理

1. 删除了跟当前主文重复的旧副本：`paper_full_body copy.txt`
2. 旧的单用途 watcher 流程已被新的 supervisor 替代；后续以 `scripts/supervise_drift_ipiguard_seq_resume.sh` 为准。
