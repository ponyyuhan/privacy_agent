# Benchmark Motivation & Progress

更新时间：`2026-02-20 21:15 CET`

## 1. 当前目标
- 按“官方 benchmark 原生执行路径”完成全量评估，不使用映射代理结果替代真实运行。
- 主对比保持一致：`mirage_full` 与 `codex_native`（以及指定官方防护基线）。
- 在全量执行中严格控制内存与并发，避免再次触发系统崩溃。

## 2. Motivation（为什么这样做）
- 映射或代理评估虽然快，但无法支撑“正式实验结论”。
- 论文/报告需要给出可追溯、可复查、可复跑的原始结果路径。
- 之前中断点发生在 ASB 全量阶段，说明必须把“稳定性与资源约束”作为第一优先级，而不是盲目堆并发。

## 3. 当前思路（执行策略）
- 原则 1：先保证“真跑通”，再扩并发。
- 原则 2：所有重任务采用可恢复（resume）策略，避免中断后重头再跑。
- 原则 3：将模型接入层与 benchmark 运行层解耦。
  - 接入层：本地 `codex_chat_shim`（OpenAI `chat.completions` 兼容）。
  - 运行层：各 benchmark 官方 runner（AgentDojo/ASB/DRIFT/IPIGuard/WASP/VPI）。

执行顺序：
1. 先收敛 AgentDojo 全量（可断点续跑、回报快）。
2. 再独占运行 ASB 三类 DPI 全量（`naive/escape_characters/fake_completion`）。
3. 并行推进 DRIFT / IPIGuard 的官方入口验证与全量执行。
4. 对 WASP / VPI 在基础设施不满足时给出硬阻塞证据与补齐清单。

## 4. 已完成工作
- ASB 已完成低内存改造（`max_workers` + `max_inflight` + bounded scheduling），并通过 smoke。
- 新增运行与监控脚本：
  - `scripts/run_asb_dpi_full_lowmem.sh`
  - `scripts/agentdojo_progress.py`
  - `scripts/asb_csv_summary.py`
- `codex_chat_shim` 已支持：
  - `reasoning_effort=low`（成本控制）
  - `ignore_request_model`
  - ASB 计划 JSON fallback（减少 plan 阶段空转重试）
- IPIGuard 关键依赖已补齐，`run/eval.py --help` 可运行。
- DRIFT 可在正确 `PYTHONPATH` 下启动官方入口。

## 5. 当前进展快照

### 5.1 AgentDojo（`v1.2.2`）
模型目录：`third_party/agentdojo/runs/gpt-4o-mini-2024-07-18`

- `workspace`: `614 / 614`（完成）
- `travel`: `167 / 167`（完成）
- `banking`: `169 / 169`（完成）
- `slack`: `131 / 131`（完成）

运行拓扑：
- 已收敛完成，当前仅保留 `127.0.0.1:18000` 供外部 benchmark 统一入口复用

### 5.2 ASB（DPI 全量）
- 当前状态：已切换到正式全量运行（AgentDojo 收敛后启动）。
- 计划顺序：`naive -> escape_characters -> fake_completion`
- 结果输出目录：`third_party/ASB/logs/direct_prompt_injection/gpt-4o-mini/no_memory/`
- 当前 run：
  - `RUN_TAG=20260220_official`
  - `TASK_NUM=1`（官方 400 任务口径）
  - `MAX_WORKERS=4`, `MAX_INFLIGHT=4`（经调优后的稳定吞吐档）
  - `ASB_LLM_REQUEST_TIMEOUT=120`, `ASB_REFUSE_JUDGE_MODE=heuristic`
  - `naive-all_lowmem_20260220_official.csv`: `rows_done=15/400`（持续增长）
- 已补齐可恢复能力：
  - `third_party/ASB/main_attacker.py` 支持按 `(Agent Name, Attack Tool)` 断点跳过（`TASK_NUM=1`）
  - `scripts/run_asb_dpi_full_lowmem.sh` 支持按 `EXPECTED_ROWS` 判断“完整/部分”并在同一 CSV 上续跑

### 5.3 DRIFT / IPIGuard / WASP / VPI
- DRIFT：官方 runner 可启动并已纳入统一串行管线（ASB 后自动执行）。
- IPIGuard：依赖修复后入口可运行并已纳入统一串行管线（ASB 后自动执行）。
- WASP：需要 `python3.10` + WebArena docker 环境（`REDDIT/GITLAB/DATASET`）。
- VPI：需要 VM/FastAPI/browser-use 基础设施，不满足时会记录硬阻塞。

## 6. 当前风险与应对
- 风险：AgentDojo `workspace` 规模较大、单条任务耗时波动大。
  - 应对：分片并行 + 可恢复写盘 + 定期进度快照。
- 风险：ASB 在 plan 阶段可能产生高重试开销。
  - 应对：shim 侧结构化 fallback + 单线程低内存串行。
- 风险：ASB 单调度器架构下，盲目提高 `max_workers` 会拉长首条样本完成时间。
  - 应对：采用 `workers=4` 稳定档位，并加超时/快速拒答判定避免写盘前卡住。
- 风险：外部 benchmark 环境依赖复杂（WASP/VPI）。
  - 应对：先形成“可跑集”完整结果，再逐项补基础设施。

## 7. 下一步（执行清单）
1. 完成 AgentDojo `workspace` 缺口补齐并导出汇总。
2. 启动并完成 ASB 三类 DPI 全量串行跑，输出 CSV 与汇总 JSON。
3. 跑通 IPIGuard 与 DRIFT 的全量官方配置并写入统一对比表。
4. 对 WASP / VPI 输出“已运行证据 + 阻塞点 + 最短补齐路径”。
5. 更新统一报告（README + 结果文档 + artifact 路径索引）。

## 10. 当前执行管线（后台）
- 主脚本：`scripts/run_full_external_eval_pipeline.sh`
- 主日志：`artifact_out_external_runtime/full_pipeline_20260220.log`
- 串行顺序：`AgentDojo检查 -> ASB全量 -> DRIFT全量 -> IPIGuard全量 -> 统一汇总`

## 8. 进度查询
- 实时统计：
```bash
PYTHONPATH=third_party/agentdojo/src python scripts/agentdojo_progress.py \
  --model-dir third_party/agentdojo/runs/gpt-4o-mini-2024-07-18 \
  --benchmark-version v1.2.2
```

- 运行状态快照：
`artifact_out_external_runtime/runtime_status.json`

## 9. README 旧内容更新（已加入）
- 已在 `README.md` 增加“1.6 README 旧内容校准说明”。
- 已明确第 24 节样例结果不等价于外部 benchmark 全量完成，避免误读。
- 已补充三轨统一评测的双口径路径说明（历史口径 + 当前无 anti-leak prompt 口径）。
- 外部 benchmark 全量完成后，将在 README 增加“最终冻结结果索引（commit/tag + 路径）”。
