# MIRAGE-OG++

可信网关 + 双策略服务 + 双授权执行器 + Skill Capsule 的可运行研究原型（paper artifact + real agents）。

本仓库实现的核心目标是：
- 把不可信 agent/skill 从副作用执行链路里剥离出去。
- 在不把明文查询暴露给单个策略服务的前提下，仍能使用集中式策略库。
- 用 PREVIEW->COMMIT 和 executor 双授权把 side effect 做成不可绕过（fail-closed）。

这不是生产级安全产品，而是可复现、可审计、可扩展的研究原型。

---

## 1. 项目定位与结论先行

### 1.1 你可以把本项目理解为
一个最小可信执行线（minimal trusted enforcement line）：

1. Agent 只能调用一个高层工具 `act(intent_id, inputs, constraints, caller)`。
2. Gateway 负责策略预检查（PIR + MPC PREVIEW）并签发事务 token（`tx_id`）。
3. 真正副作用（发消息/外联/启用 skill）只能由 Executor 执行。
4. Executor 不信任单点网关结论，必须验证来自两台策略服务的 MAC commit proofs。

### 1.2 当前已实现的关键能力
- Level 1: Secret Myopia（敏感明文不下发给 agent，只发 handle）。
- Level 2: Myopic Intent Routing（不提供任意命令执行面，只暴露 intent）。
- 2-server PIR（DPF/FSS）用于 allowlist/DLP/IOC membership。
- PREVIEW->COMMIT 的 MPC policy engine（GMW + Beaver）与双签名 commit proofs。
- Skill ingress（Import -> CheckSkillInstallPolicy -> CommitSkillInstall）。
- per-skill workload identity（`workload_token` -> `caller=skill:<digest>`）。
- capsule（macOS + Linux smoke 路径）+ UDS netless 传输。
- real agent 验证（OpenClaw + OpenAI OAuth，NanoClaw runtime）。

### 1.3 不在本仓库“已完成”范围内
- 通用高性能 MPC 框架替换（如 MOTION2NX 全量接管）。
- 生产级抗流量分析（cover traffic、多租户混洗、常时延整形）。
- 生产级跨平台沙箱硬化（完整 seccomp/AppContainer/内核逃逸对抗）。

### 1.4 论文/Artifact 关键文档索引（建议按此顺序阅读）
- `FORMAL_SECURITY.md`：形式化安全主张（NBE/SM/SAP/SCS）的游戏/定理框架与代码映射。
- `appendix_security.tex`：附录级归约证明链（无双证明不可提交副作用，归约到 MAC 不可伪造 + 哈希绑定一致性 + replay/TTL/session/caller 绑定）。
- `LEAKAGE_MODEL.md`：允许泄露函数 `L_policy`/`L_sys` 的严格定义与 shaping/bundling/confirm-path 的通道分解。
- `LEAKAGE_EVIDENCE.md`：逐通道 `L_Ci` 的官方/合成实证索引（含复现实验路径）。
- `BASELINES_FAIRNESS.md`：强基线同口径对比的语义、威胁模型与公平性说明。
- `PERFORMANCE.md`：固定形状（pad+cover+mixer）下的吞吐/延迟曲线与多核 scaling 叙事。
- `ALGORITHMS.md` / `ALGORITHMS_CN.md`：协议与算法描述（含稀疏 PIR 快路径等）。
- `MOTIVATION_PAPER.md` / `MOTIVATION_PAPER_CN.md`：论文级动机与问题定义（中英文）。

---

## 2. 快速开始

### 2.1 最短路径（本地 deterministic demo）
```bash
pip install -r requirements.txt
python main.py demo
```

### 2.2 Artifact（最小可复现，推荐先跑）
```bash
python main.py artifact
```
这会执行：
- 单元测试
- FSS/DPF 微基准
- 端到端报告生成（`artifact_out/report.json`）
- Python/Rust 策略服务吞吐短测

### 2.3 Paper-grade Artifact（论文级流水线，包含 formal+baselines+plots）
```bash
python main.py paper-artifact
```
这会在 `artifact_out/` 额外生成：
- 形式化安全检查输出（`artifact_out/security_game_nbe.json`）
- 强基线 + 大规模评测（`artifact_out/paper_eval/*`）
- policy server 吞吐曲线（`artifact_out/policy_perf/*`）
- shaping 曲线（`artifact_out/shaping_perf/*`）
- native runtime baselines（`artifact_out/native_baselines/*`）
- real-agent 闭环 campaign（`artifact_out/campaign/*`）
- 自动产图（`artifact_out/figures/*.svg`）
- 可复现 manifest（`artifact_out/repro_manifest.json`）

注意：其中 native/real-agent 相关步骤可能需要外部模型/凭据；脚本会尽量 `SKIP/continue`，不把整个流水线跑挂。

可选（更论文级、但更耗时）：
- official AgentLeak `C1..C5` 同口径 fair compare（MIRAGE + Codex + OpenClaw）：
  - 设置 `RUN_FAIR_FULL=1`
  - 输出：`artifact_out_compare/fair_full_report.json` 与 `artifact_out_compare/stats/fair_full_stats.json`
  - 提示：这一步会调用外部模型，可能非常耗 token。可用环境变量降低成本/缩短运行时间：
    - `CODEX_BASELINE_MODEL=gpt-5.1-codex-mini`（默认）
    - `CODEX_BASELINE_REASONING=low`（默认）
    - `OPENCLAW_NATIVE_MODEL=openai-codex/gpt-5.1-codex-mini`（默认）
    - `CODEX_BASELINE_CONCURRENCY=4`（并发，视限流而定）
    - `NATIVE_BASELINE_MAX_GROUPS=50`（只评测前 50 个 scenario，用于快速 sanity-check）

### 2.4 真实 agent（OpenClaw + OpenAI OAuth）
```bash
bash scripts/setup_openclaw.sh
OPENCLAW_STATE_DIR="artifact_out/openclaw_state" bash scripts/setup_openclaw_state.sh
OPENCLAW_STATE_DIR="artifact_out/openclaw_state" \
  integrations/openclaw_runner/node_modules/.bin/openclaw models auth login --provider openai-codex
bash scripts/run_openclaw.sh
```

### 2.5 真实 agent（NanoClaw 运行时）
```bash
export ANTHROPIC_API_KEY="..."
bash scripts/run_nanoclaw.sh
```

---

## 3. 信任边界与威胁模型

### 3.1 参与方
- Untrusted: agent runtime、skills、prompt 输入、第三方 skill 文档。
- Trusted TCB: gateway。
- Honest-but-curious + non-colluding: PolicyServer0 / PolicyServer1。
- Trusted enforcement point: executor（验证双 proof 后才执行 side effect）。

### 3.2 对手能力（本仓库覆盖）
- Prompt injection 诱导 agent 泄露敏感数据。
- 恶意 skill（SKILL.md）诱导下载执行、二阶段加载、外联 C2。
- 试图绕开 gateway 直接请求执行器或直接网络外发。
- 单个策略服务想从查询日志反推 recipient/domain/token。

### 3.3 关键假设
- 两台策略服务至少一台不与另一台合谋。
- Gateway 未被攻破（本项目把最小可信边界放在 gateway + executor）。
- 若声明 SCS（Skill-Confined Safety），需满足 capsule mediation contract（见第 10 节）。

### 3.4 明确不承诺
- 若对手同时攻破 gateway 与 executor，本仓库不保证不可绕过。
- 若两台策略服务合谋，PIR 的单点隐私性质不成立。
- 若不使用 capsule 或 capsule 放宽网络/执行限制，skill 可绕过 `act` 面。

---

## 4. 形式化安全性质（与代码路径映射）

下列性质是 README、`EFFECTIVENESS.md`、artifact 输出一致的“工程化定义”。

### 4.1 NBE: Non-Bypassable Effects
定义（工程版）：
- 任意副作用请求（send/fetch/webhook/skill_install）若未携带两台策略服务对同一 `(action_id, program_id, request_sha256)` 的有效 commit proofs，则 executor 必须拒绝。

代码路径：
- proof 校验与重构：`executor_server/server.py:_verify_commit_evidence`
- side effect 接口：
  - `/exec/send_message`
  - `/exec/fetch`
  - `/exec/webhook`
  - `/exec/skill_install`

artifact 证据：
- `artifact_out/report.json:executor_bypass_attempts`
- `artifact_out/report.json:baselines.no_nbe_insecure_executor`

### 4.2 SM: Secret Myopia
定义（工程版）：
- 对敏感输入（例如私钥文件），agent 在默认路径只能收到 opaque handle，不能直接得到明文。
- 明文释放必须走显式 `Declassify` 且满足 confirm 约束。

代码路径：
- handle 发行：`gateway/executors/fsexec.py`
- handle 存储与绑定：`gateway/handles.py`
- 解密/降级：`gateway/executors/cryptoexec.py`

artifact 证据：
- `report.json:malicious.read_file` -> `SENSITIVE_HANDLE_RETURNED`
- `report.json:malicious.declassify` -> `REQUIRE_CONFIRM`

### 4.3 SAP: Single-Auditor Privacy
定义（工程版）：
- 任一单个 policy server 仅观察到本地 transcript 元数据时，不应恢复具体查询对象（recipient/domain/token）的身份信息。

实现机制：
- 2-server PIR（DPF/FSS）
- fixed-shape 查询 + bundle + shadowing

代码路径：
- DPF/FSS: `fss/dpf.py`
- PIR 客户端: `gateway/fss_pir.py`
- transcript 记录: `gateway/fss_pir.py`（`MIRAGE_TRANSCRIPT_PATH`）
- 泄露评估: `scripts/artifact_report.py`（`leakage_eval`, `outsourcing_comparison`）

artifact 证据：
- `report.json:leakage_eval`
- `report.json:outsourcing_comparison`

### 4.4 SCS: Skill-Confined Safety
定义（工程版）：
- 在 capsule mediation contract 成立时，恶意 skill 无法通过直接文件/进程/网络路径绕过 `act` 执行链。

代码路径：
- macOS profile: `capsule/capsule.sb`
- capsule smoke: `capsule/smoke.py`, `capsule/run_smoke.sh`, `capsule/run_smoke_linux.sh`
- UDS transport: `gateway/http_server.py`, `capsule/mcp_proxy.py`, `common/uds_http.py`

artifact 证据：
- `report.json:capsule_smoke`
- `report.json:baselines.no_capsule_direct_exfil`
- `report.json:baselines.capsule_loopback_http_exfil`

---

## 5. 系统架构

```text
+-------------------------------+
| Untrusted Agent Runtime       |
| - OpenClaw / NanoClaw / demo  |
| - only tool: mirage_act / act |
+-------------------------------+
                |
                | MCP stdio
                v
+-------------------------------+      optional
| Capsule MCP Proxy             |------------------------+
| - forwards only /act          |                        |
+-------------------------------+                        |
                | HTTP over UDS (recommended)            |
                v                                         |
+-------------------------------------------------------------------+
| Gateway (trusted TCB)                                              |
| - intent router                                                    |
| - handle store (Level 1)                                           |
| - capability projection                                             |
| - PIR client (DPF/FSS, 2 servers)                                  |
| - MPC PREVIEW->COMMIT orchestration                                |
| - tx store / audit                                                  |
+-------------------------------------------------------------------+
                |                        |
                | signed PIR + /mpc/*    | commit payload
                v                        v
+----------------------------+   +-------------------------------+
| PolicyServer0 (HBC)        |   | PolicyServer1 (HBC)           |
| - bitset DB / DFA blocks   |   | - bitset DB / DFA blocks      |
| - commit proof (MAC)       |   | - commit proof (MAC)          |
+----------------------------+   +-------------------------------+
                \                        /
                 \ dual proofs          /
                  v                    v
                 +------------------------+
                 | Executor               |
                 | - verify both proofs   |
                 | - enforce sanitize     |
                 | - execute side effect  |
                 +------------------------+
```

---

## 6. 仓库结构（按职责）

### 6.1 Gateway 与执行路径
- `gateway/mcp_server.py`: MCP stdio server（tool: `act`, alias: `mirage.act`）
- `gateway/http_server.py`: HTTP `/act`（支持 UDS）
- `gateway/router.py`: intent 分发、capability 检查、audit、workload_token override
- `gateway/egress_policy.py`: egress PREVIEW/COMMIT（PIR + DSL->circuit + MPC）
- `gateway/skill_policy.py`: skill ingress PREVIEW/COMMIT
- `gateway/handles.py`: handle store（可 SQLite 持久化）
- `gateway/tx_store.py`: tx store（可 SQLite 持久化）
- `gateway/capabilities.yaml`: caller->intent/egress 能力映射
- `gateway/executors/*.py`: 每个 intent 的业务执行器

### 6.2 策略服务
- `policy_server/build_dbs.py`: 构建 bitset / bundle / DFA 数据
- `policy_server/server.py`: `/pir/query_*_signed`, `/mpc/*`
- `policy_server/mpc_engine.py`: GMW+Beaver 布尔电路执行
- `policy_server/policy.yaml`: demo 策略与 DSL program
- `policy_server_rust/`: Rust compiled backend（高吞吐 O(N) 内积）

### 6.3 执行器
- `executor_server/server.py`: 副作用入口 + 双 proof 验证 + patch 应用

### 6.4 Capsule
- `capsule/capsule.sb`: macOS sandbox profile
- `capsule/mcp_proxy.py`: capsule 内 MCP->gateway 转发
- `capsule/smoke.py`: 读文件/exec/网络绕过 smoke

### 6.5 Agent 接入
- `agent/`: scripted deterministic client
- `integrations/openclaw_plugin/mirage_ogpp.ts`: OpenClaw 工具桥接
- `integrations/openclaw_runner/`: pinned OpenClaw CLI
- `integrations/nanoclaw_runner/`: NanoClaw 运行时脚本

### 6.6 脚本
- `scripts/run_all.sh`: demo 全链路
- `scripts/run_artifact.sh`: artifact 全链路
- `scripts/run_paper_artifact.sh`: paper-grade 全流水线（formal + baselines + eval + plots）
- `scripts/run_openclaw.sh`: OpenClaw 真实 agent 验证
- `scripts/run_nanoclaw.sh`: NanoClaw 真实 agent 验证
- `scripts/setup_openclaw_state.sh`: 解决 OpenClaw provider plugin discoverability
- `scripts/import_codex_oauth_to_openclaw.py`: Codex OAuth 导入 OpenClaw state
- `scripts/security_game_nbe_check.py`: NBE 安全游戏/定理的可执行检查
- `scripts/paper_eval.py`: 强基线 + 攻击/良性任务集评测（含置信区间/显著性）
- `scripts/bench_policy_server_curves.py`: policy server 曲线（batch/padding 对吞吐影响）
- `scripts/bench_policy_server_scaling.py`: policy server 单核/多核 scaling（RAYON 线程数）+ JSON/Binary 传输对比
- `scripts/bench_e2e_shaping_curves.py`: 端到端 shaping 曲线（PIR/MPC mixing + cover traffic + pad_to）
- `scripts/native_guardrail_eval.py`: Codex/Claude/OpenClaw 原生防护强基线
- `scripts/real_agent_campaign.py`: real-agent 闭环评测与证据链产出
- `scripts/verify_audit_log.py`: 审计日志 hash-chain 校验（防篡改）
- `scripts/plot_paper_figures.py`: 产图（SVG，无 matplotlib 依赖）
- `scripts/write_repro_manifest.py`: 版本/seed/平台 manifest（复现实验工件）

---

## 7. 协议细节：从 `act` 到 side effect

### 7.1 统一入口 `act`
接口：
```json
{
  "intent_id": "SendMessage",
  "inputs": {...},
  "constraints": {...},
  "caller": "openclaw"
}
```

Router 行为：
1. 可选校验 `constraints.workload_token`，成功则覆盖 caller 为 `skill:<digest>`。
2. 加载 caller capability（`gateway/capabilities.yaml`）。
3. intent 分发到相应 executor（`msgexec/netexec/webhookexec/skillexec/...`）。

### 7.2 Egress PREVIEW -> COMMIT（SendMessage/FetchResource/PostWebhook）

#### PREVIEW 阶段（无副作用）
1. gateway 生成 `action_id`，计算 `request_sha256`（见 `common/canonical.py`）。
2. 执行 handle-flow 强约束（高敏 handle 不允许外流）。
3. 发起固定形状 PIR 查询（oblivious bundle + 统一查询面）：
   - 统一查询 `db=policy_bundle`
   - 单次 PIR 批量内同时覆盖：recipient / domain / DLP tokens / IOC domains / install markers
   - 可选启用 microbatch mixing + padding/cover traffic（见 `LEAKAGE_MODEL.md`）
4. 组装 secret-shared 输入并运行统一 MPC circuit（`policy_unified_v1`）：
   - 输出 `allow_pre`, `need_confirm`, `patch0`, `patch1`
5. 两台 policy server 返回 MAC-signed commit proofs。
6. gateway 写入 `tx_store`，返回 `tx_id` 和 preview 结果。

#### COMMIT 阶段（有副作用）
1. agent 使用同 intent（可带 `tx_id`）发起 commit。
2. gateway `commit_from_tx` 检查：
   - `tx_id` 有效且未过期
   - session/caller 绑定一致
   - `need_confirm==1` 时必须 `user_confirm=true`
3. gateway 将 commit evidence 转发 executor。
4. executor 验证双 proof + request hash 绑定 + TTL + program_id。
5. executor 重构输出位并在本地强制应用 `sanitize_patch`，再执行 side effect。

### 7.3 Skill Ingress PREVIEW -> COMMIT

1. `ImportSkill`: 只 staging，不执行代码；返回 `SKILL_PACKAGE` 的 HIGH handle。
2. `DescribeSkill`: 返回脱敏摘要与风险解释（不泄漏具体 IOC 规则）。
3. `CheckSkillInstallPolicy`:
   - 提取域名/IP、install markers、base64 obfuscation
   - IOC/install 走 PIR membership
   - 与 capability bit 一起进入统一 `policy_unified_v1` MPC program（intent shadowing）
   - 返回 `tx_id` / `need_confirm` / reason
4. `CommitSkillInstall`:
   - executor 校验双 proofs 后启用 skill
   - mint `workload_token`（HMAC，session-bound）
5. 后续 skill 调用：携带 `workload_token`，gateway 强制 caller 为 `skill:<digest>`。

---

## 8. 数据结构与绑定语义

### 8.1 HandleRecord（`gateway/handles.py`）
关键字段：
- `handle`, `label`, `sensitivity`
- `session`, `caller`
- `issuer_intent`
- `allowed_sinks`
- `ttl_seconds`, `revoked`

安全语义：
- handle 必须匹配原 session/caller；否则拒绝。
- 高敏 handle 默认不能进入外发 sink。

### 8.2 TxRecord（`gateway/tx_store.py`）
关键字段：
- `tx_id`
- `intent_id`, `action_id`, `request_sha256`
- `session`, `caller`
- `preview`（含 commit evidence）
- `ttl_seconds`, `revoked`

安全语义：
- `tx_id` 事务 token 绑定 caller+session+request hash。

### 8.3 request hash 绑定（`common/canonical.py`）
`request_sha256_v1(intent_id, caller, session, inputs)`
- gateway 与 executor 必须一致计算。
- commit-phase 的 `user_confirm` 不参与 hash（允许同一 preview token 被 confirm）。

### 8.4 sanitize patch（`common/sanitize.py`）
- `PATCH_NOOP = 0`
- `PATCH_REDACT = 1`
- `PATCH_CLAMP_LEN = 2`
- `PATCH_REWRITE_DOMAIN_TO_PROXY = 3`

executor 端强制应用 patch，不由 agent 自主决定。

---

## 9. PIR 与 MPC 机制（代码对齐版）

### 9.1 2-server PIR（DPF/FSS）

给定 bitset DB `D[0..N-1]`，查询索引 `alpha`：

1. Gateway 生成 DPF key shares `(k0, k1)`，满足：
   - `Eval(k0, x) XOR Eval(k1, x) = 1` 当且仅当 `x == alpha`
   - 其他位置为 0
2. P0, P1 分别计算：
   - `a_s = XOR_x (D[x] & Eval(ks, x))`
3. Gateway 重构：`a = a0 XOR a1`

本仓库实现位置：
- keygen/eval: `fss/dpf.py`
- query client: `gateway/fss_pir.py`
- server inner-product: `policy_server/db.py`（Python）和 `policy_server_rust/`（Rust）

### 9.2 Signed PIR proofs
`/pir/query_batch_signed` 返回：
- `ans_shares`
- `proof = {v, kind, server_id, kid, ts, action_id, db, keys_sha256, resp_sha256, mac_b64}`

executor 会对两份 proof 做 MAC 校验与 action/db/ts 约束校验。

### 9.3 MPC commit proofs
`/mpc/finalize` 返回：
- `outputs`（该方 share）
- `proof = {v, kind=commit, server_id, kid, ts, action_id, program_id, request_sha256, outputs, commit_tag_share_b64, mac_b64}`

executor：
- 验证两份 MAC proof
- XOR 重构 `allow_pre/need_confirm/patch bits`
- 拒绝不满足约束的请求

---

## 10. Capsule 与传输模式

### 10.1 推荐：UDS + netless
- gateway: `MIRAGE_HTTP_UDS=/tmp/mirage_ogpp_gateway.sock`
- capsule proxy: `MIRAGE_GATEWAY_UDS_PATH=/tmp/mirage_ogpp_gateway.sock`
- capsule 网络保持禁用

这一路径能避免 loopback HTTP 被恶意代码直接利用。

### 10.2 调试路径：loopback HTTP（不推荐用于安全主张）
- gateway: `MIRAGE_HTTP_BIND=127.0.0.1`, `MIRAGE_HTTP_PORT=...`
- capsule profile 需允许 loopback 网络

### 10.3 Capsule mediation contract
SCS 主张仅在以下前提下成立：
- 无宿主敏感路径读权限
- 无 direct outbound 网络
- 无任意进程执行

artifact 会用 smoke 测试验证上述行为是否达成。

---

## 11. Intent 目录（实现层）

Router 已实现的 intent（是否可用取决于 capability 配置）：

- 文件/工作区
  - `ReadFile`
  - `WriteWorkspaceFile`
  - `ReadWorkspaceFile`
  - `ListWorkspaceFiles`
- 敏感能力
  - `ReadSecret`
  - `UseCredential`
  - `Declassify`
  - `DescribeHandle`
  - `RevokeHandle`
  - `RevokeSession`
- 外发/网络
  - `CheckMessagePolicy`
  - `SendMessage`
  - `CheckFetchPolicy`
  - `FetchResource`
  - `CheckWebhookPolicy`
  - `PostWebhook`
- C2 inter-agent 中介
  - `SendInterAgentMessage`
  - `ReceiveInterAgentMessages`
- C5 memory 服务
  - `MemoryWrite`
  - `MemoryRead`
  - `MemoryList`
  - `MemoryDelete`
- C1 最终输出闸门
  - `FinalizeOutput`
- skill ingress
  - `ImportSkill`
  - `DescribeSkill`
  - `CheckSkillInstallPolicy`
  - `CommitSkillInstall`
  - `ListEnabledSkills`

---

## 12. Capability 投影与 workload identity

### 12.1 caller capability
`gateway/capabilities.yaml` 定义：
- `allow_intents`
- egress bits: `send_message`, `fetch_resource`, `post_webhook`, `skill_install`

### 12.2 per-skill workload identity
流程：
1. skill 被 executor 成功 enable 后，executor 返回 `workload_token`。
2. skill 后续调用在 `constraints.workload_token` 附带该 token。
3. gateway 验签并将 caller 覆写为 `skill:<digest>`。
4. capability 命中 `skill:*`（或更细粒度）规则。

代码：
- token mint/verify: `common/workload_token.py`
- caller override: `gateway/router.py`
- token issuance: `executor_server/server.py:/exec/skill_install`

---

## 13. 策略语言（DSL）

文件：`policy_server/policy.yaml`

### 13.1 egress program
`policy_programs.egress_v1` 包含 `SendMessage/FetchResource/PostWebhook` 三个子程序，表达式语法支持：
- `&`、`|`、`^`、`~`
- 常量 `0/1`
- 括号

输出位：
- `allow_pre`
- `need_confirm`
- `patch0` / `patch1`（组成 patch_id）

### 13.2 skill ingress program
`policy_programs.skill_ingress_v1` 输入：
- `cap_skill_install`
- `ioc_hit`
- `install_hit`
- `base64_obf`

输出同上（allow/confirm/patch）。

### 13.3 unified program（实现侧）
实现中默认使用统一 program id（`policy_unified_v1`），它会将：
- `policy_programs.egress_v1` 的三个 intent 公式
- `policy_programs.skill_ingress_v1` 的输出公式
组合成单一常量形状的 MPC circuit，并通过 intent one-hot bit 做 secret mux，从而在 policy server 侧隐藏 intent 类别。

代码：`gateway/policy_unified.py`

---

## 14. 运行方式与脚本说明

### 14.1 `python main.py demo`
等价于 `bash scripts/run_all.sh`：
- build DBs
- 启动双 policy server + executor
- 跑 benign/malicious scripted agent

### 14.2 `python main.py artifact`
等价于 `bash scripts/run_artifact.sh`：
1. unit tests
2. `bench_fss.py`
3. `artifact_report.py`
4. `bench_e2e_throughput.py`（python）
5. `bench_e2e_throughput.py`（rust，可选）

### 14.3 `bash scripts/run_openclaw.sh`
- 自动启动后端服务
- 启动 OpenClaw gateway
- 执行 benign + malicious prompt
- 输出 `artifact_out/openclaw_*.json`

### 14.4 `bash scripts/run_nanoclaw.sh`
- 需要 `ANTHROPIC_API_KEY` 或 `CLAUDE_CODE_OAUTH_TOKEN`
- 执行 NanoClaw 运行时的同类验证

### 14.5 `python main.py paper-artifact`
等价于 `bash scripts/run_paper_artifact.sh`，用于论文级评测/产图：
1. 单元测试
2. NBE 形式化检查（见 `FORMAL_SECURITY.md` 与 `scripts/security_game_nbe_check.py`）
3. baselines + 大规模评测（`scripts/paper_eval.py`）
4. AgentLeak-style 逐通道评测（`C1..C7`，synthetic suite；`scripts/agentleak_channel_eval.py`）
5. official AgentLeak `C1..C5` 的同口径 fair compare（可选，MIRAGE + Codex + OpenClaw；见 `BASELINES_FAIRNESS.md`）
   - 默认跳过；设置 `RUN_FAIR_FULL=1`
   - 输出：`artifact_out_compare/fair_full_report.json` 与 `artifact_out_compare/stats/fair_full_stats.json`
6. policy server 吞吐曲线（`scripts/bench_policy_server_curves.py`）
7. policy server 单核/多核 scaling + JSON/Binary 传输对比（`scripts/bench_policy_server_scaling.py`）
8. 端到端吞吐 benches（python + rust，可选）
9. 端到端 shaping 曲线（`scripts/bench_e2e_shaping_curves.py`）
10. native runtime baselines（`scripts/native_guardrail_eval.py`）
11. real-agent campaign（`scripts/real_agent_campaign.py`）
12. 审计日志 hash-chain 校验（`scripts/verify_audit_log.py`）
13. 自动产图（`artifact_out/figures/*.svg`）
14. 可复现 manifest（`artifact_out/repro_manifest.json`）

---

## 15. Artifact 输出字段（逐项解释）

主文件：`artifact_out/report.json`

顶层关键字段：
- `capsule_smoke`
- `baselines`
- `executor_bypass_attempts`
- `benign`
- `malicious`
- `workload_identity`
- `skill_ingress`
- `skilldocbench`
- `leakage_eval`
- `outsourcing_comparison`

### 15.1 `capsule_smoke`
检查：
- `direct_fs_read`
- `direct_exec_true`
- `direct_exec_sh`
- `direct_exfil_post`
- `direct_internet`
- `gateway_act`
- `gateway_mcp_act`

判读原则：
- 前 5 项应失败（`ok=false`）
- 后 2 项应成功（`ok=true`）

### 15.2 `baselines`
- `no_capsule_direct_exfil`: 不上 capsule 时，直接外发可成功（用于证明 capsule 必要性）。
- `no_nbe_insecure_executor`: 关闭 NBE 时可绕过（`ALLOW_INSECURE`）。
- `capsule_loopback_http_exfil`: 若允许 loopback+HTTP，可发生本地绕过（证明 UDS netless 必要性）。

### 15.3 `malicious`
- `read_file`: 应 `SENSITIVE_HANDLE_RETURNED`
- `declassify`: 默认 `REQUIRE_CONFIRM`
- `exfil_handle`: 应 `HIGH_HANDLE_BLOCKED`
- `exfil_secret_text`: 可能 `REQUIRE_CONFIRM`
- `exfil_secret_text_commit`: confirm 后走 patch 路径可 `ALLOW`

### 15.4 `skill_ingress`
- `benign`: `ALLOW`
- `suspicious`: `REQUIRE_CONFIRM`（无 confirm 不允许）
- `ioc_blocked`: `IOC_BLOCKED`

### 15.5 `skilldocbench`
- 数据集：`datasets/skilldocbench/v1/skilldocbench_v1.jsonl`
- 输出：`n`, `accuracy`, `confusion`, `sample_errors`

### 15.6 `leakage_eval`
- 对比 `unshaped` 与 `shaped` 的 `n_unique_features` / `accuracy`
- 趋势目标：shaped 显著压缩单点可见特征空间

### 15.7 `outsourcing_comparison`
- `local_rules`: 规则不外包基线
- `outsourced_cleartext`: 明文外包（隐私最差）
- `outsourced_pir`: PIR 外包（单点可见性受限）

---

## 16. 当前一组可复查结果（样例）

以下是一次本地 artifact 运行的样例（会随机器与时间变化）：

### 16.1 FSS 微基准（`artifact_out/bench_fss.txt`）
- `domain_size=4096`
- `dpf_key_bytes=235`
- `eval_pir_share_avg_s=0.012477`

### 16.2 E2E 吞吐（`artifact_out/bench_e2e.json`）
- Python policy backend: `throughput_ops_s≈0.3`（示例，取决于形状与机器）
- Rust policy backend: `throughput_ops_s≈8`（示例，取决于形状与机器）

### 16.3 关键安全观测（`artifact_out/report.json`）
- Capsule:
  - `direct_fs_read.ok=false`
  - `direct_exec_true.ok=false`
  - `direct_exfil_post.ok=false`
  - `direct_internet.ok=false`
  - `gateway_act.ok=true`
- Baseline:
  - `no_capsule_direct_exfil.ok=true`
  - `no_nbe_insecure_executor.reason_code=ALLOW_INSECURE`
  - `capsule_loopback_http_exfil.direct_exfil_post.ok=true`
- SkillDocBench:
  - `n=100`, `accuracy=1.0`
- Leakage:
  - `unshaped.n_unique_features=17`
  - `shaped.n_unique_features=1`

### 16.1 AgentLeak 风格 C1..C7 复现评测
运行：
```bash
PYTHONPATH=. python scripts/agentleak_channel_eval.py
```

输出：
- `artifact_out/agentleak_eval/agentleak_channel_summary.json`
- `artifact_out/agentleak_eval/agentleak_eval_rows.csv`

该评测会：
- 使用统一泄露函数 `L_sys(C1..C7)`（见 `LEAKAGE_MODEL.md`）
- 按通道报告 `attack_block_rate / attack_leak_rate / benign_allow_rate`
- 与 AgentLeak 公开数值（`C1/C2/C5`）做差值对照

### 16.2 AgentLeak 官方数据集模式（C1..C5）
运行（推荐）：
```bash
AGENTLEAK_CASESET=official \
AGENTLEAK_ATTACKS_PER_CHANNEL=20 \
AGENTLEAK_BENIGNS_PER_CHANNEL=20 \
PYTHONPATH=. python scripts/agentleak_channel_eval.py
```

可选参数：
- `AGENTLEAK_DATASET_PATH=/path/to/scenarios_full_1000.jsonl`
- `MIRAGE_SEED=7`
- `AGENTLEAK_ISOLATE_CASE_CONTEXT=1`（默认 1；按 case 隔离 caller，避免跨 case 预算/turn gate 污染）
- `AGENTLEAK_BENIGN_AUTO_CONFIRM=1`（默认 1；良性样本自动走 confirm path）

该模式使用官方 `scenarios_full_1000.jsonl`，按官方 target channel 映射：
- `final_output -> C1`
- `inter_agent -> C2`
- `tool_input -> C3`
- `tool_output -> C4`
- `memory_write -> C5`

结果文件 `artifact_out/agentleak_eval/agentleak_channel_summary.json` 中的 `case_meta` 会记录：
- 官方数据集规模、攻击家族分布（F1/F2/F3/F4）、垂类分布
- 每个通道最终抽样到的 attack/benign 数量

### 16.3 Official 全量（同口径）结果快照（`artifact_out_full_official_v3`）

运行：
```bash
OUT_DIR=artifact_out_full_official_v3 \
AGENTLEAK_CASESET=official \
AGENTLEAK_ATTACKS_PER_CHANNEL=100000 \
AGENTLEAK_BENIGNS_PER_CHANNEL=100000 \
MIRAGE_SEED=7 \
POLICY_BACKEND=rust \
PYTHONPATH=. python scripts/agentleak_channel_eval.py
```

关键结果（以 `artifact_out_full_official_v3/agentleak_eval/agentleak_channel_summary.json` 为准）：

| mode | attack_block_rate | attack_leak_rate | benign_allow_rate |
|---|---:|---:|---:|
| `mirage_full` | 1.000 | 0.000 | 1.000 |
| `policy_only` | 1.000 | 0.000 | 1.000 |
| `sandbox_only` | 0.827 | 0.173 | 1.000 |
| `single_server_policy` | 1.000 | 0.000 | 1.000 |

说明：
- 旧版本中 `benign_allow_rate≈0.102` 主要由跨 case 状态耦合（预算 + turn gate）导致；现已通过 case 级上下文隔离修复。
- `sandbox_only` 依然在 C3 出现显著泄露，符合“无策略/无双证明执行线”的预期基线表现。

---

## 17. OpenClaw / OAuth 专项说明

### 17.1 常见报错
报错：
```
Error: No provider plugins found. Install one via `openclaw plugins install`.
```

原因：
- OpenClaw state/config 未加载本仓库内置 provider 插件目录。

修复：
```bash
OPENCLAW_STATE_DIR="artifact_out/openclaw_state" bash scripts/setup_openclaw_state.sh
OPENCLAW_STATE_DIR="artifact_out/openclaw_state" \
  integrations/openclaw_runner/node_modules/.bin/openclaw plugins list
```
确认能看到 `openai-codex-auth` 后再登录。

### 17.2 非交互导入 OAuth（可选）
若已有 `~/.codex/auth.json`：
```bash
OPENCLAW_STATE_DIR="artifact_out/openclaw_state" \
  python scripts/import_codex_oauth_to_openclaw.py
```

---

## 18. 配置项参考（精选）

### 18.1 基础服务
- `POLICY0_URL`, `POLICY1_URL`
- `EXECUTOR_URL`
- `POLICY_BACKEND=python|rust`

### 18.2 策略与隐私形状
- `SIGNED_PIR=1`
- `DLP_MODE=fourgram|dfa`
- `FSS_DOMAIN_SIZE`（2 的幂）
- `MAX_TOKENS_PER_MESSAGE`
- `PAD_TOKEN_BATCH=1`
- `USE_POLICY_BUNDLE=1`
- `UNIFIED_POLICY=1`（默认开启：统一 `policy_unified_v1`）
- `MIRAGE_POLICY_PROGRAM_ID=policy_unified_v1`
- `POLICY_BUNDLE_NAME=default`
- PIR microbatch mixing / cover traffic（见 `LEAKAGE_MODEL.md`）：
  - `PIR_MIX_ENABLED=1`
  - `PIR_MIX_INTERVAL_MS=50`
  - `PIR_MIX_PAD_TO=1`（paper pipeline 默认无 padding；生产隐藏建议设为 `>1`）
  - `PIR_COVER_TRAFFIC=0`（生产隐藏建议设为 `1`，并使用 Rust policy backend）

### 18.3 凭据与 proof
- `POLICY0_MAC_KEY`, `POLICY1_MAC_KEY`
- `POLICY_MAC_TTL_S`

### 18.4 存储与审计
- `HANDLE_DB_PATH`
- `TX_DB_PATH`
- `TX_TTL_S`
- `AUDIT_LOG_PATH`
- `MEMORY_DB_PATH`
- `INTER_AGENT_DB_PATH`
- `LEAKAGE_BUDGET_DB_PATH`
- `LEAKAGE_BUDGET_ENABLED=1`
- `LEAKAGE_BUDGET_C1` .. `LEAKAGE_BUDGET_C7`

### 18.5 Capsule / HTTP / UDS
- `MIRAGE_HTTP_UDS`
- `MIRAGE_GATEWAY_UDS_PATH`
- `MIRAGE_GATEWAY_HTTP_URL`
- `MIRAGE_HTTP_TOKEN`
- `MIRAGE_SESSION_ID`

### 18.6 workload identity
- `WORKLOAD_TOKEN_KEY`
- `WORKLOAD_TOKEN_TTL_S`

### 18.7 strict turn output gate
- `MIRAGE_ENFORCE_FINAL_OUTPUT_GATE=1`
- 启用后每轮需提供 `constraints.turn_id`，并在切换到下一轮前成功调用 `FinalizeOutput`

### 18.8 C1/C4/C5 硬化开关（默认安全）
- `MIRAGE_FINAL_OUTPUT_CONFIRM_ALWAYS=1`
  - C1：`FinalizeOutput` 默认每次都要求 `constraints.user_confirm=true`
- `MIRAGE_HANDLEIZE_FS_OUTPUT=1`
  - C4：`ReadFile/ReadWorkspaceFile` 默认返回 opaque handle，不返回明文
- `WORKSPACE_READ_DEFAULT_SENSITIVITY=HIGH`
  - C4：工作区读取句柄默认高敏，走显式解密审批
- `DECLASSIFY_CONFIRM_LABELS=MEMORY_ENTRY,WORKSPACE_FILE,FILE_CONTENT`
  - C5/C4：上述标签句柄解密默认必须确认（即使不是 `HIGH`）

---

## 19. 常见问题与排查

### 19.1 `IndentationError: unexpected indent`（heredoc 场景）
通常是手工 heredoc 粘贴时行首多空格或终止符不匹配。建议直接使用脚本：
- `scripts/import_codex_oauth_to_openclaw.py`

### 19.2 `TX_INVALID / TX_SESSION_MISMATCH / TX_CALLER_MISMATCH`
- 检查 `tx_id` 是否过期（`TX_TTL_S`）
- 检查 commit 时是否换了 session 或 caller

### 19.3 `BAD_COMMIT_PROOF`
- 检查 policy/executor 的 MAC key 是否一致
- 检查 commit payload 的 `action_id/program_id/request_sha256`
- 检查 proof 是否超时（`POLICY_MAC_TTL_S`）

### 19.4 capsule 测试在 Linux 失败
- 确认 `bwrap` 已安装
- CI 路径参考 `.github/workflows/ci.yml`

### 19.5 OpenClaw 登录后仍不能调用
- 确认 plugin 加载路径正确（`setup_openclaw_state.sh`）
- 确认 `OPENCLAW_STATE_DIR` 与运行时一致
- 确认 `auth-profiles.json` 有 `openai-codex` profile

---

## 20. 与“模型型 guardrail”工作关系

本项目与仅靠 LLM 分类/推理的 guardrail 路线互补而非替代：
- 模型型 guardrail 擅长风险感知与解释。
- MIRAGE-OG++ 重点是不可绕过执行线与单点隐私策略外包。

你可以把模型输出当作附加策略信号输入 gateway，但不能替代 executor 双授权机制。

---

## 21. 与 `guide.md` / `guide2.md` / `new.md` 的关系

当前仓库已经实现了“可运行研究原型 + 论文 artifact”主线：
- 2-server PIR(FSS/DPF)
- PREVIEW->COMMIT + MPC policy engine
- dual-proof executor
- capsule MVP
- skill ingress
- real-agent 接入（OpenClaw/NanoClaw）

仍属于可继续深化的方向（非当前已完成）：
- 更通用/更高性能 MPC 与向量化后端
- 更强流量隐藏（cover traffic / 批处理混洗）
- 更完整策略 DSL 与更大 intent 覆盖

---

## 22. 复现清单（Checklist）

最小 checklist：
1. `python main.py artifact` 成功。
2. `artifact_out/report.json` 存在并含第 15 节字段。
3. `artifact_out/bench_fss.txt`、`bench_e2e.json` 存在。
4. （可选）`POLICY_BACKEND=rust` 时 `bench_e2e.rust.json` 存在。
5. （可选）`bash scripts/run_openclaw.sh` 生成 `openclaw_benign.json` 与 `openclaw_malicious.json`。

---

## 23. 相关文档

- `ARTIFACT.md`: artifact 运行与提交说明
- `ALGORITHMS.md`: 英文版算法/协议说明（对应主要贡献点；含正确性与验证映射）
- `ALGORITHMS_CN.md`: 中文版算法/协议说明（与 `ALGORITHMS.md` 对应）
- `EFFECTIVENESS.md`: 有效性定义与对应证据
- `FORMAL_SECURITY.md`: NBE/SM/SAP/SCS 的严格定义、安全游戏与可验证命题
- `MOTIVATION_PAPER.md`: 英文论文级 Motivation/Problem/Goals/Approach（含 baseline 能力矩阵与案例映射）
- `MOTIVATION_PAPER_CN.md`: 中文对应版本
- `new.md`: 当前工作包与完成项追踪
- `neurips_2025.tex`: 论文文本草稿

---

## 24. Paper-grade 评测：基线、指标、输出与样例结果

本节对应你提出的“论文级 6 项必做工作”：
1. 形式化安全主张（定义/游戏/可验证命题）
2. 强基线对比（不仅无防护）
3. 大规模实证（攻击/良性任务集 + 统计）
4. 性能工程到生产量级（policy server O(N) 路径工程化 + 曲线）
5. 真实 agent 闭环评测（OpenClaw/NanoClaw/脚本化 MCP）
6. 可复现实验工件（一键复现 + 固定 seed + 自动产图）

### 24.1 一键运行与固定随机性

```bash
python main.py paper-artifact
```

默认固定：
- `MIRAGE_SEED=7`
- `PYTHONHASHSEED=0`
- `EVAL_ATTACKS_PER_CATEGORY=60`
- `EVAL_BENIGNS_PER_CATEGORY=60`

你可以通过环境变量覆盖（见 `scripts/run_paper_artifact.sh`）。

### 24.2 形式化主张与可执行检查（必须）

- 严格定义与安全游戏：`FORMAL_SECURITY.md`
- 机器可复核检查：
  - `scripts/security_game_nbe_check.py` 会产生 `artifact_out/security_game_nbe.json`
  - `tests/test_security_games.py` 是 executor proof 验证逻辑的单测

你应当在 `artifact_out/security_game_nbe.json` 看到 `status="OK"`。

### 24.3 强基线对比（必须）

`scripts/paper_eval.py` 实现并评测以下模式（输出 `artifact_out/paper_eval/*`）：

- `mirage_full`：完整 MIRAGE-OG++（gateway + 双 policy server + executor 双 proof）。
- `policy_only`：只做 policy 判定/签发，但不通过 executor 强制（用于证明没有 NBE 时不可绕过性不存在）。
- `sandbox_only`：网关策略检查被显式旁路（`MIRAGE_POLICY_BYPASS=1`），近似“只有沙箱/只有运行时防护”的 ablation（注意：这不是 OS 级 sandbox 的等价实现，只用于对照）。
- `single_server_policy`：单 policy server 明文 idx 查询（性能更快但牺牲 SAP；用于隐私对照）。

### 24.4 任务集与指标（必须）

任务集由 `scripts/paper_eval.py` 内置生成并可扩展：
- 攻击集：提示注入、命令注入风格、路径绕过链、skill 供应链 IOC/安装链
- 良性集：正常消息/外联/skill 安装路径

指标（逐条 case 记录于 `paper_eval_rows.csv`）：
- 阻断率（攻击拦截率）
- 误报率（良性被拒绝率）
- 延迟（avg/p50/p95）
- 吞吐（ops/s）
- 成本代理（本仓库用“PIR 查询数 + MPC 程序数”做可复现 cost_units）
- 统计：Wilson 95% CI + permutation p-value（相对 `mirage_full`）

### 24.5 性能工程与吞吐曲线（必须）

policy server 的 PIR bitset 求值内核有两条实现（共享同一接口与 proof 格式）：
- Python：`policy_server/db.py` + `fss/dpf.py`
- Rust：`policy_server_rust/src/main.rs`（compiled backend；dense 路径使用 64-bit chunk + popcount parity）

传输层优化（长连接 + 二进制 framing）：
- 网关端对 policy/executor 调用统一改为 `requests.Session` 连接池复用（`gateway/http_session.py`）。
- Rust policy server 新增 binary PIR 端点：
  - `/pir/query_batch_bin`
  - `/pir/query_batch_signed_bin`
  - `/pir/query_batch_multi_signed_bin`
- 网关可通过 `PIR_BINARY_TRANSPORT=1` 启用 binary PIR（失败自动回退 JSON），减少 JSON/base64 编解码与 payload 体积。

另外实现了“稀疏 bitset”快速路径（默认 `auto`）：
- 预计算 bitset 的 set-bit 索引集合 `S`，用 `ans_share = XOR_{i in S} DPFEvalPoint(k_party, i)` 计算 parity share（见 `ALGORITHMS.md:Algorithm A4b`）。
- 通过 `PIR_EVAL_MODE={auto|dense|sparse}` 控制：
  - `auto`：按 `|S|·logN` vs `N` 的启发式自动选择（推荐）
  - `dense`：强制走 O(N) 路径（用于 worst-case 吞吐曲线）
  - `sparse`：强制走稀疏路径（用于稀疏集合的生产常见场景）

吞吐曲线：
- `scripts/bench_policy_server_curves.py`
- 输出：`artifact_out/policy_perf/policy_server_curves.json` 与 `.csv`

单核/多核 scaling（含 JSON vs binary 传输）：
- `scripts/bench_policy_server_scaling.py`
- 输出：`artifact_out/policy_perf/policy_server_scaling.json` 与 `.csv`
- 自动产图：`artifact_out/figures/policy_server_scaling_keys_s.svg`

端到端 shaping 曲线（mixing/padding/cover 的吞吐-延迟权衡）：
- `scripts/bench_e2e_shaping_curves.py`
- 输出：`artifact_out/shaping_perf/e2e_shaping_curves.json` 与 `.csv`
- 自动产图：`artifact_out/figures/e2e_shaping_curves_ops_s.svg`

高利用率 shaping 调度（可选）：
- PIR mixer:
  - `PIR_MIX_LANES`（并行 lane 数）
  - `PIR_MIX_MAX_INFLIGHT`（允许并行在途 tick 数）
  - `PIR_MIX_SCHEDULE={fixed|eager}`
- MPC mixer:
  - `MPC_MIX_LANES`
  - `MPC_MIX_MAX_INFLIGHT`
  - `MPC_MIX_SCHEDULE={fixed|eager}`
- 默认值保持保守（`lanes=1,max_inflight=1,fixed`）以避免低负载下排队抖动；生产压测时可逐步上调。

目标解释：证明“安全提升不是靠把系统变慢 100 倍”，而是可以通过编译/向量化显著降低常数因子。

### 24.6 真实 agent 闭环与证据链（必须）

real-agent campaign：
- `scripts/real_agent_campaign.py`
- 输出：`artifact_out/campaign/real_agent_campaign.json`
- 同目录会保存：
  - OpenClaw / NanoClaw 的 benign/malicious 输出副本
  - `audit_*.jsonl`（审计日志）
  - SHA256（证据链完整性）

native runtime baselines（无 MIRAGE）：
- `scripts/native_guardrail_eval.py`
- 输出：`artifact_out/native_baselines/native_guardrail_eval.json`

强基线汇总（同口径 + runtime + 官方模型统计汇总）：
- `scripts/build_strong_baseline_report.py`
- 输出：`artifact_out_compare/strong_baseline_report.json`
- 汇总来源：
  - `artifact_out_full_official_v3/agentleak_eval/agentleak_channel_summary.json`
  - `artifact_out_tmp/native_smoke2/native_baselines/native_guardrail_eval.json`
  - `third_party/agentleak_official/benchmarks/ieee_repro/results/model_stats.json`

official AgentLeak `C1..C5` 同口径 fair compare（MIRAGE + Codex + OpenClaw）：
- `scripts/fair_full_compare.py`
- 输出：`artifact_out_compare/fair_full_report.json`
- 统计分解与显著性：`scripts/fair_full_stats.py` -> `artifact_out_compare/stats/fair_full_stats.json`
- 语义与威胁模型解释：`BASELINES_FAIRNESS.md`

### 24.7 自动产图与复现清单（必须）

- Figures（SVG）：`artifact_out/figures/*.svg` 与 `artifact_out/figures/figures_index.json`
- Repro manifest：`artifact_out/repro_manifest.json`
  - 平台信息、git 版本、工具版本、固定 seeds

### 24.8 样例结果（来自一次本地运行，需以输出文件为准）

你可以直接查看：
- `artifact_out/paper_eval/paper_eval_summary.json`
- `artifact_out/policy_perf/policy_server_curves.json`
- `artifact_out/native_baselines/native_guardrail_eval.json`
- `artifact_out/campaign/real_agent_campaign.json`

样例（来自一次本地 smoke run；以输出文件中的 `seed` 与计数为准；本例参数：`POLICY_BACKEND=rust,EVAL_ATTACKS_PER_CATEGORY=10,EVAL_BENIGNS_PER_CATEGORY=10,PIR_EVAL_MODE=auto`）：

`paper_eval`（基线对比，节选）：

| mode | 攻击阻断率 | 良性误报率 | p95 延迟（ms） | 吞吐（ops/s） |
|---|---:|---:|---:|---:|
| `mirage_full` | 0.889 | 0.000 | 69.471 | 20.387 |
| `policy_only` | 0.889 | 0.000 | 68.917 | 19.882 |
| `sandbox_only` | 0.111 | 0.000 | 0.805 | 3234.753 |
| `single_server_policy` | 0.889 | 0.000 | 14.349 | 88.465 |

解释要点：
- `single_server_policy` 主要用于“隐私 vs 性能”对照：它更快，但牺牲 SAP（单审计方隐私）目标。
- `sandbox_only` 是显式旁路策略检查的 ablation：吞吐高但安全性显著下降，用于证明“只有运行时/沙箱并不足以覆盖攻击集”。

`policy_perf`（policy server 曲线，节选为本机最佳点的 effective keys/s）：
- Python backend：约 `20000` effective keys/s（`logical_batch=8,effective_batch=128,pad_to=128`）
- Rust backend：约 `172625` effective keys/s（`logical_batch=128,effective_batch=128,pad_to=32`）

`policy_server_scaling`（单机线程扩展与传输层对比，示例）：
- 在同一 batch/concurrency 下，`PIR_BINARY_TRANSPORT=1` 相对 JSON 常见可观收益（一次本机短测：throughput 约 `1.20x`、p95 约降至 `0.47x`）。
- 以 `policy_server_scaling.json` 为准报告不同线程数（`RAYON_NUM_THREADS`）下的 `throughput_keys_s / p50 / p95` 曲线。

`real_agent_campaign`（真实 agent 闭环，节选）：
- OpenClaw + MIRAGE：`benign_allow_rate=1.0`，`attack_block_rate=1.0`（`n_ok=1`）
- Scripted MCP：`benign_allow_rate=1.0`，`attack_block_rate=1.0`（`n_ok=1`）
- NanoClaw：若缺少凭据会被标记为 `SKIPPED`（不影响流水线其他部分）

本 README 的第 16 节仍保留了 demo artifact 的样例数值；paper-grade 结果以第 24 节这些输出为准（可在论文中引用并附上 seed/commit）。

### 24.9 生产量级性能章节建议引用（本仓库最新一组）

参见：
- `artifact_out_perf_v3/shaping_perf/e2e_shaping_curves.json`
- `artifact_out_perf_v3/policy_perf/policy_server_scaling.json`
- `artifact_out_perf_v3/policy_perf/policy_server_curves.json`

可直接引用的结论（该机型短测）：

1. 端到端（official full harness）`mirage_full` 相对 `single_server_policy`：
   - `p50` 约 `3.88x`
   - `p95` 约 `3.63x`
   - 吞吐慢化约 `4.48x`
   - 不是“慢 100x”的量级。
2. 固定形状（`pad+cover+mixer`）曲线：
   - `pad_to=2/4` 时吞吐约为 baseline 的 `0.90x`，`p50` 开销约 `1.05x~1.06x`。
   - `pad_to=16` 会明显放大尾延迟（`p95` 增大显著），应仅用于更强隐匿需求。
3. policy server 内核扩展（Rust + binary transport）：
   - 1 线程约 `2.63e5 keys/s`
   - 8 线程约 `5.05e5 keys/s`
   - 1->8 线程 speedup 约 `1.92x`（当前瓶颈已部分转向调度/IO，而非纯算子）。
