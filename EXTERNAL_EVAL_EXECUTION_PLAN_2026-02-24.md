# SecureClaw 详细方案设计与实验蓝图（2026-02-24）

## 0. 文档定位

本文是 SecureClaw 的系统设计与论文级评测蓝图。

目标：

1. 把 SecureClaw 的架构、协议、安全主张、工程约束讲清楚。
2. 给出可执行的实验设计，明确 benchmark 与 baseline 的选择依据。
3. 给出可复现的统计与验收标准，避免“跑了很多但无法发表”。

边界：

1. 本文不报告某一次 run 的实时进度和数值。
2. 本文描述的是“方案与评测方法学”，不是临时调参日志。

---

## 1. SecureClaw 要解决什么问题

## 1.1 研究问题

在 agent 系统中，最关键的风险是“执行边界失守”，不是单纯文本输出质量。

典型失守路径：

1. Prompt injection 诱导 runtime/skill 直接执行副作用。
2. 策略系统仅 advisory（建议性），缺乏 commit 前强制验证。
3. 中央策略服务看见明文查询，造成单点隐私暴露。
4. 委托/联邦入口没有强绑定，出现跨主体复用与重放。

## 1.2 SecureClaw 的核心目标

SecureClaw 同时追求 5 个主性质 + 1 个可选隐私性质：

1. **NBE**（Non-Bypassable Effects）
副作用提交不可绕过：无双证明不可 commit。

2. **SM**（Secret Myopia）
敏感明文默认不流向不可信 runtime，仅返回 opaque handle。

3. **PEI**（Patch-Carrying Egress Integrity）
若 PREVIEW 输出要求 sanitize patch，executor 在 COMMIT 前必须强制应用补丁。

4. **SCS**（Skill-Confined Safety）
在 capsule mediation contract 成立时，skill 无法绕开网关执行宿主副作用。

5. **DAS**（Delegation-Aware Binding Safety）
联邦上下文 `hctx=(external_principal,delegation_jti)` 绑定进请求哈希，防止跨主体重放。

6. **SAP**（Single-Auditor Privacy，可选模式）
任一单个 policy server 的可见 transcript 仅泄露允许函数 `L_policy`。

## 1.3 非目标（必须明确）

1. 不承诺两台 policy server 全合谋下的单方隐私。
2. 不承诺 kernel/hardware side-channel。
3. 不承诺 TCB（Gateway+Executor）被攻破后的安全。
4. 不承诺“只靠 prompt 工程”即可提供不可绕过保证。

---

## 2. 威胁模型与信任边界

## 2.1 参与方

1. `A`：不可信 runtime/skill（可恶意、可被注入）。
2. `G`：可信 Gateway（TCB）。
3. `P0`,`P1`：策略服务（honest-but-curious，且至少一方不合谋）。
4. `X`：可信 Executor（TCB），唯一副作用落点。
5. `U`：用户确认源（confirm path）。
6. `C`：可选 capsule 边界（SCS 条件）。

## 2.2 攻击者能力

攻击者可：

1. 控制 prompt、工具参数和 skill 输入。
2. 构造跨通道泄露（C1..C7）。
3. 重放旧请求、替换主体、尝试绕过 commit 验证。
4. 利用外部 benchmark 的复杂输入触发边界条件。

攻击者不可（模型前提）：

1. 直接破坏 Gateway/Executor 的完整性。
2. 同时控制两台 policy server 并合谋（SAP 前提）。

## 2.3 信任最小化原则

SecureClaw 不把“模型行为正确性”当作根安全前提，而把安全根放在：

1. Gateway 的协议约束。
2. Executor 的验收谓词。
3. 双 policy proof 的密码学绑定。

---

## 3. 系统架构设计（详细）

## 3.1 分层

1. **接入层**：`act(intent_id, inputs, constraints, caller)` 单入口。
2. **策略层**：PIR + MPC 计算 policy 输出与 commit proofs。
3. **执行层**：Executor 验证后执行外部副作用。
4. **约束层**：delegation/federated auth/capsule 形成外围防线。

## 3.2 模块职责与代码映射

### 3.2.1 Gateway 主链路

1. `gateway/mcp_server.py`
2. `gateway/http_server.py`
3. `gateway/router.py`
4. `gateway/egress_policy.py`
5. `gateway/skill_policy.py`
6. `gateway/policy_unified.py`

职责：

1. 统一入口编排。
2. capability 与身份约束。
3. PREVIEW 事务生成。
4. commit evidence 转发。

### 3.2.2 策略计算层

1. `gateway/fss_pir.py`
2. `policy_server/server.py`
3. `policy_server/mpc_engine.py`
4. `policy_server_rust/src/main.rs`
5. `policy_server/build_dbs.py`

职责：

1. membership 查询（PIR）。
2. policy circuit 求值（MPC）。
3. commit proof 生成与签名。

### 3.2.3 执行与验证层

1. `executor_server/server.py`
2. `common/canonical.py`
3. `gateway/tx_store.py`
4. `gateway/handles.py`

职责：

1. 严格验收谓词。
2. request hash 绑定一致性。
3. replay 与事务状态管理。
4. handle 生命周期管理。

### 3.2.4 委托与联邦控制面

1. `common/delegation_token.py`
2. `gateway/delegation_store.py`
3. `gateway/federated_auth.py`
4. `common/federated_proof_token.py`

职责：

1. 跨主体最小授权。
2. 会话绑定、到期与撤销。
3. ingress 身份证明与 anti-replay。

### 3.2.5 Capsule 与中介合约

1. `capsule/MC_CONTRACT_SPEC.md`
2. `capsule/mcp_proxy.py`
3. `capsule/verify_contract.py`

职责：

1. 证明 skill 运行面受限。
2. 提供 SCS 主张的系统假设证据。

---

## 4. 协议设计细节（从 act 到 commit）

## 4.1 核心数据结构

### 4.1.1 请求元组与上下文绑定

定义：

`rho = (intent_id, caller, session, inputs_eff, hctx)`

其中 `hctx = (external_principal, delegation_jti)`，缺失字段省略，空上下文记为 `{}`。

`ReqHash(rho) = SHA256(CanonJSON({v,intent_id,caller,session,inputs,context}))`

作用：

1. 把 authorization 绑定到“具体请求语义”。
2. 防止 PREVIEW 证据被跨请求复用。
3. 支持 delegation/federation 上下文绑定。

### 4.1.2 Commit Proof Share

每个 policy server 返回：

`pi_s = (meta_s, mac_s)`

`meta_s` 至少包含：

1. `v`
2. `kind`
3. `server_id`
4. `kid`
5. `ts`
6. `action_id`
7. `program_id`
8. `request_sha256`
9. `outputs`
10. `commit_tag_share_b64`

`mac_s = HMAC(K_s, Canon(meta_s))`

### 4.1.3 TxRecord 与 HandleRecord

TxRecord 绑定：

1. request hash
2. action id
3. program id
4. 双 proof
5. session/caller
6. 状态机状态（previewed/committed/expired）

HandleRecord 绑定：

1. handle id
2. sensitivity label
3. session/caller 作用域
4. TTL
5. 可选撤销标记

## 4.2 PREVIEW 状态机（无副作用）

建议实现状态（便于审计）：

1. `S0_RECEIVED`
2. `S1_AUTHZ_CHECKED`（caller/principal/delegation）
3. `S2_HASH_BOUND`
4. `S3_POLICY_EVAL_PIR`
5. `S4_POLICY_EVAL_MPC`
6. `S5_PROOFS_COLLECTED`
7. `S6_TX_PERSISTED`
8. `S7_PREVIEW_RETURNED`

关键约束：

1. 未进入 `S6_TX_PERSISTED` 不得返回可提交 `tx_id`。
2. 任一步骤失败必须 fail-closed。

## 4.3 COMMIT 状态机（有副作用）

建议实现状态：

1. `C0_COMMIT_REQUESTED`
2. `C1_TX_LOADED`
3. `C2_PROOF_VERIFY`
4. `C3_BINDING_RECHECK`
5. `C4_REPLAY_FRESHNESS_CHECK`
6. `C5_POLICY_OUTPUT_CHECK`
7. `C6_EFFECT_EXECUTED`
8. `C7_AUDIT_COMMITTED`

关键约束：

1. `C2~C5` 任一失败必须拒绝副作用。
2. 只有 `C6` 后才允许“外部可见 effect”。

## 4.4 Executor 验收谓词（Accept Predicate）

最低检查项（与 `FORMAL_SECURITY.md` 对齐）：

1. 结构/schema 合法。
2. `policy0/policy1` 身份不同且有效。
3. 双 MAC 验签通过。
4. `abs(now-ts) <= POLICY_MAC_TTL_S`。
5. `(action_id, program_id, request_sha256)` 双方一致。
6. 重算 `ReqHash(rho(req))` 与 proof 绑定一致。
7. replay guard 拒绝窗口内重复 action_id。
8. `allow_pre=1`。
9. `need_confirm=1` 时必须显式确认。
10. sanitize patch 约束满足。

## 4.5 失败语义（Fail-Closed）

必须定义统一拒绝行为：

1. 不产生外部副作用。
2. 返回 reason_code（便于统计和审计）。
3. 写审计日志（含 request hash 与上下文摘要）。

## 4.6 Delegation + Dual Principal 设计细节

Delegation token 最小字段：

1. `iss`（external principal）
2. `sub`（internal actor pattern）
3. `scope`（intent set）
4. `session`
5. `exp_ms`
6. `jti`

Gateway 每次请求需检查：

1. 会话一致性。
2. subject 匹配。
3. scope 覆盖。
4. 未过期。
5. `jti` 未撤销。

授权生效规则：

`effective_caps = caps(caller) ∩ caps(external_principal)`

这样避免两类越权：

1. external principal 借 internal actor 升权。
2. internal actor 绕过 external principal 约束。

## 4.7 Federated ingress 设计细节

可选三段式校验：

1. mTLS 证书哈希钉扎。
2. 请求签名 + ts/nonce anti-replay。
3. 短时 proof token。

并把 ingress 上下文写入 `hctx`，纳入 `ReqHash` 绑定。

## 4.8 Skill ingress 设计细节

1. skill 安装是 effectful action，必须 PREVIEW->COMMIT。
2. `skill_digest` 与 IOC 检测结果进入策略输入。
3. 安装后 workload token 将调用主体收敛到 `skill:<digest>`。
4. skill 权限不得直接继承宿主 runtime 的全部权限。

---

## 5. 安全主张与证明链（严谨版摘要）

完整形式定义在：

1. `FORMAL_SECURITY.md`
2. `appendix_security.tex`
3. `paper_full_body.tex`

## 5.1 NBE：不可绕过副作用

坏事件：

1. 无授权上下文却成功 commit。
2. 绑定错位（同证据用于不同请求）。
3. replay 在保护窗口内成功。

归约来源：

1. HMAC EUF-CMA（proof 伪造难）。
2. `ReqHash` 碰撞抗性 + canonicalization 一致性。
3. replay 存储原子性与持久性假设。

## 5.2 SM：明文近视

坏事件：

攻击者无显式 declassification 却区分高敏感秘密值。

边界：

`Pr[Bad_SM] <= q_h / 2^128 + negl(lambda)`（`q_h` 为在线猜测次数）。

## 5.3 SAP：单审计方隐私

坏事件：

单个 policy server 视图区分两个同泄露轨迹工作负载。

前提：

1. 2-server PIR 单方安全。
2. 固定电路形状下 MPC 单方可模拟。
3. 至少一台 policy server 不合谋。
4. 若声称 intent-hiding，`program_id/endpoint class/batch shape` 对覆盖 intent 保持常量。

## 5.4 SCS：技能受限安全

SCS 不是“纯密码学结论”，而是：

1. 协议安全（NBE/SM）
2. 系统中介契约（capsule contract）

二者共同成立时的组合主张。

## 5.5 组合结论（Composition）

论文中应明确：

1. 组合界是 bad events 的并界。
2. 并界不要求事件互斥。
3. 每个误差项要有明确来源与工程可观测性。

---

## 6. 泄露模型与通道预算

## 6.1 `L_policy`

定义：

`L_policy = (L_PIR, L_MPC, L_CONFIRM, L_TIME)`

核心设计点：

1. `L_PIR`：bundle + shift + fixed key count + mixer/padding/cover。
2. `L_MPC`：统一 `program_id` + 常量形状 batch。
3. `L_CONFIRM`：可配置固定 DFA 步数（避免长度侧漏）。
4. `L_TIME`：只允许桶化时间，不允许细粒度请求时间泄露。

## 6.2 `L_sys`

定义：

`L_sys = (L_C1,...,L_C7)`

其中：

1. `C1..C5` 对应 AgentLeak 官方主通道。
2. `C6/C7` 由合成全通道套件补齐（日志与 skill ingress 维度）。

## 6.3 预算与审计

建议每个通道维护：

1. 允许泄露字段白名单。
2. 预算计数器。
3. reason_code 归因。
4. 审计 hash-chain 元数据。

对应实现：

1. `LEAKAGE_MODEL.md`
2. `LEAKAGE_EVIDENCE.md`
3. `gateway/leakage_budget.py`

---

## 7. 工程配置与部署剖面

## 7.1 安全优先剖面（推荐论文主配置）

建议：

1. `UNIFIED_POLICY=1`
2. `USE_POLICY_BUNDLE=1`
3. `MIRAGE_POLICY_PROGRAM_ID=policy_unified_v1`
4. `PIR_MIX_ENABLED=1`
5. `MPC_MIX_ENABLED=1`
6. `PIR_COVER_TRAFFIC=1`
7. `MPC_COVER_TRAFFIC=1`
8. `PAD_DFA_STEPS=1`
9. UDS + netless capsule

## 7.2 平衡剖面（实验常用）

1. 保持 unified/bundle。
2. mixer on, cover 可按负载调小。
3. binary transport on（若后端支持）。

## 7.3 性能优先剖面（仅对照，不用于强安全主张）

1. 可关闭部分 cover/padding。
2. 可切 `single_server_policy`（仅隐私对照）。
3. 必须在文档中明确“主张降级”。

---

## 8. 论文级实验设计（详细）

## 8.1 研究问题（RQs）与假设（Hs）

### RQ1：SecureClaw 是否显著降低攻击泄露

- H1：`mirage_full` 的 attack leak rate 显著低于 native baselines。

### RQ2：不可绕过执行线是否成立

- H2：在未满足双 proof 验收谓词时，副作用提交成功率接近 0。

### RQ3：单方策略服务隐私是否成立

- H3：在固定形状与 bundling 配置下，单方 transcript 区分优势接近随机。

### RQ4：安全增强是否带来可接受开销

- H4：相对高性能对照，延迟与吞吐开销处于可解释范围且可工程优化。

## 8.2 多轨评测框架

### Track A：协议与形式安全轨

目标：验证 NBE/SM/SCS 的可执行命题。

基准：

1. 安全游戏脚本与单测
2. delegation/federation 协议测试
3. capsule contract 检验

建议脚本：

1. `scripts/security_game_nbe_check.py`
2. `tests/test_security_games.py`
3. `tests/test_delegation_and_dual_principal.py`
4. `tests/test_federated_auth.py`
5. `capsule/verify_contract.py`

### Track B：泄露与效果主轨（主论文图表）

目标：同口径比较 attack/benign 表现。

核心 benchmark：

1. AgentLeak 官方 `C1..C5`（主结果）
2. AgentLeak 合成 `C1..C7`（补齐 C6/C7）

对应脚本：

1. `scripts/agentleak_channel_eval.py`
2. `scripts/fair_full_compare.py`
3. `scripts/fair_full_stats.py`
4. `scripts/fair_utility_breakdown.py`

### Track C：注入鲁棒性外部轨

目标：覆盖不同类型注入与工具调用工作流。

建议 benchmark 与理由：

1. **AgentDojo**：任务型 agent 基准，覆盖多套件（banking/slack/travel/workspace），可评估 utility/security 兼顾。
2. **ASB**：direct prompt injection 大规模口径，补足高样本统计稳定性。
3. **DRIFT**：强调动态 checklist/tool trajectory 对齐，覆盖复杂工具链行为。
4. **IPIGuard**：强调 dependency sink 风险抑制，补足运行时防护角度。
5. **WASP/VPI**（条件可用）：作为外部环境依赖较重的补充轨，需单列基础设施前提。

对应脚本：

1. `scripts/run_full_external_eval_pipeline.sh`
2. `scripts/run_asb_dpi_full_lowmem.sh`
3. `scripts/run_drift_ipiguard_full_lowmem.sh`
4. `scripts/external_benchmark_unified_summary.py`

### Track D：性能与可扩展性轨

目标：解释开销来源并给出工程优化空间。

建议 benchmark：

1. policy kernel 曲线（batch/padding）。
2. thread scaling + wire format（json/bin）。
3. 端到端 shaping（mix/pad/cover）曲线。

对应脚本：

1. `scripts/bench_policy_server_curves.py`
2. `scripts/bench_policy_server_scaling.py`
3. `scripts/bench_e2e_shaping_curves.py`

## 8.3 Benchmark 选择准则（为什么选这些）

选择标准：

1. **相关性**：能映射到 RQ 和安全性质。
2. **官方性**：优先官方数据和官方 runner。
3. **可复现性**：可固定 seed、输出原始行级结果。
4. **可对比性**：支持 same-cases/same-metrics。
5. **覆盖度**：同时覆盖 attack、benign、协议边界、性能维度。

基于上述标准：

1. AgentLeak 官方 C1..C5 作为主论文比较轴。
2. AgentLeak C6/C7 作为 SecureClaw 专属通道补充。
3. AgentDojo/ASB/DRIFT/IPIGuard 作为“外部鲁棒性证据”轨。
4. WASP/VPI 作为扩展轨（基础设施满足时纳入主报告，否则列阻塞证据）。

### 8.3.1 Benchmark-性质覆盖矩阵（建议写入论文方法节）

| Benchmark | 主要覆盖面 | 主要回答的 RQ | 作为主结果还是补充 |
|---|---|---|---|
| AgentLeak 官方 `C1..C5` | 多通道泄漏 + benign/attack 同口径 | RQ1, RQ2 | 主结果 |
| AgentLeak 合成 `C1..C7` | 补齐 `C6/C7`（日志/skill ingress） | RQ1, RQ3 | 补充 |
| AgentDojo (`v1.2.2`) | 任务完成度与安全行为并行评估 | RQ1, RQ4 | 补充（强） |
| ASB（DPI） | 大样本 direct prompt injection 稳定统计 | RQ1 | 补充（强） |
| DRIFT | 动态 checklist/tool trajectory 场景 | RQ1, RQ2 | 补充（强） |
| IPIGuard | dependency sink 风险抑制能力 | RQ1 | 补充（强） |
| WASP / VPI | 外部复杂环境下注入鲁棒性 | RQ1, RQ4 | 扩展（条件） |

使用规则：

1. 主论文结论优先来自“官方、可复算、同口径”的主结果集（AgentLeak 官方）。
2. 外部 benchmark 作为稳健性补证，不可替代主口径统计。
3. 任何 coverage 不同的 benchmark 必须单独分母报告，禁止直接并表混算。

## 8.4 Baseline 选择与取舍（必须解释）

### 8.4.1 内部结构基线（解释 SecureClaw 机制价值）

1. `mirage_full`：完整系统。
2. `policy_only`：去掉 executor 强制边界，检验 NBE 贡献。
3. `sandbox_only`：策略旁路对照，展示“仅运行时防护”不足。
4. `single_server_policy`：隐私-性能对照，展示 SAP 成本与收益。

### 8.4.2 原生 runtime 基线（外部可见对比）

1. `codex_native`
2. `openclaw_native`

目的：回答“无 SecureClaw 执行线时，native guardrails 在同任务集表现如何”。

### 8.4.3 防护机制基线（不加 anti-leak prompt）

1. `codex_drift`
2. `codex_ipiguard`
3. `codex_agentarmor`

目的：比较“运行时中介防护”与“协议级不可绕过执行线”的差异。

注意：

1. 这些 defense baseline 不是 SecureClaw 的等价替代。
2. 报告时必须说明其威胁模型与保证边界不同。

### 8.4.4 Baseline-机制映射矩阵（建议写入论文对照节）

| Baseline | 有无双证明提交线 | 有无单方策略隐私 | 有无委托/双主体约束 | 主要作用 |
|---|---|---|---|---|
| `mirage_full` | 有 | 有（2-server） | 有 | 主系统 |
| `policy_only` | 无 | 有（2-server） | 有 | 评估 executor 边界价值 |
| `sandbox_only` | 无 | 无（策略旁路） | 弱 | 运行时防护下界对照 |
| `single_server_policy` | 有（可有） | 无（单服务） | 有 | 隐私-性能权衡对照 |
| `codex_native` | 无 | 无 | 无 | 原生 runtime 基线 |
| `openclaw_native` | 无 | 无 | 无 | 原生 runtime 基线 |
| `codex_drift` | 无 | 无 | 无 | 运行时中介防护基线 |
| `codex_ipiguard` | 无 | 无 | 无 | 运行时中介防护基线 |
| `codex_agentarmor` | 无 | 无 | 无 | 运行时中介防护基线 |

解释约束：

1. 防护机制基线用于比较“runtime 防护能力”，不等价于 SecureClaw 的协议级提交安全。
2. 若防护基线采用机制对齐实现（而非官方完整实现），需在论文中显式标注“实现来源与差异”。

## 8.5 公平性协议（Fairness Protocol）

必须执行以下约束：

1. **same-cases**：统一官方 manifest，所有系统共用。
2. **same-seed**：固定 `MIRAGE_SEED`。
3. **same-metrics**：统一 row-level 指标定义。
4. **no anti-leak prompt tuning**：native baseline 不加额外“防泄漏提示词”。
5. **cache reuse with disclosure**：defense baseline 可复用 scenario 输出，但需在报告中标注。
6. **run_tag isolation**：所有外部评测产物必须按 run_tag 隔离，禁止混读历史目录。

## 8.6 指标体系（含公式）

设 attack 样本数 `N_a`，benign 样本数 `N_b`：

1. `AttackLeakRate = leak_attack / N_a`
2. `AttackBlockRate = block_attack / N_a`
3. `BenignAllowRate = allow_benign / N_b`
4. `FalsePositiveRate = deny_benign / N_b`
5. `LatencyP50/P95`：按 case latency 统计。
6. `OpsPerSecond`：`N_total / wall_clock_s`。

可选透明指标（native 场景建议报告）：

1. `model_call_count`
2. `model_ops_s`
3. `model_latency_p50_ms`
4. `model_latency_p95_ms`

## 8.7 统计分析计划

建议最小统计包：

1. 比例指标：Wilson 95% CI。
2. 与 `mirage_full` 差异：Fisher exact（双侧）。
3. 报告 attack 与 benign 两侧 p-value。
4. 不仅报点估计，还要给计数分子/分母。

实现参考：

1. `scripts/fair_full_stats.py`

## 8.8 错误归因与失败模式分析

必须做 reason_code 分解：

1. benign deny 的原因分布。
2. attack leak 的原因分布。
3. 可用性失败与安全拒绝分离（例如 quota/parse failure 不应被误当“强安全”）。

实现参考：

1. `scripts/fair_utility_breakdown.py`

## 8.9 复现与产物治理

每次实验必须产出：

1. 固定 manifest。
2. row-level 结果。
3. summary JSON。
4. 统计 JSON。
5. 配置快照（seed/model/runtime/defense）。
6. run_tag 对应目录。

严禁：

1. 手工抄表。
2. 在无 run_tag 约束下“取最新文件”。

---

## 9. Benchmark 与 Baseline 最终建议组合（可投稿）

## 9.1 主表（必须）

1. 数据：AgentLeak 官方 `C1..C5`。
2. 系统：`mirage_full`, `policy_only`, `single_server_policy`, `codex_native`, `openclaw_native`。
3. 指标：`AttackLeakRate/AttackBlockRate/BenignAllowRate` + p50/p95。
4. 统计：CI + Fisher vs `mirage_full`。

## 9.2 扩展表（建议）

1. 防护基线：`codex_drift`, `codex_ipiguard`, `codex_agentarmor`。
2. 外部鲁棒性：AgentDojo / ASB / DRIFT / IPIGuard 统一报告。
3. 协议轨：delegation/federation/capsule/NBE tests。
4. 性能轨：policy kernel + e2e shaping + scaling。

## 9.3 必写脚注

1. 各基线威胁模型差异。
2. coverage 差异（例如不同 benchmark 的任务/注入数量不同）。
3. 基础设施可用性异常（quota/outage）解释。

---

## 10. 论文提交前验收标准

## 10.1 安全与协议

1. NBE 可执行检查通过。
2. 核心 security tests 全绿。
3. delegation/federation/capsule 关键断言通过。

## 10.2 数据与统计

1. 主表分子/分母可回溯到 row-level 文件。
2. CI 与 p-value 可复算。
3. reason_code 分解可解释主要误差来源。

## 10.3 文档一致性

1. README / benchmark 文档 / TeX 数值一致。
2. 定义一致（`ReqHash/rho/ctx/hctx`）。
3. 假设一致（TTL/replay/non-collusion/capsule 前提）。

## 10.4 复现一致性

1. 所有产物按 run_tag 隔离。
2. 统一报告生成命令可重放。
3. 报告引用路径不跨 run_tag。

---

## 11. 分阶段执行路线（不含实时进度）

### Phase 0：规范冻结

1. 冻结协议定义与 accept predicate。
2. 冻结 baseline 集合与公平性协议。
3. 冻结主表指标与统计方法。

### Phase 1：安全轨收敛

1. 形式化检查与单测全通过。
2. delegation/federation/capsule 断言补齐。

### Phase 2：主表评测

1. 跑 AgentLeak 官方同口径 fair compare。
2. 生成统计与失败归因。

### Phase 3：扩展评测

1. 跑 defense baseline。
2. 跑外部注入鲁棒性轨（AgentDojo/ASB/DRIFT/IPIGuard）。

### Phase 4：性能轨

1. policy kernel 曲线。
2. scaling + transport。
3. e2e shaping 曲线。

### Phase 5：论文回填

1. 更新 README/BENCHMARK/TeX。
2. 附录补齐假设与局限。
3. 产出“冻结索引（run_tag + commit + artifact path）”。

---

## 12. 附：关键命令模板（供复现）

## 12.1 主公平评测

```bash
OUT_DIR=artifact_out_compare_noprompt \
MIRAGE_SEED=7 \
FAIR_FULL_REUSE_SECURECLAW=1 \
FAIR_FULL_REUSE_NATIVE=1 \
DEFENSE_BASELINES=drift,ipiguard,agentarmor \
python scripts/fair_full_compare.py
```

## 12.2 统计与分解

```bash
python scripts/fair_full_stats.py --report artifact_out_compare_noprompt/fair_full_report.json
python scripts/fair_utility_breakdown.py --report artifact_out_compare_noprompt/fair_full_report.json
```

## 12.3 多轨汇总

```bash
python scripts/multi_track_eval.py --out-dir artifact_out_compare_noprompt --run-protocol-tests 1
```

## 12.4 外部 benchmark 管线

```bash
bash scripts/run_full_external_eval_pipeline.sh
python scripts/external_benchmark_unified_summary.py \
  --output-json artifact_out_external_runtime/external_benchmark_unified_report.json \
  --output-md artifact_out_external_runtime/external_benchmark_unified_report.md
```

---

## 13. 一句话结论

SecureClaw 的核心价值不在“模型更听话”，而在于把副作用提交变成可验证的协议事实：只有在双证明、强绑定、可审计、可重放防护都满足时，系统才允许 effect commit；实验设计的核心是把这种协议级保证与运行时基线放在同一口径下做可复算比较。
