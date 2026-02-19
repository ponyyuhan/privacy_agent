# SecureClaw：动机、问题定义、目标与方案（中文论文级草稿）

SecureClaw 在仓库早期历史中曾被称为 SecureClaw-OG++。为保证复现兼容，artifact 中仍保留少量历史命名。

## 摘要级结论

现代 Agent 系统的核心安全缺口，不在于“是否能识别风险”，而在于“是否能**不可绕过地约束副作用执行**”。  
SecureClaw 的核心思想是把信任从“模型是否听话”迁移到“系统执行线是否可验证”：

1. 不可信运行时只暴露一个高层动作面（`act`）。
2. 策略外包采用 2-server PIR（DPF/FSS）降低单点可见性。
3. 采用事务化 `PREVIEW -> COMMIT` 与 MPC 产出提交证据。
4. 副作用仅由独立 Executor 执行，缺少双策略证明即 fail-closed。
5. 通过 Capsule 约束恶意 skill 的本地绕过路径（文件/进程/网络）。

本文档基于当前仓库实现和已产出的 artifact 结果，给出可直接用于论文写作的中文版本。

---

## 1. 研究动机（Motivation）

### 1.1 风险已从“内容不安全”升级为“执行不安全”

在真实 Agent 生态中，攻击者越来越少追求“让模型说错话”，越来越多追求“让模型替用户执行动作”。典型攻击目标包括：

- 诱导读取并外发本地敏感材料（SSH 私钥、API Token、配置凭据）。
- 利用 skill/package 文档诱导下载-执行链（`curl|bash`、二阶段加载）。
- 借助网络工具对外回连可疑基础设施（C2/IOC 域名或 IP）。
- 绕开 MCP/网关，直接通过本地网络或进程接口执行副作用。

因此，单纯的提示词防护、拒答策略或分类器式 guardrail 无法覆盖执行面威胁。

### 1.2 策略外包的结构性矛盾

组织希望集中维护策略库（allowlist/IOC/DLP），以便统一更新和审计；  
同时又不希望策略服务看到具体查询对象（收件人、域名、文本片段）。

即：

- 集中策略提高可运营性；
- 集中明文可见性带来隐私泄露。

SecureClaw 的动机是把该矛盾转化为“系统与密码学”的可落地问题：  
在不暴露单点明文查询的前提下，仍保持策略判断与执行约束能力。

### 1.3 为什么“不可绕过执行线”是关键要求

风险识别再准确，如果副作用可绕过策略层直接执行，系统仍不安全。  
因此核心要求不是“给出建议”，而是“形成可验证、可拒绝、可审计的执行门”：

- 副作用必须绑定双重策略授权证据；
- 证据缺失、不一致或过期时必须 fail-closed。

---

## 2. 问题定义（Problem Definition）

### 2.1 系统实体

- `A`：不可信 Agent Runtime（含 skills、prompt、外部文档输入）。
- `G`：可信 Gateway（最小可信计算基）。
- `P0, P1`：诚实但好奇且不合谋的双策略服务。
- `E`：独立执行器（真实副作用唯一执行点）。
- `C`：可选 Capsule（OS 级隔离与约束层）。

### 2.2 副作用集合

定义副作用集合：

`SE = {SendMessage, FetchResource, PostWebhook, CommitSkillInstall}`

这些操作具有真实外部影响，必须纳入强制安全约束。

### 2.3 对手模型

攻击者可：

- 控制 prompt 和 skill 文本内容；
- 诱导读取敏感信息并外发；
- 尝试绕过网关直接触发执行接口；
- 观察单个策略服务 transcript 并反推查询身份。

假设：

- 至少一台策略服务不与另一台合谋；
- Gateway 与 Executor 不被同时攻破；
- 若声明 SCS 性质，需满足 Capsule mediation contract。

---

## 3. 安全目标（Security Objectives）

### 3.1 NBE：Non-Bypassable Effects（副作用不可绕过）

任何成功执行的副作用请求，必须携带来自 `P0/P1` 的有效 commit proofs，且绑定同一 `(action_id, program_id, request_sha256)`。

### 3.2 SM：Secret Myopia（秘密近视）

默认路径下不向不可信运行时返回敏感明文，仅返回 opaque handle；  
明文释放需显式满足去密级约束（如用户确认）。

### 3.3 SAP：Single-Auditor Privacy（单审计方隐私）

在单个策略服务可见的 transcript 视角下，不应恢复具体查询身份（recipient/domain/token），只暴露约定的形状级泄露。

### 3.4 SCS：Skill-Confined Safety（技能受限安全）

在 capsule 约束成立时，恶意 skill 不能通过本地文件/进程/网络直接绕过 `act` 执行线。

---

## 4. 当前项目已解决的核心问题

1. **执行绕过问题**  
   副作用不再由网关单点放行，Executor 会二次校验双证明与请求绑定。

2. **明文泄露问题**  
   敏感读取先 handle 化，避免明文直接暴露给 agent。

3. **策略外包隐私问题**  
   membership 查询通过 2-server PIR（DPF/FSS）完成，避免单点看见明文查询值。

4. **skill 安装供应链问题**  
   skill enable 被纳入 `PREVIEW -> COMMIT` 事务路径，而非“导入即信任”。

5. **本地直接绕过问题**  
   Capsule + UDS netless 路径抑制恶意 skill 的 direct exec/network bypass。

6. **真实 Agent 可验证性问题**  
   方案不仅在脚本化 demo 成立，也在 OpenClaw/NanoClaw 运行时可复现。

---

## 5. 方案设计（Approach）

### 5.1 单动作面收敛：`act(intent_id, inputs, constraints, caller)`

不可信运行时通过统一高层接口表达意图，不能在可信面直接发起任意低层命令。  
Gateway 在 `gateway/router.py` 中完成路由、能力校验与审计。

### 5.2 Handle-first 秘密数据流（SM）

- 敏感读取产生带绑定信息的 handle（`session/caller/ttl/sensitivity`）。
- 高敏句柄禁止流向外发 sink。
- 去密级动作需显式确认。

### 5.3 2-server PIR 外包策略查询（SAP）

对查询索引 `alpha`：

1. Gateway 生成 DPF keys `(k0, k1)`；
2. `P0/P1` 分别在本地 bitset 上计算 O(N) share；
3. Gateway 重构最终 bit，单个策略服务看不到明文查询对象。

适用于：recipient/domain allowlist、IOC、install marker、DFA block transition。

### 5.4 事务化 PREVIEW -> COMMIT（NBE 核心）

`PREVIEW`：

1. 计算 canonical `request_sha256` 绑定；
2. 执行固定形状 PIR 查询（降低意图侧信道）；
3. 基于 DSL（`policy_server/policy.yaml`）编译电路并运行 MPC；
4. 返回 `tx_id` + commit evidence。

`COMMIT`：

1. 校验 `tx_id` 的 caller/session/TTL 绑定；
2. Executor 校验双 MAC proof 与哈希绑定；
3. 重构输出位（`allow_pre/need_confirm/patch`）；
4. 在 Executor 内强制应用 sanitize patch 后执行副作用。

### 5.5 Skill Ingress 事务门控

路径：

`ImportSkill -> DescribeSkill -> CheckSkillInstallPolicy -> CommitSkillInstall`

- Import 仅 staging，不执行代码；
- Check 阶段结合 PIR 信号（IOC/install）与本地特征（obfuscation）；
- Commit 必须通过双证明；
- 成功后签发 `workload_token`，用于后续最小权限身份投影。

### 5.6 per-skill workload identity

`workload_token`（HMAC + session 绑定）使 Gateway 能将不可信 caller 覆写为 `skill:<digest>`，从而在 capability 层实现最小权限隔离。

### 5.7 Capsule 与 UDS netless（SCS 支撑）

推荐安全路径：

- Gateway 使用 UDS 暴露；
- Capsule 网络禁用；
- 拒绝不在白名单内的本地执行与敏感路径访问。

---

## 6. 基于当前 Artifact 的实证证据

数据来源：`artifact_out/report.json`、`artifact_out/bench_fss.txt`、`artifact_out/bench_e2e*.json`。  
当前报告时间戳对应 UTC 时间：**2026-02-10 08:39:33**。

### 6.1 绕过抑制与 Capsule 证据

- `capsule_smoke.status = OK`
- `direct_fs_read.ok = false`
- `direct_exec_true.ok = false`
- `direct_exec_sh.ok = false`
- `direct_exfil_post.ok = false`
- `direct_internet.ok = false`
- `gateway_act.ok = true`
- `gateway_mcp_act.ok = true`

对照基线：

- `baselines.no_capsule_direct_exfil.ok = true`（无 capsule 时可绕过）
- `baselines.no_nbe_insecure_executor.reason_code = ALLOW_INSECURE`（关闭双授权即可被绕过）
- `baselines.capsule_loopback_http_exfil.direct_exfil_post.ok = true`（loopback HTTP + 放宽网络会重新暴露绕过面）

### 6.2 Secret Myopia 与提交约束证据

恶意流程结果：

- `read_file -> OK / SENSITIVE_HANDLE_RETURNED`
- `declassify -> DENY / REQUIRE_CONFIRM`
- `exfil_handle -> DENY / HIGH_HANDLE_BLOCKED`
- `exfil_secret_text -> DENY / REQUIRE_CONFIRM`
- `exfil_secret_text_commit -> OK / ALLOW`（显式确认后走合法提交路径）

### 6.3 Skill Ingress 证据

- 良性 skill：允许并可提交启用；
- 可疑 skill：需确认（未确认不能提交）；
- IOC 命中 skill：在 PREVIEW 阶段阻断；
- SkillDocBench v1：`n=100`, `accuracy=1.0`。

### 6.4 单点可见性（泄露）证据

- `leakage_eval.unshaped.n_unique_features = 17`
- `leakage_eval.shaped.n_unique_features = 1`

外包对照：

- 明文外包：`id_accuracy = 1.0`
- PIR transcript 单点视角：`id_accuracy = 0.0`

### 6.5 性能证据

FSS 微基准（`domain_size=4096`）：

- `dpf_key_bytes = 235`
- `eval_pir_share_avg_s = 0.012477`

E2E 吞吐：

- Python policy backend：`throughput_ops_s = 0.731`
- Rust policy backend：`throughput_ops_s = 10.516`

含义：O(N) 内积路径的编译后端优化可显著提升吞吐常数。

---

## 7. 可声明的阶段性贡献（当前版本）

1. 构建了针对 Agent 副作用的可验证不可绕过执行线（双证明执行器）。
2. 将策略外包与查询隐私通过 2-server PIR（DPF/FSS）统一到可运行系统中。
3. 将 skill install/enable 纳入与 egress 同等级的事务控制，并引入 per-skill workload identity。
4. 提供可复现实验工件（artifact）、基线/消融、以及真实 Agent 运行验证路径。

---

## 8. 边界与局限（严谨披露）

1. MPC 为研究原型实现，尚非全栈工业级 2PC 框架替换。
2. 流量隐藏目前以 fixed-shape/padding/bundle 为主，未覆盖完整 cover traffic。
3. Capsule 为 MVP 级，跨平台硬化与内核对抗不在当前完成范围。
4. 数据集规模与策略语言覆盖仍可继续扩展。

这些边界定义了当前 artifact 的能力范围，不影响其核心系统主张。

---

## 9. 下一步走向“完整体”的目标

1. 高性能策略后端：SIMD/向量化 PIR 内积与更强编译后端。
2. 更强元数据隐私：cover traffic、批处理混洗、恒定化响应形状。
3. 更完整策略 DSL 与更丰富 intent taxonomy。
4. 更严格持久化与撤销策略（handles/tx/workload token）。
5. 跨平台生产级 capsule 硬化（macOS/Linux/Windows）。

---

## 10. 可直接放论文的一段中文总述

Agent 系统的主要安全风险正在从内容层面迁移到执行层面：攻击者可通过 prompt 或 skill 文档驱动模型触发真实副作用、外泄敏感数据并绕过表层防护。SecureClaw 将该问题重构为系统执行约束问题：不可信运行时仅能通过统一高层动作接口表达意图，策略判断通过双策略服务上的隐私保护计算完成，副作用提交则必须由独立执行器在验证双重加密证明后执行，并在不满足条件时 fail-closed。系统进一步将 skill install 或 enable 纳入事务化控制，并通过 capsule 约束本地直接绕过路径。该设计表明，面向真实 Agent 生态的安全性不仅依赖风险识别能力，更依赖可验证、不可绕过的执行线。

---

## 11. 与 Codex/Claude 内置安全手段的功能差异勾选矩阵（截至 2026-02-13）

为保证严谨性，判定口径如下：

- `✅`：对 Codex 或 Claude 而言为官方文档明确声明的一等能力。对 SecureClaw 而言为仓库内已实现并有 artifact 证据支撑。
- `◐`：部分具备或可通过配置实现，但语义上不等价于 SecureClaw 的加密不可绕过执行约束。
- `❌`：在引用资料中未见该能力作为内置机制被明确声明。

| 能力项 | SecureClaw（本项目） | OpenAI Codex 内置 | Claude Code 内置 | 证据与说明 |
|---|---|---|---|---|
| 运行时隔离与操作审批门控 | ✅ | ✅ | ✅ | SecureClaw 通过 capsule+gateway 执行线；Codex 文档说明 sandbox/approval 机制；Claude 文档说明 permission 架构与 sandboxed bash。 |
| 本地工作流默认限制网络 | ◐ | ✅ | ✅ | SecureClaw 在启用 capsule/UDS 的 netless 配置时可实现（推荐路径），但是否默认取决于部署配置；Codex 本地默认网络关闭；Claude 默认网络请求需审批。 |
| 组织/管理员对本地代理配置施加约束 | ◐ | ✅ | ◐ | Codex 有 `requirements.toml` 与托管 requirements；Claude 文档提到 server-managed settings；SecureClaw 目前有策略配置但未形成完整企业级配置治理面。 |
| MCP 服务与工具白名单控制 | ◐ | ✅ | ✅ | Codex 支持 MCP 身份 allowlist 与工具 allow/deny；Claude 支持允许的 MCP servers 与权限配置；SecureClaw 当前主要在 gateway 做能力/策略控制，尚未做到对等的完整 MCP 身份策略平面。 |
| 副作用执行前必须具备双策略加密证明 | ✅ | ❌ | ❌ | SecureClaw Executor 验证 `P0/P1` 双证明与绑定元数据；Codex/Claude 文档未声明等价的双证明提交机制。 |
| 独立 Executor 二次验签（网关不能单点放行副作用） | ✅ | ❌ | ❌ | SecureClaw 明确分离 gateway/executor 并 fail-closed；Codex/Claude 文档未声明该原语。 |
| 事务化 `PREVIEW -> COMMIT`（含 `tx_id` 与请求哈希绑定） | ✅ | ❌ | ❌ | SecureClaw 协议与 artifact 可验证；Codex/Claude 文档未声明原生事务化副作用提交流程。 |
| 基于 2-server PIR（DPF/FSS）的策略外包 membership 查询 | ✅ | ❌ | ❌ | SecureClaw 使用 PIR share + bitset 评估；Codex/Claude 文档未见 PIR/FSS 外包策略机制。 |
| 单审计方视角的 transcript 隐私（难还原具体查询身份） | ✅ | ❌ | ❌ | SecureClaw 有 leakage 对照实验；Codex/Claude 文档未声明同类单方可见性隐私保证。 |
| Handle-first 敏感数据流与显式去密级门控 | ✅ | ❌ | ❌ | SecureClaw 对敏感读取返回 handle 并对去密级动作强制约束；Codex/Claude 文档侧重权限与沙箱，不是 handle 语义执行模型。 |
| Skill 安装/启用纳入事务化副作用门控 | ✅ | ❌ | ❌ | SecureClaw skill ingress 需要 check+commit 证明后启用；Codex/Claude 文档未声明默认等价机制。 |
| per-skill workload identity（`skill:<digest>`）最小权限投影 | ✅ | ❌ | ❌ | SecureClaw 通过 session 绑定 token 覆写 caller；Codex/Claude 引用资料未声明同类内置能力。 |
| 通过消融实验证明“移除 NBE 层即可重新绕过” | ✅ | ❌ | ❌ | SecureClaw artifact 含 no-capsule/no-NBE 基线；Codex/Claude 产品文档不以该类密码学消融为主要输出。 |
| 云端隔离执行与厂商托管凭据代理 | ❌ | ✅ | ✅ | Codex 云端在隔离容器执行；Claude Web 运行于隔离 VM，并文档化了受限凭据代理与清理机制。 |
| 云端会话审计日志内置支持 | ◐ | ◐ | ✅ | Claude 文档明确 cloud audit logging；Codex 文档包含日志/遥测/会话持久化控制；SecureClaw 当前已有运行日志与 artifact 记录，但企业级统一审计面仍在完善。 |

### 这组差异对论文主张的意义

Codex/Claude 的内置能力在工程运维层面很强，核心是“权限+沙箱+审批治理”；  
SecureClaw 解决的是另一个正交问题：对副作用授权做可加密验证、可审计的不可绕过执行约束，并在策略外包时提供单点可见性隐私。  
因此三者关系是“可叠加互补”，不是“互相替代”。

---

## 12. 矩阵引用来源

- [SecureClaw-Impl] 仓库实现入口：`gateway/`、`policy_server/`、`executor_server/`、`capsule/`、`integrations/openclaw_runner/`。
- [SecureClaw-Art] 工件结果：`artifact_out/report.json`、`artifact_out/bench_fss.txt`、`artifact_out/bench_e2e.json`、`artifact_out/bench_e2e_rust.json`。
- [OAI-Sec] OpenAI Codex Security：https://developers.openai.com/codex/security
- [OAI-Config] OpenAI Codex Configuration Reference：https://developers.openai.com/codex/config-reference
- [OAI-CLI] OpenAI Codex CLI Features：https://developers.openai.com/codex/cli/features
- [OAI-Blog] OpenAI《Introducing upgrades to Codex》（2025-09-15）：https://openai.com/index/introducing-upgrades-to-codex/
- [CLAUDE-Sec] Claude Code Security：https://code.claude.com/docs/en/security
- [CLAUDE-Blog] Anthropic 沙箱文章：https://www.anthropic.com/engineering/claude-code-sandboxing

---

## 13. 扩展公开案例库（Codex / Claude / OpenClaw）

本节的口径说明：

- 所有案例都按“版本区间 + 发布时间”描述，避免泛化成“永远不安全”。
- 结论不是“内置防护无效”，而是“单层权限/沙箱/审批在真实世界反复被绕过，因此需要额外的加密不可绕过执行层”。
- 时间一律用绝对 UTC 日期，便于论文引用。

### 13.1 Codex 相关公开案例

| 案例 ID | 时间（UTC） | 产品 / 影响版本 | 公开描述（摘要） | 对 SecureClaw 的启示 |
|---|---|---|---|---|
| C-01 | 2025-09-22 | `@openai/codex` `< 0.39.0` | 沙箱路径边界逻辑缺陷，模型生成 cwd 可越过工作区边界，导致越界写入/执行（`CVE-2025-59532`）。 | SecureClaw 最终副作用仍要过 dual-proof executor；运行时沙箱混淆不等于可提交副作用。 |
| C-02 | 2025-08-13 | Codex CLI（社区 CVE 记录） | workspace-write 模式下 symlink 跟随问题可导致覆盖写入/潜在 RCE（`CVE-2025-55345`）。 | SecureClaw 通过 handle-first + capability + executor 校验，避免“本地读到即外发”。 |
| C-03 | 2025-07-25 | Codex CLI `< 0.9.0`（社区 CVE 记录） | `rg` 自动批准存在危险 flag 覆盖问题（`CVE-2025-54558`）。 | SecureClaw 不把最终安全性建立在命令 allowlist 上，而是建立在 PREVIEW->COMMIT + 双证明执行。 |

### 13.2 Claude Code 公开案例（节选）

| 案例 ID | 时间（UTC） | 产品 / 影响版本 | 公开描述（摘要） | 对 SecureClaw 的启示 |
|---|---|---|---|---|
| A-01 | 2025-08-16 | `claude-code` `< 1.0.4` | 过宽 allowlist 使提示注入链可“读文件+外发”绕过确认（`CVE-2025-55284`）。 | SecureClaw 对敏感读默认只返回句柄，高敏句柄外发直接阻断。 |
| A-02 | 2025-08-05 | `claude-code` `< 1.0.20` | `echo` 命令解析错误可绕过审批（`CVE-2025-54795`）。 | SecureClaw 副作用授权是加密证明驱动，不依赖单点审批语义。 |
| A-03 | 2025-09-10 | `claude-code` `< 1.0.105` | `rg` 解析错误可绕过审批（`CVE-2025-58764`）。 | 命令解析层失效时，SecureClaw 仍由 executor 二次验签兜底。 |
| A-04 | 2025-12-03 | `claude-code` `< 1.0.93` | `$IFS`/短参数解析导致命令校验绕过并执行（`CVE-2025-66032`）。 | SecureClaw 绑定 `request_sha256` + 双策略 commit proofs。 |
| A-05 | 2025-10-03 | `claude-code` `< 1.0.120` | deny 规则在 symlink 下可被绕过（`CVE-2025-59829`）。 | SecureClaw 通过独立 executor + handle 绑定降低路径绕过后果。 |
| A-06 | 2025-10-03 | `claude-code` `< 1.0.111` | 启动 trust dialog 前可被诱导执行项目内代码（`CVE-2025-59536`）。 | SecureClaw 将 skill/运行时置于 capsule 与事务门控下，副作用仍需证明链。 |
| A-07 | 2025-11-19 | `claude-code` `< 1.0.39` | Yarn 插件路径可在信任前触发执行（`CVE-2025-65099`）。 | SecureClaw 将 skill enable 视为事务副作用，不是“加载即信任”。 |
| A-08 | 2025-06-24 | `claude-code` `>=0.2.116,<1.0.24` | IDE 扩展 WebSocket 可被任意来源连接（`CVE-2025-52882`）。 | SecureClaw 推荐 UDS + token 绑定传输，且最终由 executor 校验。 |
| A-09 | 2026-01-21 | `claude-code` `< 2.0.65` | 恶意仓库环境配置可在信任前泄露 API key（`CVE-2026-21852`）。 | SecureClaw 对数据释放做 handle/caller/session 绑定与显式去密级门控。 |
| A-10 | 2026-02-03 | `claude-code` `< 1.0.111` | trusted-domain 前缀校验可被伪域名绕过，触发自动请求（`CVE-2026-24052`）。 | SecureClaw 在 egress commit 前执行目的地策略与 IOC/allowlist 校验。 |

补充的近期 Claude 案例（同类漏洞家族）：

| 案例 ID | 时间（UTC） | 产品 / 影响版本 | 公开描述（摘要） | 对 SecureClaw 的启示 |
|---|---|---|---|---|
| A-11 | 2026-02-06 | `claude-code` `< 2.1.7` | deny 规则可经 symlink 绕过（`CVE-2026-25724`）。 | SecureClaw 增加 executor 侧 proof 门控与 handle 绑定数据流。 |
| A-12 | 2026-02-06 | `claude-code` `< 2.0.55` | 管道 `sed` 命令注入可绕过写入限制（`CVE-2026-25723`）。 | SecureClaw 无双证明不放行写入/外发副作用。 |
| A-13 | 2026-02-06 | `claude-code` `< 2.0.57` | `cd` + 写路径校验薄弱可写入受保护目录（`CVE-2026-25722`）。 | SecureClaw 将命令解析正确性与最终副作用授权解耦。 |
| A-14 | 2026-02-03 | `claude-code` `< 2.0.72` | `find` 命令注入可绕过审批（`CVE-2026-24887`）。 | SecureClaw 在 executor 缺证据即 fail-closed。 |
| A-15 | 2026-02-03 | `claude-code` `< 2.0.74` | ZSH clobber 解析缺陷可导致任意写入（`CVE-2026-24053`）。 | SecureClaw 的副作用门控独立于 shell 解析细节。 |
| A-16 | 2025-11-21 | `claude-code` `< 2.0.31` | `sed` 校验绕过可导致任意文件写入（`CVE-2025-64755`）。 | SecureClaw 用事务化与能力投影约束副作用。 |
| A-17 | 2025-09-24 | `claude-code` `< 1.0.39` | Yarn2+ 插件自动加载可在信任前执行（`CVE-2025-59828`）。 | SecureClaw 将 skill enable 纳入可审计事务。 |
| A-18 | 2025-09-10 | `claude-code` `< 1.0.105` | 恶意 git email 可触发信任前执行（`CVE-2025-59041`）。 | SecureClaw 通过 capsule + 双证明提交降低此类启动链风险。 |

### 13.3 OpenClaw 公开案例

| 案例 ID | 时间（UTC） | 产品 / 影响版本 | 公开描述（摘要） | 对 SecureClaw 的启示 |
|---|---|---|---|---|
| O-01 | 2026-02-06 | `openclaw` `< 2026.1.20` | 本地未认证客户端可通过 WebSocket `config.apply` + 不安全 `cliPath` 触发本地 RCE（`CVE-2026-25593`）。 | SecureClaw 的副作用提交仍需双证明，控制面失守不直接等于副作用可执行。 |
| O-02 | 2026-02-04 | `openclaw` `< 2026.1.30` | `MEDIA:/path` 提取可导致任意本地文件包含读取（`CVE-2026-25475`）。 | SecureClaw 将敏感读取 handle 化并限制高敏外发路径。 |
| O-03 | 2026-02-02 | VirusTotal Blog | VirusTotal 报告其已分析 **3,016+** 个 OpenClaw skills，发现**数百**个处于“主动恶意”状态，并点名 ClawHub 发布者单人关联 **314** 个恶意 skill（体现供应链集中度风险）。 | SecureClaw 将 skill enable 纳入 PREVIEW->COMMIT，并引入 IOC/suspicious 分流。 |
| O-04 | OpenClaw 官方文档 | 安全 / Threat model | 官方文档描述了“运行带 shell access 的 AI gateway”的威胁模型，并强调硬化不是完美边界。 | SecureClaw 在沙箱之外再加一层加密执行门，形成正交防线。 |

---

## 14. 真实运行复现（本仓库，2026-02-13 UTC）

### 14.1 实际执行命令

1. `OUT_DIR=artifact_out BENCH_ITERS=12 BENCH_CONCURRENCY=3 bash scripts/run_artifact.sh`  
2. `PYTHONPATH=. BENCH_ITERS=12 BENCH_CONCURRENCY=3 POLICY_BACKEND=python BENCH_OUT_PATH=/Users/yuhan/PycharmProjects/privacy_agent/artifact_out/bench_e2e.json python scripts/bench_e2e_throughput.py`  
3. `PYTHONPATH=. BENCH_ITERS=12 BENCH_CONCURRENCY=3 POLICY_BACKEND=rust BENCH_OUT_PATH=/Users/yuhan/PycharmProjects/privacy_agent/artifact_out/bench_e2e.rust.json python scripts/bench_e2e_throughput.py`  
4. `OPENCLAW_STATE_DIR=artifact_out/openclaw_state OPENCLAW_MODEL_PRIMARY=openai-codex/gpt-5.1-codex-mini bash scripts/run_openclaw.sh`

本节引用的实际产物：

- `artifact_out/report.json`（`ts=1770975104`，UTC `2026-02-13T09:31:44Z`）
- `artifact_out/bench_fss.txt`
- `artifact_out/bench_e2e.json`
- `artifact_out/bench_e2e.rust.json`
- `artifact_out/openclaw_benign.json`
- `artifact_out/openclaw_malicious.json`

### 14.2 攻击类复现矩阵（公开案例类型 -> 本地实测）

| 复现 ID | 对应公开攻击类型 | 本次运行观察结果 | 本地证据 |
|---|---|---|---|
| R-01 | 直接本地文件读取绕过 | capsule 内被阻断（`PermissionError`） | `report.json:capsule_smoke.direct_fs_read.ok=false` |
| R-02 | 直接进程执行绕过 | capsule 内 `/usr/bin/true`、`/bin/sh` 均被阻断 | `report.json:capsule_smoke.direct_exec_true.ok=false`, `direct_exec_sh.ok=false` |
| R-03 | 直接网络外发绕过 | capsule 配置下外发失败 | `report.json:capsule_smoke.direct_exfil_post.ok=false`, `direct_internet.ok=false` |
| R-04 | 消融：无 capsule | 直接外发可成功 | `report.json:baselines.no_capsule_direct_exfil.ok=true` |
| R-05 | 消融：弱化 loopback 传输 | loopback 外发可成功 | `report.json:baselines.capsule_loopback_http_exfil.direct_exfil_post.ok=true` |
| R-06 | Executor 缺失提交证据绕过 | 被拒绝（fail-closed） | `report.json:executor_bypass_attempts.missing_evidence.status=DENY` |
| R-07 | 仅单侧 proof 绕过 | 被拒绝（fail-closed） | `report.json:executor_bypass_attempts.one_server_proof_only.status=DENY` |
| R-08 | 真实 OpenClaw 恶意链中的敏感读取 | 返回句柄，不给明文 | `openclaw_malicious.json` 第 1 段 `SENSITIVE_HANDLE_RETURNED` |
| R-09 | 未确认去密级 | 被拒绝 | `openclaw_malicious.json` 第 2 段 `REQUIRE_CONFIRM` |
| R-10 | 高敏句柄外发 | 被拒绝 | `openclaw_malicious.json` 第 3 段 `HIGH_HANDLE_BLOCKED` |
| R-11 | 真实 OpenClaw 恶意外发闭环 | 最终发送被策略拒绝 | `openclaw_malicious.json` 第 4 段 `POLICY_DENY` |
| R-12 | 可疑 skill 安装 | 需要显式确认 | `report.json:skill_ingress.suspicious.check.reason_code=REQUIRE_CONFIRM` |
| R-13 | IOC 命中 skill 安装 | 直接阻断 | `report.json:skill_ingress.ioc_blocked.check.reason_code=IOC_BLOCKED` |
| R-14 | skill 越权调用 | caller 投影到 `skill:<digest>`，`SendMessage` 被拒绝 | `report.json:workload_identity.send_message.reason_code=CAPABILITY_DENY` |
| R-15 | 策略外包身份泄露 | 明文外包 `id_accuracy=1.0`；PIR 外包 `id_accuracy=0.0` | `report.json:outsourcing_comparison` |
| R-16 | transcript 侧信道 | `n_unique_features` 从 `17` 降到 `1`；推断准确率下降（`0.5556 -> 0.1111`） | `report.json:leakage_eval` |

### 14.3 本次实跑的性能与工程可行性

- FSS/DPF 微基准（`domain_size=4096`）：`dpf_key_bytes=235`，`eval_pir_share_avg_s=0.009850`（`artifact_out/bench_fss.txt`）。
- E2E 吞吐：
  - Python 后端：`throughput_ops_s=0.734`，`avg_ms=4086.868`。
  - Rust 后端：`throughput_ops_s=10.69`，`avg_ms=265.178`。
- 真实 OpenClaw（OpenAI OAuth）运行：
  - benign 会话 `mirage-openclaw-benign`：`6450 ms`。
  - malicious 会话 `mirage-openclaw-malicious`：`77332 ms`，并出现分阶段 DENY/确认行为。

---

## 15. 案例到防线映射（SecureClaw 相比内置防护新增了什么）

从 C-01..O-04 的共性可以看到：多数失守发生在解析器、allowlist、路径校验、信任对话框等单层控制点。  
SecureClaw 的增量在于“副作用执行的加密证据门控”：

1. `PREVIEW -> COMMIT` 生成事务绑定证据；
2. Executor 校验双策略服务 proofs 与请求哈希绑定；
3. 证据不完整/不一致直接 fail-closed；
4. 敏感数据采用 handle 类型并绑定 session/caller；
5. skill enable 与外发同级，纳入事务化副作用控制。

这不是替代沙箱与审批，而是在它们失效时限制后果的正交安全层。

---

## 16. 第 13-15 节附加来源

- [CVE-Mitre-Codex-59532] https://cveawg.mitre.org/api/cve/CVE-2025-59532
- [CVE-Mitre-Codex-55345] https://cveawg.mitre.org/api/cve/CVE-2025-55345
- [CVE-Mitre-Codex-54558] https://cveawg.mitre.org/api/cve/CVE-2025-54558
- [GHSA-Codex-59532] https://github.com/advisories/GHSA-w5fx-fh39-j5rw
- [GH-API-Claude-Advisories] https://api.github.com/advisories?ecosystem=npm&affects=%40anthropic-ai%2Fclaude-code&per_page=100
- [CVE-Mitre-Claude-55284] https://cveawg.mitre.org/api/cve/CVE-2025-55284
- [CVE-Mitre-Claude-66032] https://cveawg.mitre.org/api/cve/CVE-2025-66032
- [CVE-Mitre-Claude-59829] https://cveawg.mitre.org/api/cve/CVE-2025-59829
- [CVE-Mitre-Claude-59536] https://cveawg.mitre.org/api/cve/CVE-2025-59536
- [CVE-Mitre-Claude-65099] https://cveawg.mitre.org/api/cve/CVE-2025-65099
- [CVE-Mitre-Claude-58764] https://cveawg.mitre.org/api/cve/CVE-2025-58764
- [CVE-Mitre-Claude-54795] https://cveawg.mitre.org/api/cve/CVE-2025-54795
- [CVE-Mitre-Claude-54794] https://cveawg.mitre.org/api/cve/CVE-2025-54794
- [CVE-Mitre-Claude-52882] https://cveawg.mitre.org/api/cve/CVE-2025-52882
- [CVE-Mitre-Claude-21852] https://cveawg.mitre.org/api/cve/CVE-2026-21852
- [CVE-Mitre-Claude-24052] https://cveawg.mitre.org/api/cve/CVE-2026-24052
- [CVE-Mitre-Claude-25724] https://cveawg.mitre.org/api/cve/CVE-2026-25724
- [CVE-Mitre-Claude-25723] https://cveawg.mitre.org/api/cve/CVE-2026-25723
- [CVE-Mitre-Claude-25722] https://cveawg.mitre.org/api/cve/CVE-2026-25722
- [CVE-Mitre-Claude-24887] https://cveawg.mitre.org/api/cve/CVE-2026-24887
- [CVE-Mitre-Claude-24053] https://cveawg.mitre.org/api/cve/CVE-2026-24053
- [CVE-Mitre-Claude-64755] https://cveawg.mitre.org/api/cve/CVE-2025-64755
- [CVE-Mitre-Claude-59828] https://cveawg.mitre.org/api/cve/CVE-2025-59828
- [CVE-Mitre-Claude-59041] https://cveawg.mitre.org/api/cve/CVE-2025-59041
- [GH-API-OpenClaw-Advisories] https://api.github.com/advisories?ecosystem=npm&affects=openclaw&per_page=100
- [CVE-Mitre-OpenClaw-25593] https://cveawg.mitre.org/api/cve/CVE-2026-25593
- [CVE-Mitre-OpenClaw-25475] https://cveawg.mitre.org/api/cve/CVE-2026-25475
- [OpenClaw-Security] https://docs.openclaw.ai/gateway/security
- [OpenClaw-Skills] https://docs.openclaw.ai/tools/skills
- [VirusTotal-OpenClaw-Skills-Study] https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html
