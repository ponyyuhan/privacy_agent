下面我继续（更“顶会 reviewer 视角” + 更聚焦“真实痛点” + 更聚焦“拉开与 AAB/Faramesh 的差距”）给你一些**可以在现有模块上小改/加模块**、但**贡献度明显变大**的方向。每个方向我都按：**痛点 → 你现在的基础 → 建议改/加什么 → 为什么能更像“非增量” → 怎么评估** 来写。

---

## 0) 先把“最大短板”当成新贡献的切入点：Benign leakage 还不够低

你自己的 briefing deck 里已经明确写了：在 parity run 里 SecureClaw 的 **normal-task leakage 仍是 0.3585**，并且你们自己也认为需要“better default secret sealing + better safe summaries”。这其实是 reviewer 最容易抓住的点：**攻击集 0 泄露很强，但正常任务下仍会泄露，说明系统还没把“默认行为”做对**。

所以最“划算”的路线是：**把“降低 benign leakage（且不牺牲可用性）”变成一个新模块/新贡献**，而不是只把它当成未来工作。下面的建议有一半都围绕这个点展开。

---

## 1) 加一个“Safe Output Builder（安全摘要/安全输出构造器）”：把 benign leakage 当成可系统性解决的问题

### 痛点（真实且 reviewer 关心）

* 现实里更多是“正常任务误泄露”，而不只是注入攻击下的外泄。
* 你现在的硬边界（Preview→Commit + executor fail-closed）对 **side effects** 很强，但 **C1（最终输出）** 仍可能把敏感值“解释/复述/总结”出来，导致 benign leakage。

### 你现在已有的基础

* 你已经有 **sealed handles / secret myopia**（敏感明文不进入 runtime），并且有显式 declassify 路径（需要确认）。
* 你也明确了“strict defaults 会降低 measured benign leakage，但部署里可以用 confirm/sanitize 恢复 utility”。

### 建议新增模块：Safe Output Builder（SOB）

核心目标：**把最终输出变成“默认安全”的产物**，而不是“模型自由生成 + 事后检查”。

**最小改动版（不动你核心协议）**：

1. **输出模板化（结构化）**：对常见 intents（email reply、ticket summary、CRM update、log summary…）给出固定“安全摘要模板”，模板字段默认只允许：

   * 非敏感统计信息（数量/时间/状态）
   * 去标识化描述（“a customer”, “an internal doc”, “a token-like string was detected”）
   * handle 引用（如果必须引用某个对象）
2. **摘要源头限制**：SOB 只从 gateway 内“安全视图”取信息，而不是把原始文本（含潜在秘密）喂回 LLM 让它自由总结。
3. **可控展开**：当用户确实需要某个敏感字段时，把它变成**显式“展开请求”**（等价于 declassify/confirm flow），并且强制走 Preview→Commit（或走 confirm-only 的安全路径）。

### 为什么这会显著拉开与 AAB/Faramesh 的差距？

Faramesh/AAB 的主线是“执行边界的确定性授权与可重放治理”，强调 canonicalization + decision artifacts + provenance logging。
它不主要解决“**正常任务里模型如何安全地输出/总结**”这个问题。你把 SOB 做成系统模块后，你的系统就从“只把 side effects 关起来”进化为“**连信息叙述/总结都被系统化约束**”，这不是 AAB 的自然延伸方向。

### 怎么评估（让 reviewer 买账）

* 在 AgentLeak parity（OR(C1,C2,C5)）里，单独报告：

  * **C1 benign leakage** 降幅（这是 SOB 的主目标）
  * utility 不要只用 allow rate：加“任务完成质量/用户满意度 proxy”（比如任务字段完整度、摘要可用性评分）
* 做一个消融：

  * baseline：现有系统
  * +SOB：只加输出构造器
  * +SOB + confirm policy：允许用户展开
    看 benign leakage 是否显著下降、并且 utility 回升。

---

## 2) 把“Policy-plane 隐私”从“机制”升级为“可验证的部署契约”：Policy Privacy Contract（PPC）

### 痛点

SAP 的核心假设是：固定形状/cover traffic/padding 等配置正确，否则单服务器 transcript 仍能泄露 intent 或 workload shape（你们自己也在 leakage sweep 里展示了 unshaped 有 MI）。

**reviewer 会问**：
“如果工程师把某个开关关了、或者新加了一个 intent 导致 program_id/shape 变化，你的 SAP 还成立吗？如何防止‘配置漂移’让隐私 silently break？”

### 你现在已有的基础

你已经有“可验证系统假设”的先例：**Capsule Mediation Contract** 有规范文件、smoke test、verifier，并且有“失败则降级 claim”的语义。

### 建议新增模块：Policy Privacy Contract（PPC）

模仿 capsule contract 的形态，为 SAP 增加一个“部署时必须通过的隐私契约”：

**PPC 内容可以非常工程化（但论文贡献很大）**：

1. **契约声明**（版本化 JSON / schema）：

   * 哪些 intents 被宣称“intent-hiding”
   * 对这些 intents，要求 `program_id`、endpoint class、batch geometry 必须恒定
   * mixer/padding/cover 的最小参数
2. **PPC verifier**：

   * 静态检查：配置/路由表是否满足“同形状”
   * 动态 smoke：跑一组固定 workload，验证单服务器 transcript 的可区分性低于阈值（可以是轻量 MI/分类器 sanity）
3. **Claim gating**：

   * PPC fail → 自动降级为“no-SAP / partial SAP”模式，并且 audit 里记录“privacy contract violated”。

### 为什么这会把你和 AAB/Faramesh 拉开？

Faramesh 强调“canonical action + deterministic policy + provenance logging”，并未把“策略服务的可观测泄露”形式化成一个**可执行、可验收、可降级的契约**（至少从论文摘要与定位看，它的重点不在 policy-plane query privacy）。
你把 PPC 做出来，本质上贡献是：

> “不是提出一个隐私机制，而是提出 **让隐私主张在真实部署中不被误配破坏** 的系统方法学。”

这个在系统顶会非常加分：**从理论/机制走到可操作的 claim management**。

### 怎么评估

* 做一个“误配置实验”：关掉 padding/cover 或让 program_id 分裂 → verifier 报 FAIL，系统降级，报告可区分性上升。
* 加一个“回归测试”：每次新增 intent 时 PPC 自动检查，防止工程演进破坏 SAP。

---

## 3) 把“unkeyed request hash 的字典猜测风险”变成一个“可落地的改进点”，并转化为新贡献

你们的论文限制部分已经写了：**unkeyed request-hash 可导致对低熵字段的 offline guessing**，因此需要“足够 min-entropy 或 residual-risk accounting”。

### 痛点

这在 reviewer 眼里属于“理论上可攻击的缺口”，尤其当 hashed 字段包含 email/域名/常见 recipient 这类低熵字段。

### 建议（小改但价值大）

把 `request_sha256` 从“裸 hash”升级为**抗字典猜测的 commitment**，例如：

* `request_commit = HMAC(K_req, Canon(rho))`（K_req 只在 gateway+executor，policy server 不需要知道）
* policy server 仍然可以对“必要字段”做 PIR/MPC，但 transcript 里不再暴露可离线猜测的裸 hash

这能把“限制”翻转成“新贡献”：

> 我们不仅指出风险，还给出**与系统协议兼容**的修复，并证明它不破坏 NBE 的绑定语义（只是把绑定从 SHA256 换成 keyed commitment）。

### 与 AAB/Faramesh 的差距

Faramesh 的主线里 canonical action hash 用于 provenance / replay。
你做 keyed commitment 之后可以强调：

* “我们不仅要可重放/可审计，还要**审计标识本身不成为隐私泄露载体**。”
  这就把故事从“执行治理”带到“隐私友好的治理”，差距更大。

---

## 4) 新增“Privacy-preserving Provenance（隐私友好的可审计性）”：解决“审计必须记录，但审计本身会泄露”的悖论

### 痛点

企业要审计、要 provenance log，但 log 往往会把敏感字段完整写进去（recipient、URL、payload、token）。这与“control-plane privacy paradox”是一条线的延伸。

你们目前已经在系统模型里把 C6（logs/audit）作为 channel，并且 synthetic suite 会测试 audit/log leakage。

### 建议新增模块：P-Provenance（隐私友好的审计表示）

核心 idea：**审计记录默认只记录“可验证但不泄密”的表示**，例如：

* 记录：action type、policy decision、commit evidence 的验证状态、keyed commitments、patch id、reason_code
* 不记录：明文 recipient / 明文 payload
* 如需复盘，走“受控解密/受控重放”流程（可要求多方批准/双人授权/不同角色）

这会形成一条很清晰的“非增量贡献”：

* AAB/Faramesh 强调 provenance logging keyed by canonical action hashes。
* 你强调 **provenance logging 也必须隐私最小化**，否则 control-plane 成为“隐私 sink”。

### 怎么评估

* 明确对比一个“enterprise DLP proxy baseline”（你们 E6 里也计划了这类 baseline），比较：

  1. policy-plane 日志里敏感值的可见性
  2. audit log 泄露率（C6）
  3. 仍然能否做 incident replay（功能性）


---

## 5) 把“未被 executor 覆盖的副作用（特别是 OS/UI side effects）”变成一个扩展模块：UI/OS Effect Wrapping

你们自己在 limitations 里已经写了：如果 agent 能触发“unmediated OS/UI effects outside executor path”，NBE 不适用，这要求把这些路径也 wrap 到 executor 才能继承保证。

### 痛点

这会被 reviewer 解读为：“你的保证只覆盖你能 hook 的工具 API；现实里 computer-use / RPA / UI 自动化会绕过。”

### 建议：加一个“UI Executor / Mediated UI Channel”

不是要你做完整浏览器自动化系统，而是做一个最小可行版本，让论文叙事完整：

* 把 UI 动作抽象成 intent（click/type/navigate）
* 所有 UI event 由 executor 发出（runtime 只能提出“计划”）
* Capsule 中 runtime 禁止直接生成 UI events（或禁止访问本地 automation API）

这会让你的系统“覆盖面”明显比 AAB 更接近真实 agent 产品形态（很多 agent 最终会走 computer-use）。
同时，你也能把“我们的边界不是只管 HTTP API，还能扩展到 UI side effects”作为强贡献。

---

## 6) 让“Secret Handles”从“只是不返回明文”升级为“可组合的密态数据流原语”（这会极大拉开差距）

### 痛点

目前 handle 很容易被 reviewer 认为是“capability token 的工程实现”。要把它抬到顶会贡献，需要让它具备更强的**可组合性**：

* 现实任务里，agent 不一定需要“拿到明文”，它往往只需要：

  * 比较（是否等于某个 ID）
  * 解析（提取邮箱域名）
  * 统计（计数/聚合）
  * 格式化（生成不含敏感字段的摘要）

### 建议：Handle-first “sealed computation”

给 handle 加一个**小而强的算子集合**，每个算子都在 boundary 内执行，并返回：

* 非敏感结果（plain）
* 或新 handle（派生 handle）

例如（举例，不必全做）：

* `ExtractDomain(handle_email) -> "example.com"`
* `MatchRegex(handle_text, pattern) -> bool`（pattern 受限）
* `Redact(handle_text) -> handle_text_redacted`（供 sanitize patch）
* `Join(handle_a, handle_b) -> handle_joined`（用于构造 safe summaries）

**重点是**：让 agent 在不见明文的前提下仍能完成很多工作，从而大幅降低 benign leakage，同时提升 utility。

### 为什么这会比 AAB 更“非增量”

AAB 解决的是“是否允许做这件事”，但不解决“为了完成任务，模型是否必须接触敏感数据”。
你把 handle 做成密态数据流原语后，就能说：

> 我们不仅把执行权从 runtime 收回，还把**数据权**（明文接触权）也系统性收回，并提供可用的替代计算接口。

这会在 novelty 上明显拉开。

---

## 7) 写作与叙事层面的“非增量化”建议（不改系统，但能显著改变 reviewer 观感）

如果你不想让 reviewer 把你看成“又一个 AAB”，你的论文/汇报叙事必须把主线从“Preview→Commit”挪开一点：

### 建议的主线表达（更不容易被归类到 AAB）

1. **问题不是只有“缺少执行边界”**
   而是“缺少执行边界 + control-plane 会变成隐私 sink + runtime 默认会接触敏感明文导致 benign leakage”。
2. 你的核心回答应该是三件套（你们 paper 里其实已这么写了）：

   * NBE：不可绕过的 executor gate
   * SAP：外包策略检查的单审计方隐私（解决 control-plane privacy paradox）
   * SM/PEI/SCS/DAS：在 compromised runtime 下的机密性与多主体正确性
     你们在 related work 里也已经写了“对 Faramesh 的正交点是 control-plane privacy + compromised runtime confidentiality/binding”。

但如果你再加上我上面提的 SOB / PPC / privacy-preserving provenance / sealed computation，这条“正交性”会更硬、更像“另一条研究主线”，而不是“同主线的小扩展”。

---

## 我建议你优先做的 3 个（性价比最高、最能拉开差距）

1. **Safe Output Builder（解决 benign leakage）**
   这直接打你当前最大的短板。

2. **Policy Privacy Contract（把 SAP 从机制变成可验证部署契约）**
   这能显著增强“严谨性 + 工程可落地”，并且是 AAB 不会自然覆盖的方向。

3. **Keyed commitment 修复 unkeyed hash dictionary risk**
   把 limitation 翻成贡献，reviewer 会很吃这一套。

---

如果你愿意，我也可以按你现在的模块结构（NBE/SM/PEI/SCS/DAS/SAP）给出一个“最小改动路线图”：

* 每个模块加/改 1 个点，
* 形成 2–3 个新的“paper-level contributions”，
* 同时给出对应的实验表格该怎么设计、如何写成 reviewer 觉得“不是 incremental”的 story。
