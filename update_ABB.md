下面我会用“顶会 reviewer 视角”来给**可落地、能显著增量的创新点**，目标是两件事：
(1) 让 SecureClaw 对 **agent 安全/隐私的真实痛点**贡献更大；
(2) 让它与 **AAB/Faramesh** 的差异更大，避免被认为“在 AAB 上加一点隐私组件”的增量工作。

---

## 0) 先把“你现在已经很强的部分”说清楚（否则 reviewer 容易误判为 AAB 增量）

从你现有材料看，SecureClaw 已经不是“只有执行边界”：

* 你已经有 **Preview→Commit + executor fail-closed** 的“不可绕过副作用边界”，并且 commit 需要双 policy server 的 proof share，executor 侧用 accept predicate 严格验证。
* 你把“策略层可能成为隐私汇聚点”明确提出为 **control-plane privacy paradox**，并且定义了 SAP（single-auditor privacy）的泄露契约与可模拟性目标。
* 你已经强调 **runtime 拿不到明文 secret，只拿 handle**（sealed handles / secret sealing）。
* 你还把 **capsule mediation contract** 做成可验证系统假设 + claim gating / downgrade semantics（这在系统安全论文里很加分）。
* 你明确写了：和 Faramesh 的差异是两条“正交维度”：(i) control-plane privacy（SAP），(ii) compromised runtime 下的 confidentiality + delegation-aware binding。

但是——**reviewer 仍然可能会说你是 AAB 的增量**，原因是 Faramesh/AAB 的最新版本（2026-01 arXiv）也非常清晰地提出了：AAB + Canonical Action Representation (CAR) + decision artifact（PERMIT/DEFER/DENY）+ audit/provenance/replay【turn0search1†】【turn1view0†】【turn2view4†】。
所以你想“拉开差距”，最好不要停留在“我们也有 gate + 我们多了 PIR/MPC”。你需要让贡献看起来像**另一类问题被解决了**：**“执行治理必须同时做到隐私最小暴露 & 运行时明文隔离，否则治理层本身就是新泄露面”**。

下面给你一组“改模块/加内容”的建议，我按**性价比（短期能做出来）→ 论文贡献增量**排序，并且每条都写清楚：痛点、怎么改、为什么会拉开与 AAB 的差距、怎么评估。

---

## 1) 高性价比、reviewer 很难挑刺：把 `request_sha256` 改成“Keyed Request Commitment”，解决你自己文档承认的低熵离线猜测泄露

### 痛点（真实且你已在 limitation 里承认）

你现在的 binding 用的是 **unkeyed `request_sha256 = SHA256(CanonJSON(rho))`**。
你自己材料明确写了：**unkeyed request hash 可导致 policy side 观察后做离线猜测（dictionary attack）**，尤其对低熵字段（recipient/domain/短 token）。
这对“我们强调 policy-plane privacy”的叙事是一个明显薄弱点：reviewer 会抓住说“SAP 只保护了 PIR/MPC 的查询值，但你把可猜的 hash 暴露了”。

### 怎么改（模块改动非常局部）

把 `request_sha256` 替换为：

* `request_commit = HMAC(K_GX, CanonJSON(rho))`
  其中 `K_GX` 只在 **gateway + executor**（TCB）共享。policy server 只看到 `request_commit`，无法离线猜测 preimage。executor 仍可重算验证，保持 NBE 绑定逻辑不变。

这几乎不需要改你的大架构：proof share 的 `meta_s` 里把 `request_sha256` 字段替换成 `request_commit` 即可。

### 为什么能显著拉开与 AAB/Faramesh 的差异

Faramesh 的核心是 AAB + CAR + decision record（审计可重放），其 canonical action digest/decision record 是一个“治理核心对象”【turn1view0†】【turn2view4†】。如果这一类系统把 action digest/record 暴露给外包/第三方 policy 或日志系统，就天然存在 “digest 可被猜测/链接” 的风险。
你做 keyed commitment 相当于把“**治理绑定对象**”变成**不可被单点观察方做字典攻击的承诺**——这非常符合你“control-plane privacy paradox”的主题，也不是 AAB 文章的重点贡献方向【turn0search1†】。

### 怎么评估（能写进 paper 的实证点）

在你现有 SAP distinguishability sweep 之外（你已有 MI/分类器）再加一个非常直观的实验：

* 给 policy server 一组 transcript + (unkeyed hash) vs transcript + (keyed commitment)，让它做“低熵 recipient/domain 的字典猜测”攻击；报告成功率。
  这会让你的 SAP 更“硬”，并且把 limitation 直接消掉，reviewer 会觉得你很稳。

---

## 2) 贡献升级、并且明显不是 AAB 增量：加一个“Privacy-Preserving Provenance & Replay”模块（隐私版的 Faramesh audit/replay）

### 痛点（真实企业需求）

AAB/Faramesh 很强调 **decision-centric audit log + provenance + replay**【turn2view4†】。现实企业也确实需要：事后调查、合规审计、政策更新后的回溯重评估。
但你这边的主张是：**policy/控制面不能成为隐私 sink**。
那么 reviewer 可能会问：

> “你把 policy outsourcing 做成 SAP 很好，但审计/回放怎么办？审计日志本身会不会变成新的隐私 sink？”

你已经把 logs/audit 作为泄露通道 C6 来测了；但这还不够“顶会贡献”，你需要给一个系统化的“审计也隐私最小化”的设计。

### 怎么加（新模块，和你现有 handle + SAP 完全匹配）

我建议把审计设计升级成一个明确的机制：

**Private Decision Record (PDR)**：

* 记录内容只包含：

  * `action_id, program_id, decision (allow/deny/confirm/sanitize), timestamp, request_commit`（最好是上面 keyed commitment）
  * 对敏感字段只记录 **sealed handle IDs / commitments**，不记录明文 canonical action。
* 对“可回放/可重评估”的需求：回放时由 gateway 使用 sealed handles 拉取所需字段，并在 SAP 模式下做 PIR/MPC policy replay。
* 给外部审计方的“可验证性”：提供**hash-chained、tamper-evident**的 PDR 链（你现在已有 claim gating / spec 验证基础设施，很适合承接）。

这会把你的论文从“我们有 gate + privacy policy”提升为：
**“我们给出了一个可外包、可审计、可回溯的 agent 执行治理，但任何单点观察者都无法获得敏感明文。”**

### 为什么这能让你不再像 AAB 增量

Faramesh 的 replay/provenance 是围绕 CAR/decision record 建的【turn2view4†】；而你这里提出的是 **“provenance/replay 也必须满足 single-auditor privacy + secret sealing”**。
这不是在 AAB 上贴补丁，而是把 AAB 的“治理优势”（audit/replay）带进了“隐私约束下的世界”。对 reviewer 来说这是**新的问题域**：

> 不是“能不能 gate”，而是“在审计与外包存在时，如何保证治理层不泄露”。

### 怎么评估（非常像顶会系统/安全论文的证据）

你已经规划了 E6：企业 DLP proxy vs SAP 路由，测单审计方可区分性和日志明文可见性。
把它升级成**“审计/回放 baseline”**会更强：

* Baseline A：Faramesh-style centralized decision log（记录 canonical action 或可还原字段）
* Baseline B：SecureClaw-PDR（只记录 commitments + handle IDs）
  对比：
* 单点审计方能否从日志恢复 recipient/domain/token（visibility）
* 回放能力：是否还能在不暴露明文的情况下做 policy re-eval（功能性）
  这会非常有说服力。

---

## 3) 解决“真实泄露痛点”，并明显拉开差距：把 sealed handles 从“vault references”升级成“Data-Flow Objects”，引入最小化 declassification（减少 CONFIRM/DENY 的必要性，提高可用性）

### 痛点

现在 sealed handle 的价值是：runtime 拿不到明文，很多泄露通道直接消失。
但在真实任务中，经常需要“**部分信息**”来完成工作（比如：展示 email 的 domain、显示账号后四位、判断是否同一客户等）。如果你只能 deny/confirm，utility 会被打得很惨；而如果你直接 reveal 明文，又会破功。

### 怎么改（属于“现有模块的自然升级”）

把 handle 设计从“仅存储 secret value”升级为：

* handle 带 **label + lineage**（来自哪个源、敏感度、用途限制）
* gateway/executor 支持 **一组安全的 handle-to-handle 变换**（全部在可信边界内执行）：

  * `mask(handle, policy)` → 返回一个“已脱敏的新 handle”
  * `predicate(handle, ...)` → 返回布尔/小域结果（比如 domain allowlist membership），最好可走 SAP
  * `format(handle, template)` → 只生成允许结构的输出（防止拼接泄露）
* 这些变换被 policy 决策控制，并且可被审计记录为“对 handle 做了什么”，而不是记录明文。

### 为什么能拉开与 AAB/Faramesh

AAB/Faramesh 的核心对象是 action（CAR）和 decision；它不处理“敏感数据在 runtime 中如何被最小化使用”这一类 data-flow 问题【turn0search1†】。
你把 handle 升级成 data-flow object，本质上是在做一个 **“agent 系统中的信息流最小泄露接口”**，这会让你的论文更像安全/隐私顶会会喜欢的那类“系统层新抽象”，而不是“又一个 execution gate”。

### 怎么评估

两类指标都容易做，而且非常 reviewer-friendly：

1. utility：减少 confirm/deny 的比例（更多 sanitize/partial reveal），看 benign allow 或 task success 变好。
2. leak：仍按你现在的多通道 leakage harness 看 attack leak rate 是否保持 0。

---

## 4) 直接补上你 limitation 里的“最大真实缺口”：把 UI/OS side effects 也纳入 executor boundary（让 Threat Model B 覆盖 computer-use agents）

你论文里已经明确写了：如果 agent 能触发“未被 executor mediation 的 OS/UI effects”，NBE 不适用，需要 wrap 进 mediated executor。
这其实是现实里非常大的痛点（computer use / browser automation / RPA）——也是 reviewer 会追问的点：

> “你解决的是 tool-call 边界，但未来 agent 大量通过 UI 操作，你怎么办？”

### 怎么加（高风险但高回报的扩展模块）

做一个 **UI Mediated Executor**：

* agent runtime 不直接驱动 UI（鼠标键盘/浏览器）；
* 所有 UI 操作也必须变成“previewable action”并走 commit；
* executor 侧在隔离环境里执行 UI 操作（例如 remote browser / VNC controlled by executor），并把截图/DOM diff 作为 preview 证据返回。

这个模块一旦做出来，你的论文 scope 直接从“tool agents”扩展到“computer-use agents”，顶会 reviewer 会觉得“这不只是 AAB 增量”。

### 怎么评估

你们已经规划了 E5：VPI-Bench mediated subset，且指出 scope gap。
把 UI mediation 做出来后，E5 就从“我们解释缺口”变成“我们把缺口补上”。这在投稿时非常加分。

---

## 5) 让“SAP 的非合谋假设”更能被接受：给一个 single-box deployment 路线（TEE / split-trust / committee）

你现在 SAP 依赖 policy servers 非合谋。这在学术上没问题，但 reviewer 会问：

> “现实部署里怎么保证不合谋？成本如何？有没有单机替代？”

### 你可以做的“可选模式”

不必推翻 SAP，而是加一个“可选部署模式”：

* **TEE-backed policy enclave**：把“两个 server”替换成“一个 server + TEE attestation”，让单点运维也能拿到类似 single-auditor privacy 的性质。
* 或者更务实：n-of-m committee（3 台里至少 1 台 honest），降低“必须 2 台不合谋”的心理门槛。

这会让 reviewer 觉得你考虑了 deployment reality，且不是 AAB 会写的方向。

---

## 6) 别让 AAB 的 CAR 优势变成你被攻击的点：强调你“高层 intent allowlist”的设计哲学，并补一个“接口适配层”

Faramesh 的一个亮点是 CAR：解决语义等价但字符串不同的 action canonicalization 问题【turn1view0†】。
你这边其实走的是另一条路：**intent 是固定 allowlist，不开放 RunCommand(cmd)/Fetch(url) 这类低层原语**——这天然降低了“语义别名”空间，也更容易做 policy 证明/审计。

### 但要避免 reviewer 说你“限制太死、不通用”

建议你加一个内容/模块（不一定要重工程）：

* **Adapter layer**：把常见工具（Email/Slack/DB/Payments）的原生 API schema/OpenAPI 通过模板化映射到你的高层 intents；
* 你在论文里强调：我们不是“减少能力”，而是“把能力变成可治理的、可 canonicalize 的高层 effect”。

这能把“CAR vs allowlist”从弱点变成亮点：

* Faramesh：用 CAR 抵抗别名（通用但复杂）；
* SecureClaw：通过接口约束把治理空间压缩（更安全、policy 更简单），并提供 adapter 保证可用性。

---

## 7) 给你一个“最像顶会贡献”的组合建议（我会优先选这套）

如果你希望**在不大改系统**的情况下，让论文贡献明显上一个台阶，并且和 AAB/Faramesh 拉开距离，我建议你优先做这三个（从易到难）：

1. **Keyed Request Commitment**（修掉离线猜测泄露）
2. **Privacy-Preserving Provenance & Replay (PDR)**（把 Faramesh 的 audit/replay 优势收编到“隐私约束”下）【turn2view4†】
3. **Handle → Data-Flow Objects**（最小化 declassification，提高 utility，减少 confirm/deny）

做完这三件事，你的工作会更像：

> “privacy-preserving execution governance for compromised-agent systems”
> 而不是：
> “AAB + PIR/MPC + secret handles 的拼装”。

---

如果你愿意，我可以基于你论文/原型的现有模块划分（NBE/SM/PEI/SCS/DAS/SAP），把上述建议直接改写成“可投顶会”的 **Contributions 段落 + Related Work positioning 段落**（用 reviewer 最能接受的措辞），同时给一个“新增实验表格/图”的最小集合，让你在不扩大太多工作量的前提下，显著降低“增量工作”风险。
