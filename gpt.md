根据你提供的 **2026-02-24《实验蓝图》**、`paper_full_body.txt`、`FORMAL_SECURITY.md`、`LEAKAGE_MODEL.md`、`LEAKAGE_EVIDENCE.md` 等材料，我下面以“顶会 reviewer（偏安全/系统方向）”的口径，从**新颖性/正确性/严谨性/实验客观性/基线与benchmark**几个维度做一次“可被直接用于 rebuttal/修改计划”的评审式建议。

---

## 1) 我理解的论文核心主张（以 reviewer 视角复述）

你们把问题定义为：**agent 系统中最关键风险是执行边界失守（effects commit 可被绕过）与多通道泄漏**，且“只靠 prompt/guardrails”属于 advisory，无法抵抗**被攻击者控制的 runtime/skills**。你们的系统模型明确把**runtime 视为对手**，并允许其直接向 executor 发送任意请求尝试绕过。系统由 5 个角色组成：不可信 runtime、可信 gateway、两台 policy server、唯一可产生副作用的 executor、以及作为显式解密/解密许可来源的用户确认。你们当前主张是五个主性质 + 一个可选隐私性质：**NBE、SM、PEI、SCS、DAS（+ optional SAP）**。

你们的三条机制线（我认为是论文“可发表贡献”的抓手）是：

1. **不可绕过执行线（dual authorization execution line）**：policy server 发 commit proof share（MAC），executor 端以 **双证明 + freshness + request binding + anti-replay + policy bits** 的 accept predicate 失败关闭。

2. **泄漏感知的 constant-shape 编译**：把 policy 查询编译成固定形状（统一 program id、固定 PIR key 数、pad+cover+mixer），从而把“单个 policy server 的可见 transcript”限制在显式泄漏函数中（可模拟）。

3. **oblivious routing / bundling**：把逻辑 DB 名称/意图等信息用 bundle + index shift + unified routing 隐藏，让 policy server 观察到单一 db_name 和固定 endpoint 形态。

这些内容整体是“系统+安全协议+隐私外包”的组合型工作，而不是纯 prompt/guardrail。

---

## 2) 是否有类似解决方案？你们的“新颖性”在哪里？

结论先说：**有相邻/部分重叠的工作**，但你们仍然可能在“组合点 + 威胁模型 + 可验证协议 + policy 外包隐私”上站得住。关键在于**不要把新颖性押在一个已经被别人占据的点**，而是把“差异化”写得更硬、更可验证。

### 2.1 最接近你们 NBE 叙事的工作：AAB（Action Authorization Boundary）

2026 年 1 月 arXiv 的 Faramesh 等人提出 **Action Authorization Boundary (AAB)**，核心就是在 agent pipeline 里建立 **non-bypassable authorization boundary**，并强调 canonical action 表达、授权语义与 provenance logging，用于“防止 agent-driven actions 被绕过授权”。这在“**不可绕过边界**”叙事上和你们非常贴近。([arXiv][1])

**你们必须做的定位：**

* 把 NBE 的 novelty 说清楚：你们不只是“概念边界/工程 hook”，而是一个 **双 policy server 的 cryptographic commit line（双 MAC share + executor accept predicate）**，并且和 **SAP（单审计方隐私，可选）**、SM、PEI、SCS、DAS **组合成可证明的主命题**。【217:8†paper_full_body.txt†L54e authorization boundary”这个概念在 2026 已经不是空白。**你们的新颖性更像是“把它做成协议事实 + 加上 policy 外包隐私 + 处理多通道泄漏模型”。

如果你们投稿的是 2026 的安全/系统顶会，这一块 reviewer 很可能会抓住问：**“你们和 AAB 的本质区别是什么？”**
建议在 related work 里直接开小节对齐 AAB，把差异写成 checklist（例如：双证明/单方隐私/固定形状编译/skill supply chain ingress/C6 audit leakage 的显式 L_sys/L_policy 定义）。

### 2.2 与“运行时防护/注入防御”类工作关系（你们不该和它们硬拼同一条线）

你们材料里把 DRIFT / IPIGuard / AgentArmor 当作 defense baselines（wrapper）对照是合理的，因为它们更多解决**注入/轨迹/依赖图**层面的防护，而不是“runtime 完全 adversarial 时仍不可绕过”。例如：

* DRIFT（NeurIPS 2025）是动态推理/防护框架，重点是运行期防御 prompt injection。([arXiv][2])
* IPIGuard（EMNLP 2025）面向 indirect prompt injection 的防护。([arXiv][3])
* AgentArmor（arXiv 2025）强调 agent 的权限/安全治理等。([arXiv][4])

你们自己的正文也承认：这些是 **runtime wrapper**，不是 non-bypassable effect-boundary protocol。【217:1†paper_full_body.txt†L13-L18】

**这里 reviewer 会问的致命问题是：**

> 如果这些 wrapper 在你的主 benchmark 上也能做到 0 泄漏 100% benign allow，那你的系统“到底赢在哪？”

而你们主张的答案是：赢在 **“对抗被攻破 runtime/skill 的不可绕过执行线nity check 的分离）。【221:6†paper_full_body.txt†L1-L6】

所以论文叙事一定要把“我们不是更会 prompt，我们是把 effect commit 变成协议事实”放在第一位（你们蓝图第 13 节一句话结论就很好）。【217:7†EXTERNAL_EVAL_EXECUTION_PLAN_2026-02-24.md†L81-L83】

### 2.3 pol白，但在 agent-policy 场景仍可能新颖

在“PIR + access control”方向确实已有系统性工作，例如 MIT thesis “Pri不提供访问控制，并研究如何在 PIR 上叠加 access control。([dspace.mit.edu][5])
另外两服务器 PIR、DPF、结果验证等也有一系列工作与综述。([arXiv][6])

**你们的机会点**在于：把这些密码学组件放进 agent 的 policy enforcement line，提出 **“single-auditor privacy：任一 policy server 的 view 可被 L_policy 模拟”**，并通过 fixed-shape 编译把“endpoint/intent/db selection”的 side-channel 明确纳入可控泄漏函数。【217:8†paper_full_body.txt†L60-L69】【217:3†LEAKAGE_MODEL.md†L39-L48】

换句话说：你们可以把 novelty 锚在“**把 agent-policy 外包隐私做成系统工程 + 明确的 leakage contract + 可复现的 distinguishability sweep**”，而不是锚在“我们用了 PIR”。

---

## 3) 你们当前最强的地方（Strengths）

### S1. 威胁模型“敢把 runtime 当对手”且协议边界清晰

系统模型里ail 论文里是不敢写的。你们将可信边界收敛到 gateway+executor，并明确 non-goals（policy server 全合谋、TCB 被攻破、OS sandbox escape、kernel side-channel 不在范围）。【217:8†paper_full_body.txt†L31-L48】【217:2†paper_full_body.txt†L30-L35】

### S2. accept predicate 写得足够“可验证”，还有可执行检查

executor 的 accept predicate 条件（双证明、freshness、request binding、anti-replay、policy bits）写得像“协议 RFC”，并且你们提供 unit tests 和 end-to-end harness 去验证“实现等于证明里假设的 prex_security.txt†L33-L52】

### S3. 评估方法学意识强：same-cases、neutral prompt、CI + Fisher、reason code 分解

你们的 fairness protocol 写得很像顶会 artifact guide：固定 manifest + same seed + row-level 指标 + Wilson CI + Fisher exact test + 失败归因/拆解。--

## 4) 我认为最可能导致“顶会拒稿”的 Major Concerns（你需要优先修）

### C1. 核心卖点是“不可绕过执行线”，但主 benchmark（AgentLeak C1..C5）未必真正打到“绕过”场景

AgentLeak 是 2026 的 full-stack leakage benchmark，覆盖多通道泄漏。([arXiv][7])
但你们自ils”与“compromised runtime（故意泄漏）”。【221:6†paper_full_body.txt†L1-L6】【221:1†LEAKAGE_EVIDENCE.md†L12-L28】

**reviewer 会追问：**

* 你的 main table 里 `policy_only`（去掉 executor 强制边界）为什么不显著更差？如果它也 0 泄漏，那 NBE 的实证价值在哪？（你们蓝图说它是检验 NBE 贡献的 ablation）【221:8†EXTERNAL_EVAL_EXECUTION_PLAN_2026-02-24.md†L9-L15】

> 建议：把“绕过执行线”的攻击设成主实验的一部分，而不是只放在 sanity cypass suite”**：让 runtime **直接调用 executor**、重放旧 evidence、修改 request hash、伪造 proof、跨 session/caller 复用等（你们 harness 本来就测了这些）并报告“绕过成功率全游戏脚本已经覆盖 replay/session mismatch/missing share/MAC mutation/hash mutation/expiry 等，论文需要把这些汇总成“真实攻击成功率表”。【217:5†appendix_security.txt†L46-L52】

2. 把 defense baselines（DRIFT/IPIGuard/AgentArmor）也在“compromised runtime”条件下跑一次（哪怕是小规模），直观展示：**prompt/wrapper 不能阻止一个故意 exfiltrate 的 runtime**。这能把你们与相关工作“拉开维度”。

如果不做这一步，你们会面临一种典型拒稿理由：

> “系统很复杂，但在标准 benchmark 上看起来只是另一个 guardrail；核心 claim（non-bypassability）缺少能打动人w 只有 ~80%，解释不够会被认为“不可用”
> 你们主表（官方 C1–C5，neutral prompt）：

* SecureClaw full：attack leak 0%，attack block 100%，**benign allow 80%**。【221:5†paper_full_body.txt†L23-L37】

这在安全顶会是危险信号：reviewer 会觉得“安全是靠强拒绝堆出来的”。

你们确实在限制章节承认 false positives 的主要来源（allowlist miss、DLP hit、leakage budget exhaustion），并说会给 reason code breakdown。【217:2†paper_full_body.txt†L36-L41】

**建议把“80%”拆开讲清楚，否则会被误读：**

1. **把 benign 的 outcome 分成 3 类/4 类**：`ALLOW`、`A:contentReference[oaicite:32]{index=32}`DENY`。

   * 如果大量 benign 被标成 require_confirm，但 benchmark 没有用户确认步骤导致被算作 deny，那么“真实可用性”可能被低估。你们的系统模型里用户确认是显式 declassification 能力，完全可以把它作为单独指标报告。【217:8†pareason code 分布**（你们 plan 里也强调要分离 quota/parse failure vs 安全拒绝）。【221:10†EXTERNAL_EVAL_EXECUTION_PLAN_2026-02-24.md†L43-L49】【221:5†paper_full_body.txt†L45-L49】
2. 给出每个 vertical/task 的 allow 分布，证明不是某个子集完全不可用。

---

### C3. “性能对比”可能存在口径争议：你需要明确是否包含 LLM 推理时间

主5s、60s/81s 量级，而 SecureClaw 是 18/37ms。【221:5†paper_full_body.txt†L30-L33evel check？”

* “这是不是 apples-to-oranges？”

你们蓝图其实已经意识到要单独报告 model_call_count/model_latency 等透明指标。**强烈建议把它落实到主文里**：

* 把延迟拆成：`LLM inference`、`gateway+policy+executor enfor:contentReference[oaicite:37]{index=37}ency`。
* 在同一个 runtime（比如都用 Codex）下比较“加上 SecureClaw 的增量开销”。这样 reviewer 没得挑口径。

---

### C4. SAP（single-auditor privacy）目前更像“声明 + 机制描述”，需要更硬的实证/攻击展示

你们的 leakage contract 很清楚：允许 coarse timing buckets、confirm branch bit、request hash 可见（及低熵字典攻击风险）等。【217:3†LEAKAGE_MODEL.md†L25-L33】
并且你们设计了“single-policy-server distinguishability sweep”（MI + classifier）。【221:0†LEAKAGE_EVIDENCE.md†L9-L43】

**但你们现在给 reviewer 的关键是：把这组 sweep 的结果（数字）写进正文主结果或核心图表。**
否则 reviewer 会说：“SAP 是理论上的，未展示单服务器到底能不能从 transcript 推断 intent/DB selection。”

建议你们至少做：

* **shapings chance；MI 值对比；并把残余可区分信号归因到你们承认的 residual terms（confirm-branch bit、timing bundling、only mixer、only fixed-key-count，说明“哪一步贡献最大”。

---

## 5) Baseline / Benchmark 选择：总体方向对，但要处理好“可比性”与“威胁模型不一致”

### 5.1 优点：你们的 baseline 体系设计是正确的

你们明确了四个内部结构基线（full / policy_only / sandbox_only / single_server_policy）+ 两个 native runtime baseline（codex/openclaw）+ 三个 defense wrapper baseline（drift/ipiguard/agentarmor）。【221:8†EXTERNAL_EVAL_EXECUTION_PLAN_2026-02-24.md†L9-L29】【221:14†EXTERNAL_EVAL_EXECUTION_PLAN_2026-02-24.md†L3-L13】

这套结构是“顶会喜欢的”：能解释机制价值、能解释隐私-性能权衡、能解释与现实平台 baseline 的差异。

### 5.2 需要补强：把“威胁模型差异”放进主文对照表里

你们已经写了“wrapper 不是等价替代”，但 reviewer 需要一眼看懂：

* wrapper 的威胁模型：runtime 不主动作恶、不会绕过中间件
* SecureClaw 的:14†EXTERNAL_EVAL_EXECUTION_PLAN_2026-02-24.md†L1-L13】

### 5.3 Benchmark：AgentLeak 作为主轴很对，但外部 injection benchmark 需要“冻结且汇总”

你们的 plan 里主张：

* AgentLeak 官方 C1..C5 为主表；
* C6/C7 用合成 suite 补齐；
* AgentDojo/ASB/DRIFT/IPIGuard/WASP/VPI 作为鲁棒性补证，且必须分母独立，不混算。【221:12†EXTERNAL_EVAL_EXECUTION_PLAN_2026-02-2hmark 进度快照（2026-02-20），其中 AgentDojo 已完成、ASB 仍在跑等。【217:4†README.md†L14-L24】
  建议你们在投稿前务必做到：
* 外部 benchmark **给出冻结 run_tag/commit/seed/manifest**（你们 Phase 0/5 也强调了）。【217:7†EXTERNAL_EVAL_EXECUTION_external_benchmark_unified_summary.py` 也计划了）。【217:7†EXTERNAL_EVAL_EXECUTION_PLAN_2026-02-24.md/严谨性：我会在 rebuttal 里追问的点，以及你们如何提前堵住

### Q1. “双 policy server 非合谋”假设如何落地？是否现实？

你们明确假设：至少一台xt†L33-L36】
reviewer 可能会质疑现实性：两个 server 往往都在同一云上。

建议做两件事：

1. 在 deployment dvs “operator”）

   * 或者用 HSM/TEE 做 key 隔离（即使同云也降低合谋风险）
2. 明确“若不满足假设，系统降级成什么？”（比如仍有 NBE+SM，但无 SAP）你们在 FORMAL_SECURITY 里其实已经写了“SAP does not hRMAL_SECURITY.md†L60-L66】

### Q2. request_sha256 的低熵字典攻击：这会被安全 reviewer 盯上

你们自己很诚实地写了 residual risk：unkeyed request hash 对低熵字段可被离线猜测，优势上界 `min(1,q_d/2^k)`。【217:0†appendix_leakage.txt†L47-L53】【217:3†LEAKAGE_MODEL.md†L29-L33】

**建议你们主动给一个工程 mitigation**（否则 reviewer 会说“你承认了一个实际可利用的信息泄漏”）：
-salt（由 gateway 生成、包含在请求中但不单独暴露明文内容），让 policy server 看到的 hash 对字典攻击不可用；同时保持 executor 可重算绑定。

* 或者用 keyed hash（但要小心：key 放哪儿、policy sm DFA”，用 dummy 形式掩盖？
  你们承认 confirm 分支可能泄漏一个 bit。【217:0†appendix_leakage.txt†L46-L48】
  建议：
* 在高隐私配置下，强制所有请求都走同形态 confirm DFA（即使不需要），用 dummy 输出填充，从而把 branch bit 从 residual risk 变成“被消除”。然后在性能节给出该配置开销曲线（你们已经有 shaping 曲线体系）。【217:11†paper_full_body.txt†L11-L28】

---

## 7) 我会怎么改论文结构来“显著增大录取概率”

你们现在材料很丰富，但顶会 paper 最大风险是：**贡献太多、主线不够硬，reviewer 抓不到“非你不 **主问题**：在 agent 系统里，把 policy 从 advisory 变成 **protocol-fact** 的唯一方法，是让副作用提交依赖可验证 evidence（而非 prompt）。【217:7†EXTERNAL_EVAL_EXECUTION_PLANSecureClaw 用 dual authorization execution line（NBE）+ secret myopia（SM）+ capsule contract（SCS）保证“runtime 即使 adversarial 也拿不到明文、也绕不过 executor”。【217:9†paper_full_body.txt†L50-L65】

3. **独特附加价值**：在不把 policy server 变成新的隐私单点的前提下，用 2- privacy（SAP），并用 distinguishability sweep 实证验证。 【217:8†paper_full_body.txt†L60-L65】【221:0†LEAKAGE_EVIDENCE.md†L9-L43】

然后实验按“**三轨**”展开（你们已经这么规划了）：privacy 证 + protocol tests。【221:6†paper_full_body.txt†L34-L43】

---

## 8) 最优先的修改清单（按“最能提升录取概率”排序）

1. **把 compromised runtime bypass suite 做成主结果的一部分**，用它证明“wrapper T/IPIGuard/AgentArmor 拉开维度的关键）【221:6†paper_full_body.txt†L1-L6】

2. **把 benign allow 的 80% M / DENY），并给 reason-code 分布与 vertical 分布，证明不是“靠拒绝堆安全”。【217:2†paper_full_body.txt†L36-L41】

3. **性能口径澄清**：把 latency 拆成 enforcement overhead vs LLM/tool latency；同 runtime 条件下报告增量开销，避免 apples-to-oranges。并沿RNAL_EVAL_EXECUTION_PLAN_2026-02-24.md†L23-L29】

4. **SAP 的 MI/分类器 sweep 数字进正文**：展示 shaping OFF→ON 的可区分性坍塌到 chance，并归【221:0†LEAKAGE_EVIDENCE.md†L9-L43】

5. **Related work 正面对齐 AAB**：明确“non-bypassable boundary 并非你们首创”，你们的贡献是“协议化 + policy 外包隐私 + leakage([arXiv][1])

6. **给 request hash 低熵字典攻击一个 mitigation**（哪怕是可选配置），把 residual risk 变成“可消除的工程项”。【217:0†appendix_leakage.txt†L47-L53】

---

如果你愿gths / weaknesses / questions / requested changes / overall score）再输出一版更像真实 reviewer report 的文本，方便你直接用于 rebuttal 和 revision。

[1]: https://arxiv.org/pdf/2601.17744 "Faramesh: A Protocol-Agnostic Execution Control Plane for Autonomous Agent Systems"
[2]: https://arxiv.org/abs/2506.12104?utm_source=chatgpt.com "DRIFT: Dynamic Rule-Based Defense with Injection Isolation for Securing LLM Agents"
[3]: https://arxiv.org/abs/2508.15310?utm_source=chatgpt.com "IPIGuard: A Novel Tool Dependency Graph-Based Defense Against Indirect ..."
[4]: https://arxiv.org/abs/2508.01249?utm_source=chatgpt.com "AgentArmor: Enforcing Program Analysis on Agent Runtime Trace to Defend Against Prompt Injection"
[5]: https://dspace.mit.edu/handle/1721.1/151392?utm_source=chatgpt.com "Private Information Retrieval with Access Control"
[6]: https://arxiv.org/pdf/2301.11730?utm_source=chatgpt.com "Two-Server Private Information Retrieval with Optimized Download Rate ..."
[7]: https://arxiv.org/pdf/2602.11510 "AgentLeak: A Full-Stack Benchmark for Privacy Leakage in Multi-Agent LLM Systems"
