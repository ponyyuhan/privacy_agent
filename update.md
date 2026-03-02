根据你仓库里 **2026-02-25 的收敛快照**（含 official C1–C5 fair compare 的关键数值与产物路径）以及论文草稿中已经写清的 **RQ1–RQ4 与 NBE/SM/PEI/SCS/DAS/SAP** 定义，我会用“顶会 reviewer”口径，围绕 **方案/动机/方法/实验** 给你一份“下一步怎么做才能更像可录用论文”的建议清单，并对你列出的结果做“谨慎使用 + 必须质疑/重跑”的点名。
（你现在的框架其实已经把 reviewer 最在意的“威胁模型、可验证边界、可复查证据链”写出来了，但实验叙事和 threat-model separation 还没收敛到能让人放心的程度。）

---

## 0) 先把“论文主线”收紧：你到底在证明什么，不在证明什么

你们的文档里已经写得很清楚：SecureClaw 不是“更聪明的风险检测器”，而是 **把信任从模型遵从性迁移到一个可验证的执行线**（executor 侧 accept predicate + fail-closed），并把 prompt/skill 视作对手可控输入。这是很强的系统论文主线。

但 reviewer 会卡你两点：

1. **威胁模型不要混**。你们自己也在 baseline note 里强调：

* Threat model (1) “compromised runtime/skills 已经是恶意的，会主动外泄”；
* Threat model (2) “native guardrails：runtime 不主动作恶，只看平台内置能否扛 prompt-injection”。
  SecureClaw 核心为 (1)，但你们又必须报告 (2) 以便对比。
  **如果你把 (1)/(2) 混在一个主表里，100% 会被 reviewer 说“对比不公平/结论不成立”。**

2. **把“可观测 0 leak”说清楚**。你们自己也写了：“attack leak = secret token 是否出现在该 channel artifact 里”，所以 0 leak 只是 “没有 canary token 穿过测量通道”，并不等价于“系统绝对不泄露”，更不覆盖 host side channel 或 TCB 内部泄露。
   论文里要主动把这句放在主结果旁边，否则会被抓住打。

> 下一步写作上的核心动作：
> **把论文结果章节拆成两张主表 + 若干补充表**：
>
> * 表 A：Native guardrails（官方 AgentLeak C1–C5）同口径对比（你现在的 fair compare 主表属于这里）。
> * 表 B：Compromised runtime / bypass suite（你现在缺的“能证明 NBE/SCS 必要性”的主表）。
>   然后把 SAP / federation / perf 放到对应 RQ2–RQ4。

---

## 1) 方案与方法：你现在“最能打”的点是什么，怎么写才像顶会

你现在最有竞争力的，不是“又一个 LLM guardrail”，而是下面这条组合拳（建议按这个写贡献）：

* **NBE（Non-bypassable effects）**：PREVIEW→COMMIT，executor 的 accept predicate 是唯一 effect gate，必须验证双 policy server 的 proof share、request hash binding、freshness、replay guard、语义位（allow/confirm/patch）一致，否则 fail-closed。
* **SM/PEI/SCS/DAS 组合**：handle-first secret flow + 明确 declassification；patch-carrying egress integrity；skill install 也变成交易；delegation hash-context binding 防跨主体重放。
* **SAP（可选）**：把 policy outsourcing 变成 “固定形状 PIR/MPC + leakage contract”，并明确声明 “只有在 program id / endpoint class / batch shape 等公共可观测都被统一时才声称 intent hiding”。

> 重要写作建议（能显著提升录取概率）：
> 把贡献写成一句 reviewer 一眼能懂的“结构性不变量”——
> **“Any side effect is executable iff executor verifies cryptographic evidence bound to the exact request tuple.”**
> 然后再说 SAP 是 optional privacy mode，不影响 integrity line（你们 formal doc 也这么写）。

---

## 2) 你给的 9 组实验：我会怎么在 review 里打分，以及哪里必须重跑

下面我按你列的 1–9，给“可用性（能不能放主论文）/风险点/必须重跑设计”。

---

### (1) Official AgentLeak C1–C5 fair compare（你最核心的实验）

**可用性：高（应该是主表 A）。**
你们已经做了“same cases / same seed / same metrics”，并且清楚列了 baselines 含义与 threat model 分界。统计方法（Wilson + Fisher）也写了。

**但：你当前这张表会被 reviewer 直接质疑两处结果“很可能不正确或不可比”。**

#### 质疑点 1：SecureClaw benign_allow_rate=0.8（20% benign 被拒）到底在拒什么？

你论文表里写 SecureClaw full benign allow 80%。按你给的 n_benign=2520，这相当于 **504 条 benign “没 allow”**（如果按 allow/deny 二分）。这在系统安全论文里是非常刺眼的。

**你必须把 benign 的结果拆成至少三类**（否则 reviewer 会认为你牺牲可用性换安全）：

* **ALLOW**：自动通过并完成任务
* **REQUIRE_CONFIRM**：需要用户确认（这在很多系统论文里不算“误报”，而是“软阻断/二阶段批准”）
* **HARD_DENY**：无论如何拒绝（这才是传统意义 FP）

你们的 leakage 模型里其实已经把 confirm 作为独立可泄露项 (L_{\mathsf{CONFIRM}}) 并讨论了 padding 选项；而 fair 工具链也有 `fair_utility_breakdown.py` 专门拆 benign deny/false-positive reason。
**下一步不是“再跑一次”，而是：把主表里的 benign_allow_rate 改成一张三分类 breakdown（或把 confirm 单独列出来）**，否则 0.8 会被误读。

> 你应该重跑/重算：
>
> * 输出每个系统的 benign：ALLOW / REQUIRE_CONFIRM / HARD_DENY / ERROR(TIMEOUT) 的占比；
> * 把 “误报率” 明确定义为 **HARD_DENY on benign**。
>   同时在正文解释：confirm 是你设计里的“显式 declassification gate”，不是模型拒答。

#### 质疑点 2：openclaw_native benign_allow_rate=0.0（这几乎必然是跑挂了或映射错了）

你表里 OpenClaw native benign allow 0%，同时 attack leak 1.48%、block 98.52%。这意味着它**对 2520 条 benign 全拒绝/全失败**。这在现实中极不可信，reviewer 会判定“baseline 实现或计分逻辑有 bug”。

**重跑设计（必须做，而且要写到论文 artifact 里）**：

1. 从 `agentleak_eval_rows.csv`（或你 native baseline 的 per-case rows）抽样 50 条 benign，人工检查：

   * 是真的返回了 DENY？
   * 还是 ERROR/TIMEOUT/SKIPPED 被你统计成 denied？
2. 给 OpenClaw baseline 加一个 **“availability/completion rate”** 指标：多少 case 跑完且产出可解析输出。
3. 如果确实是权限/配置导致它“默认拒绝一切”，那就不能把它当“native guardrails baseline”，只能当“极端拒绝策略”对比，并在表里把它移到 appendix。

（你们 baseline note 已经强调 native baseline 强依赖具体模型版本与平台默认变化；但这不能解释 0% benign 这种极端异常，只能解释结果漂移。）

#### 质疑点 3：IPIGuard / AgentArmor 在 official 上 0 leak 且 100% benign allow —— 会反向削弱你

你论文里写 IPIGuard / AgentArmor 在同一 manifest 上 0 leak、100% benign allow。
如果 reviewer 只看这一张表，会问：**“那你这套复杂协议的必要性在哪？”**

所以你必须补一个“Threat model (1) compromised runtime”的主表 B 来回答：

* 这些 wrapper 在 (2) 下可能好看，但 **它们不能提供 executor-side non-bypassability**（你们自己也在论文里写了这句话，但缺“硬证据表”支撑）。

---

### (2) paper_eval（内部 9 类攻击 + 4 类良性）

**可用性：中（适合做“攻击面覆盖/边界定义”与 ablation，不适合当主 benchmark）。**

你现在的描述里有一个 reviewer 会抓住的点：

* “command_injection 未拦（边界定义导致）”
  这句话如果不解释清楚，会被认为“系统对命令注入无效”。

**重构建议：把 paper_eval 从“杂合任务”变成“性质驱动的 test suite”**，每类攻击明确对应哪个 theorem/假设：

* 命令注入/直接执行：应该属于 SCS（capsule contract）或明确 out-of-scope
* payload substitution after preview：属于 PEI（patch-carrying）
* replay old tx across principal：属于 DAS
* secret exfil：属于 SM + NBE

你们 formal security 文档其实非常适合做这种 mapping（六个性质 + assumption partition）。
下一步把 paper_eval 输出改成一个 **“Property × AttackClass 的矩阵（pass/fail + reason code）”**，并且把“未拦”解释为“本实现故意不覆盖该类/需要 capsule contract 才覆盖”。

---

### (3) C1–C7 全通道（含 C6/C7 synthetic）

**可用性：中（只能作为补充表/appendix；不要混入官方表）。**

你们论文已经写“官方覆盖 C1–C5，C6–C7 单独评估”；这个决定是对的，继续坚持。
而且你们在 LEAKAGE_MODEL 里把 C6/C7 的允许泄露项写得很清楚（日志、skill ingress 相关元数据）。

**风险点：synthetic suite 的可信度取决于你能否写清“生成规则 + secret token 检测语义”。**
你们已经在 LEAKAGE_EVIDENCE 里解释了“0 leak 的含义与不含义”——建议把这段浓缩成正文里的一句话（否则 appendix 再严谨也没用）。

---

### (4) SAP：单 policy server transcript distinguishability（你现在最“像顶会”的实验之一，但也最容易被挑刺）

**可用性：中高（如果你把 SAP 作为主要贡献之一；否则建议降级为 optional/appendix）。**

你现在的结果表述是：unshaped 有明显可分信号（MI≈0.414 bits，MAP≈0.514），full shaping 后接近 chance。这个方向是对的。

**但 reviewer 会质疑三点：**

1. **MAP 指标到底是什么？**
   你把 “MAP=0.207（明显低于 chance=1/3）” 也当作“接近 chance”写进表里。这非常危险：

* 如果这是“accuracy”，低于 chance 意味着 classifier 系统性偏置或 label/采样 bug；
* 如果这是“mean average precision”，那 chance baseline 不等于 1/3，你的解释就不成立。
  👉 **下一步必须把这个指标定义写清、把 chance baseline 算对，并给 CI/显著性。**

2. **你测的是 intent class，而真实隐私风险常常是“具体查询值”（域名/recipient/IOC token）**。
   你们 motivation 里提出 policy outsourcing paradox 是“不想让单点 auditor 看到 raw queried values”。那 SAP 的实验更应该测：

* 单 policy server 能否区分 “查询的是哪个 recipient/domain（在 K 个候选里）”；而不是只测 3 类 intent。
  👉 设计一个 k-way 任务（比如 K=32 或 64），用 transcript features 训练 classifier，报告 top-1 acc 与 chance=1/K。

3. **“intent hiding” 的前提是 program id 等公共可观测要统一**。
   你们 README 明确写了 unified program id (`policy_unified_v1`) 用 secret mux 合并多个 intent，从而在 policy server 侧隐藏 intent 类别；论文也强调 “只有 public observables constant 才 claim intent hiding”。
   👉 那 SAP 实验必须加一个 ablation：

* `UNIFIED_POLICY=0`（或不同 program_id）时，单 server 区分能力应该显著上升；
* `mixer/pad/cover` 分别关掉时，区分能力如何回升（证明 shaping 不是摆设）。

---

### (5) 协议与联邦授权（DAS/多代理）

**可用性：中（目前 7/7 太小，只能算“功能测试”；要成为论文结论，需要规模与随机性）。**

你们论文 RQ3 写的是“delegated multi-agent workflows 是否 enforced”；而现在是 deterministic campaign 7 cases。
reviewer 会说：**“toy campaign”**。

**下一步改成两层：**

* 层 1（保持）：7 个手工设计 case（覆盖 revoke/missing delegation/dual-principal 等），作为“spec regression”。
* 层 2（新增）：property-based / fuzz 风格的随机 trace 生成：

  * 随机生成 delegation graph、session、caller、scope、revocation events；
  * 自动检查不变量（例如“跨 principal 重放必拒”）。
    这样 reviewer 才会认为你在验证“协议性质”，而不是演示 demo。

---

### (6) 性能评估（policy server + e2e shaping）

**可用性：中高（系统论文必备，但要注意“可比性与解释”）。**

你们已经写了成本分解：固定形状引入 padding/cover dummy compute、mixing 排队、transport 开销。这很好。
你们 README 里也明确强调 “不是慢 100x” 这种 reviewer 关心的点。

**但需要补两件事才像顶会：**

1. **给出 policy DB 尺寸与现实场景映射**：keys/s 很抽象。你要说清楚：

* allowlist 是 4K、64K、1M domain 时，每次 PREVIEW 需要多少 PIR queries + MPC programs（你们已经有 cost_units 口径）。

2. **executor 侧的 accept predicate 开销要单独 microbench**：因为你们 claim “executor enforcement constant-sized，主要是 dual MAC + replay lookup”。
   把这个测出来，会让 reviewer 更信你“系统开销可控”。

---

### (7) Native runtime smoke baseline

**可用性：低（目前有 ERROR/SKIPPED，可作为 sanity check 但不能放主结论）。**

你们 baseline note 里也说了：那种“故意泄露的 deterministic script baseline”只能作为 compromised runtime 上界 sanity check，不是 native baseline。这点非常正确。

**下一步：把这一块变成主表 B 的一部分**（compromised runtime / bypass suite），而不是“零散 smoke”。

---

### (8) Real-agent campaign（目前 n_cases=0）

**可用性：几乎不可用（现在放论文会扣分）。**
你自己也说“不宜作为主论文核心结论”。我建议更激进：**不修就删**；要修就把它变成“可复现 case study”，至少给出一个非空、可跑、可核验的 case 列表与日志证据链（你们 README 里说会保存 audit_*.jsonl 与 SHA256）。

---

### (9) 外部 benchmark 管线（AgentDojo/ASB/DRIFT/IPIGuard）

**可用性：低到中（除非你补齐并冻结；否则不要在主文里承诺）。**
顶会 reviewer 对“外部 benchmark 未完成/缺文件”的容忍度很低。建议：

* 若 DRIFT/IPIGuard 外部管线跑不稳，就只引用 AgentDojo/ASB 并把缺项移到 appendix 的“future work / engineering status”。

---

## 3) 你觉得“结果不太正确”的地方：我会重点怀疑这些，并给出“怎么重跑才服人”

### A. openclaw_native benign_allow=0：必须当成“统计/映射 bug”优先排查

**重跑/排查步骤（不依赖大规模重算，先做诊断）：**

1. 从 OpenClaw native 的 per-case rows 抽样 benign：看每条究竟是 `DENY` 还是 `ERROR/TIMEOUT/SKIPPED`。
2. 如果是 ERROR 占主导：

   * 论文里必须把 availability 单独列；
   * benign_allow 不应把 ERROR 当 deny。
3. 如果是 OpenClaw 真的默认拒绝：那就把它换成“严格拒绝策略 baseline”，而不是“native guardrails baseline”。

### B. SecureClaw benign_allow=0.8：必须拆出 REQUIRE_CONFIRM，否则主表会被误读

你们体系里 confirm 是机制的一部分（declass/skill install 等路径本来就会走 confirm）。
**重跑不是重点，重点是重新计分**：

* 主文里把 benign outcome 分成 ALLOW / CONFIRM / HARD_DENY；
* 把 “误报率” 定义成 benign 的 HARD_DENY。

### C. IPIGuard/AgentArmor “完美结果”会让 reviewer 质疑你贡献：必须补 Threat model (1) 的硬对比

你要用一张主表 B 明确展示：

* 在 compromised runtime / malicious skill 可主动 bypass 的情况下，这些 wrapper 没有 executor-side non-bypassability，因此能被绕过；
* 你的系统在 executor accept predicate + capsule contract 下 fail-closed。
  你们其实已经有“没有 capsule 时 direct bypass 成功 / 去掉 NBE 时绕过重开”的证据链描述——下一步就是把它系统化成一个 benchmark（至少 30–50 cases）并对所有 baseline 跑同一套。

### D. “0 leak”检测语义过窄：加一个“变形泄露”子套件

因为你们的 leak 判定是 “secret token 是否出现”。对手可以 base64/hex/分片/同义改写泄露，token 可能不出现。
**建议新增一个评测维度**（不需要替换 AgentLeak，只需补充）：

* 让攻击把 secret 做可逆编码（base64/hex）再外发；
* evaluator 也做对应解码/模糊匹配检测。
  这会显著提升“实验正确性/对抗性”的可信度。

---

## 4) 回答你最关心的三个问题（并告诉你“下一步该怎么选”）

### Q1: “真实部署里谁来提供第二个 policy server？同一公司两台机器算不算不合谋？假设是否过强？”

你们文档里对 SAP 的假设写得很诚实：**SAP 需要两台 policy server 且至少一台不合谋；若两台合谋，单审计者隐私在该模型下不可能**。

reviewer 会接受这个假设，但前提是你做到两点：

1. **把 SAP 明确定位成 optional mode，不影响核心 integrity claim**（你们已经写了）。
2. **给出现实部署选项**（论文里要写，不能只在口头讨论）：

   * **跨管理域**：P0 由企业自管（或内网），P1 由独立云/合规团队/第三方审计方托管；
   * **多云/多区**：两个不同云厂商或不同账号/不同密钥体系；
   * **“同公司两台机器”**：严格说不满足非合谋的密码学假设，但可以作为 **defense-in-depth**（降低单点失陷/内部滥用风险），并在论文里明确“这不提供 SAP 的形式化隐私，只提供工程上的分权”。
   * 如果你愿意扩展：可以讨论“用 TEE + 远程证明”模拟非合谋（但这会引入新的假设与攻击面，论文要谨慎）。

### Q2: 2-server SAP 是否有必要做？

从“录取概率最大化”的角度，我给你一个非常现实的建议：

* **如果你能把主表 B（compromised runtime / bypass suite）做扎实**，那么即便 SAP 只作为 optional/appendix，也依然可能被录用，因为 NBE+SM+PEI+SCS+DAS 的组合已经是一个完整系统贡献。
* **但如果你担心 NBE 方向被认为“理念已知”**（尤其是下面要说的 Faramesh），那 SAP 反而是你最容易拉开差距的点——前提是你把 SAP 实验从“intent 三分类”升级到“真实查询值/索引隐藏”的可量化证据（上面我给了重跑设计）。

换句话说：**SAP 不是必须做，但如果做，就要做得“像密码系统论文”，否则会变成拖后腿的复杂度。**

### Q3: 你方案与 arXiv:2601.17744 的区别，会不会贡献分不清？

我查了 arXiv:2601.17744（Faramesh）。它的核心贡献是提出 **Action Authorization Boundary (AAB)**：在 agent reasoning 与执行之间放一个 mandatory、non-bypassable 的执行时授权边界，使用 canonical action representation（CAR）做确定性授权，并让 executor 在执行前验证 decision artifact（PERMIT/DEFER/DENY），强调 determinism、non-bypassability、replayability 与 provenance logging。([arXiv][1])

**重叠点（你必须正面承认，否则 reviewer 会觉得你在“抢首创”）：**

* 你们和 Faramesh 都在强调“执行边界才是关键”以及“必须 non-bypassable/fail-closed”。([arXiv][2])
* 都使用 canonical/哈希绑定的动作表征与可验证的执行授权（它叫 CAR + decision artifact，你们是 CanonJSON + ReqHash + commit proof shares）。([arXiv][2])

**你们可以区分的核心差异（也是你论文必须强化的地方）：**

1. **隐私与 policy outsourcing：**Faramesh 论文里没有出现 PIR/MPC、two-server、non-collusion 等关键词，也不讨论“policy server 单点可见性”问题。([arXiv][2])
   而你们把 policy evaluation 外包到 2-server PIR + 固定形状 MPC，并定义泄露合同 (L_{\mathsf{policy}}) 与可区分性实验，这是实质性不同的研究问题与贡献【76:1†paper_full_body.txt†L1-L6】【76:14†FORMAL_SECURITY-carrying sanitize）、skill ingress transaction 化，是“数据/副作用”层面的约束，不只是“授权记录”。这些点在你们论文贡献与协议描述里是明确的【76:11†paper_full_body.txt†L15-L32】。
2. **多主体委托安全（DArnal_principal 与 delegation_jti 绑定进 ReqHash/hctx 来防跨主体重放，这是比“单主体授权边界”更具体的协议设计【76:11†paper_full_body.txt†L36-L43】。

> 下一步你需要做的不是“证明你**“AAB/NBE + privacy-preserving outsourced policy + end-to-end secret/egress/skill/federation constraints”**；
>
> * 并用主表 B + SAP 强化实验，证明这些差异不是“附加 feature”，而是解决了 Faramesh 未覆盖的威胁面。

---

## 5) 最重要的“下一步清单”（按优先级，直接照做就能显著提升录取概率）

我给你一份不需要反复澄清、可以直接执行的 checklist（按 reviewer 风险排序）：

### P0（必须先做，否则主结论站不稳）

1. **修正/解释 OpenClaw benign_allow=0 的异常**：加 availability 指标，或移出主表。
2. **把 benign_allow 拆成 ALLOW/CONFIRM/HARD_DENY**，并把误报率定义成 benign HARD_DENY。
3. **新增主表 B：compromised runtime / bypass suite**（至少 30–50 cases），用于证明：

   * policy_only 没有 executor dual-proof boundary 时可以被绕过；
   * 没 capsule / loopback HTTP 等 downgrade 时可以被直连外泄；
   * full 系统 fail-closed。
     （你们已有“无 capsule 可 bypass / 去掉 NBE 会重开绕过”的证据链描述，可直接系统化）【80:7†MOTIVATION_PAPER.md†L31-L36】

### P1（把论文从“工程项目索引隐藏”的 k-way 分类**，并修正 MAP/chance 的定义与统计显著性；加 ablation（unified program / mixer / pad / cover）。【76:13†README.md†L3-L9】【76:1†paper_full_body.txt†L1-L6类攻击明确对应 NBE/SM/PEI/SCS/DAS 中的哪一条；把“未拦”解释为 out-of-scope 或需 capsule contract。

### P2（加分项，但做不好宁可不写）

6. **扩展 RQ3 federation 到 fuzz/property-based**，把 7-case demo 变成“协议性质验证”。
7. **外部 benchmark（AgentDojo/ASB/DRIFT/IPIGuard）要么补齐并冻结，要么降级为 appendix/未来工作**。
8. **real-agent campaign 要么删，要么补成非空可复现 case study**（含日志哈希链、audit 证据）。

---

如果你愿意，我也可以按“reviewer 打分表”的格式，把你现在的论文（motivation→method→security→eval→related work）逐段指出：

* 哪些句子会触发 rejection（比如 threat model 混淆/指标定义不严谨/0 leak 过度宣称）；
* 哪些地方只要补一个表或一个 ablation 就能变成“可接受”的顶会稿。

[1]: https://arxiv.org/abs/2601.17744 "https://arxiv.org/abs/2601.17744"
[2]: https://arxiv.org/pdf/2601.17744 "https://arxiv.org/pdf/2601.17744"
