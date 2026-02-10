我看完你这三个附件（README / ARTIFACT / EFFECTIVENESS）后，整体判断是：

* **你已经把 MIRAGE‑OG++ 从“概念 demo”推到了“可复现的研究原型（research prototype）”**：Level 1/2、2‑server DPF/FSS‑PIR、PREVIEW→COMMIT 的 2PC/MPC（GMW+Beaver）、executor 双授权、capsule（MVP）、skill ingress（MVP）、以及真实 agent runtime（OpenClaw + NanoClaw）接入都写清楚并可跑。
* 但如果目标是 **NeurIPS/AAAI/CCS/NDSS**，目前最大的短板不在“工程是否能跑”，而在：

  1. **论文级“核心科学问题”与形式化性质是否足够尖锐**
  2. **对 ClawHub 这种真实恶意 skill 供应链的覆盖是否“可量化、可对比、可复现”**
  3. **capsule/ingress 是否能把“杜绝恶意 skill”的承诺变成一个清晰的条件化安全定理（而不是口号）**
  4. **你引入的 FSS/MPC 是否“不可替代”（不是本地跑规则就能替代）**

下面我给你一个“更详细的下一步方案”，以**最少改动现有代码**为原则，把它包装成**顶会更爱看的学术系统/安全论文**。

---

## 0. 你现在的基线已经很好：顶会 reviewer 会认可的点

从 README 来看，你现在已经具备几条很强的系统论文卖点：

1. **不可绕过的执行线（Non‑bypassable enforcement line）**
   PREVIEW→COMMIT + executor 双授权：executor 只有在拿到两台 policy server 的 MAC commit proof 才执行副作用，缺一不可、fail‑closed；并且 sanitize patch 在 executor 内强制应用。

2. **隐私‑审计悖论的密码学解法**
   你用 2‑server PIR（DPF/FSS，O(log N) key）去查集中规则库（allowlist/DLP/IOC），单个 policy server 看不到具体 recipient/domain/token；同时把 policy DSL 编译成布尔电路用 2PC/MPC 评估。

3. **你已经补上“恶意 skill 能绕过 API”的关键缺口**
   你做了 capsule（MVP）来阻断“恶意 skill 不走 MCP、直接读宿主 secret/直连公网/执行命令”的绕过路径；并且把 skill install/enable 也做成 PREVIEW→COMMIT 的受控副作用（skill ingress MVP）。

4. **Artifact 结构清楚，复现路径完整**
   ARTIFACT.md 明确了无外部 key 的可复现实验，以及可选的真实 agent 验证路径。

> 这些已经足以支撑 CCS/NDSS 风格的“系统 + 原型 + 复现”论文骨架。下一步要做的是：让它从“工程很强”变成“学术贡献很清晰”。

---

## 1. 你现在离顶会还差的“关键补强点”（按优先级）

### P1：把“杜绝恶意 skill”的承诺写成**条件化的安全性质 + 可复现实验**

你现在的 docs 里已经解释了 capsule/ingress 的目的，但顶会 reviewer 会追问：

* **你到底杜绝了什么？**（exfil？host exec？二阶段加载？凭证窃取？）
* **在什么假设下成立？**（capsule 是否跨平台、是否能保证“act 是唯一出口”）
* **如果 capsule 只是 MVP（macOS sandbox-exec），你怎么论证它不是纸糊的？**

> 需要：把你的目标写成 2–3 个清晰性质（例如 NBE/SM/SAP/SCS），并让 artifact 里每个性质都有对应 testcase + report 字段。

### P1：对 ClawHub/恶意 SKILL.md 的覆盖要“量化、可对比”

你现在对“ClawHub-style malicious skills”已有叙述与 ingress feature（IOC、install marker、base64/obfuscation boolean、DescribeSkill 的 redaction）。
但顶会会要求你提供至少一种：

* **真实数据集（哪怕是小规模）**：恶意/良性 skills 的 SKILL.md/manifest 样本
* **可比较指标**：阻断率、误报率、对正常安装体验的影响（confirm 次数等）
* **baseline 对比**：仅沙箱、仅静态规则、本地 DLP、仅 LLM guardrail 等

否则会被认为“工程很好，但更像安全产品而不是论文”。

### P2：capsule 需要从“单平台 smoke test”升级到“可迁移的最小可信边界”

你现在的 capsule 是 MVP（macOS sandbox-exec profile + MCP->HTTP proxy）。
顶会 reviewer 很可能要求：

* Linux 下最小实现（namespaces/seccomp/bwrap 任一）
* 或者把 capsule 明确写成“实现无关的接口层”，并证明“只要满足 mediation 接口，系统性质成立”（更学术）

### P2：你需要一个更“硬核”的泄露分析（prove or measure）

你已经做了 padding/shaping/bundle/intent shadowing 来减少单个 policy server 对 intent class 的泄露。
但顶会会希望你至少给出其中一种：

* **形式化 leakage function**（你允许泄露哪些：长度、固定批次数、输出位等）
* 或者**实证泄露评估**（classifier attack：policy server transcript 能否区分 intent/recipient 类别）

这会显著增强你“FSS/MPC 必要性”的说服力。

---

## 2. 下一步方案（更详细、可落地）：把 MIRAGE‑OG++ 变成“顶会论文级”MIRAGE‑OG+++

我建议你把下一步工作拆成 6 个“工作包”（WP），每个都能产出论文里的一节 + 一组 artifact 实验。

---

### WP‑A：把系统贡献学术化：给出 4 条核心性质 + 对应测试

**目标**：让论文能写成“我们证明/论证了 X”，而不是“我们实现了 Y”。

你可以把性质定义为（名字可换）：

1. **NBE（Non‑Bypassable Effects）**：任何真实副作用（SendMessage/PostWebhook/CommitSkillInstall…）必须携带来自 (P_0,P_1) 的两份有效 commit proof，否则 executor 必拒绝。
2. **SM（Secret Myopia）**：对不可信 agent/skill，敏感明文不可得（只返回 sealed handle；declassify 必须 explicit + confirm）。
3. **SAP（Single‑Auditor Privacy）**：任意单个 policy server 观测到的 transcript 在计算上不泄露被查询的 recipient/domain/token/IOC（在你定义的 leakage 边界内）。
4. **SCS（Skill‑Confined Safety）**：在 capsule mediation 假设成立时，恶意 skill 无法绕过 `act` 直接读 host secrets/直连公网/执行二阶段 payload。

**你要做的最小改动**（建议）：

* 在 `artifact_out/report.json` 里为每条性质加一组固定字段：`nbe_*`, `sm_*`, `sap_*`, `scs_*`
* 每条性质至少 2 个 test：一个正例（允许）+ 一个负例（拒绝/失败 closed）
* 把这些 test 写成 deterministic 脚本（你现在已经有 `python main.py artifact` 的框架，非常合适）。

**为什么这一步“顶会价值很大”**：
系统安全顶会最喜欢“性质—机制—实验闭环”。你已经有机制，下一步要把性质写出来并配上实验。

---

### WP‑B：强化“杜绝恶意 skill”的关键：**Skill Workload Identity + 最小特权能力投影**

你现在的 capability projection 是按 `caller` 在 `gateway/capabilities.yaml` 配置。
但从“杜绝恶意 skill”的角度，最关键的升级是：

> **每个 skill 必须有独立身份（workload identity），不能共享同一个 caller。**

否则一个恶意 skill 仍可能借用“全局 caller”能力去调用不该调用的 intent。

**最小可行方案（不需要 TEE）**：

1. `ImportSkill` 后生成 `skill_digest`（你已经有 staging + handle），将其作为 **skill identity**
2. capsule 运行某个 skill 时，向 gateway 请求一个 **短期 capability token**：`cap = MAC_K(skill_digest || session || ttl)`
3. 所有 `act` 调用都带上 `cap`，gateway 验证 cap 后把 `caller` 绑定为该 skill identity
4. `capabilities.yaml` 支持按 `skill_digest` 细粒度授权（比如 twitter trends skill 只能 `FetchResource` 到允许域名、不能 `ReadFile`）

**这一步的论文表达**：
把“skill 生态”从“插件能任意跑”变成“每个 skill 都是受限 workload”，这非常贴合 supply-chain 防御语境，而且能显著增强你对 ClawHub 类攻击的阻断叙事。

---

### WP‑C：把 capsule 从 “MVP smoke test”升级为“跨平台最小实现 + 明确的 mediation contract”

你现在 capsule 在 artifact 里做了 smoke test：host secret read / direct exec / direct internet 都失败，`act` 走 HTTP/MCP proxy 成功。
下一步顶会更稳的做法是：

**C1. 明确 capsule contract（写进论文）**

* capsule 必须满足：

  * (A) 无 direct network（或仅 loopback/UDS 到 gateway）
  * (A) 无 direct host secret filesystem
  * (A) 无任意 exec（或严格 allowlist）
* 论文里把这些写成“Capsule Mediation Assumption”，然后 SCS 的性质在此假设下成立（这就是学术化）。

**C2. 补一个 Linux 版本（最小实现就够）**

* 用 `bubblewrap(bwrap)` + `unshare -n` + `seccomp`（任选组合）做：

  * `--unshare-net` 禁网
  * bind mount 只给 workspace
  * seccomp deny `execve` / `ptrace` / `mount` …（最小集合即可）
* Artifact 里可以只跑 Linux CI（GitHub Actions）来证明跨平台，而 macOS 仍保留 sandbox-exec。

**C3. 把“gateway transport”做成 UDS 模式（更强）**
你现在用 HTTP `POST /act` + bearer token（可选）。
为了减少 capsule egress 面，下一步建议加：

* `gateway/uds_server.py`：监听 Unix Domain Socket
* `capsule/mcp_proxy.py` 直连 UDS
* capsule 网络直接 `--network=none`

这会显著提升“杜绝恶意 skill”的可信度。

---

### WP‑D：把 Skill Ingress 做成“对 ClawHub 攻击链的针对性防御”，并做数据集/评测

你已经实现了 ingress MVP：ImportSkill（staging）→ DescribeSkill（redact）→ CheckSkillInstallPolicy（PIR+MPC）→ CommitSkillInstall（executor 双 proof）。
下一步要让它“论文级”，必须补上两个东西：

**D1. 攻击链覆盖面：把你截图里的关键模式变成 feature + policy**
你可以把 ClawHub 恶意链路抽象为 3 类 ingress 信号（你截图里也强调了“二阶段加载/高复用基础设施/裸 IP 落点”）：

* **Infrastructure reuse**：domain/IP/URL/path 的 IOC membership（你已经能用 PIR 查）
* **Doc‑to‑exec markers**：`curl|bash`、base64 decode、pipe 到 shell、分段拼接（你现在有 install marker DB + base64/obfuscation boolean）
* **Two‑stage loader semantics**：第一阶段脚本拉第二阶段 payload（可用 URL 模式 + “download‑execute”组合规则近似）

建议把这三类写成 `policy_programs.skill_ingress_v1` 的“可解释输出”：

* `REQUIRE_CONFIRM`（提示用户这就是风险点）
* `IOC_BLOCKED`（强拒绝）

**D2. 给 NeurIPS/AAAI 或 CCS/NDSS 都很关键：做一个 SkillDocBench（小数据集也行）**
最小路线：

* 收集 N=200~500 个 skills 的 SKILL.md（良性/恶性各半，或恶性 20%）
* 恶性标签来源可以是：公开 IOC、你截图中列的样本、以及你自己构造的 staged loader 样例
* 输出：

  * detection（阻断/confirm/allow）
  * FP/FN
  * 用户交互成本（confirm 次数）
  * 被阻断的攻击链阶段（install 阶段阻断 vs runtime 阶段阻断）

对 NeurIPS/AAAI：你可以把它包装成 **“agentic supply-chain benchmark + system defense”**；
对 CCS/NDSS：它是现实性证据（realistic workload）。

---

### WP‑E：让 FSS/MPC “更不可替代”：补一节“为什么不能本地跑规则” + 做泄露评估

你现在已经有 intent shadowing、policy bundle、padding/shaping。
顶会更强的包装方式是：

**E1. 明确“隐私–审计悖论”场景**

* 组织希望集中维护 IOC/规则库（快速响应新攻击），但不希望把用户/企业数据上送审计中心。
* 你用 2‑server PIR + 2PC/MPC，让**规则库可外包**同时单点看不到查询内容。

**E2. 做一个“transcript classifier attack”当作泄露评估**
做法很简单，但论文效果很强：

* 给单个 policy server 的 transcript（长度、请求数、访问 DB 的结构、时间）训练分类器
* 任务：区分 intent class（egress vs ingress）、区分 recipient 类别等
* 对比三种设置（ablation）：

  1. 无 shaping（最容易泄露）
  2. 你现在的 shaping/bundle（应显著降低）
  3. 进一步加 cover traffic（可选）

这一步会把你的“隐私”从“理论正确”变成“实证很强”。

---

### WP‑F：性能与可扩展性：把“能跑”变成“能跑到足够规模”

你现在的性能部分已经很好：有 DPF key size microbench、以及 e2e throughput，并且提供 Rust policy backend 来降低 O(N) 常数。
顶会下一步要补的是“规模曲线 + 真实参数”：

1. **画三条 scaling 曲线（不用很大）**

* 横轴：`FSS_DOMAIN_SIZE`（4K → 64K → 1M）
* 横轴：token batch size（4‑gram 32 → 128）
* 横轴：policy circuit size（egress_v1 vs skill_ingress_v1）
  纵轴：端到端 latency、吞吐、CPU 消耗

2. **把 policy server 的 O(N) 计算与 DPF key size 分开报告**
   让读者看到：

* 在线通信低（O(log N) key）
* 计算瓶颈在哪里（O(N) inner product）
* Rust backend 能将常数降到什么程度

这会让你在 CCS/NDSS 的系统评审中更稳。

---

## 3. 论文包装建议：分别对齐 NeurIPS/AAAI vs CCS/NDSS 的“口味”

### 如果你要冲 CCS/NDSS（我认为最匹配）

主线标题可以是：

> **Non‑Bypassable, Privacy‑Preserving Policy Enforcement for Agentic Tool Use and Skill Supply Chains**

贡献点（写在 introduction 最后一段）：

1. 新威胁模型：doc‑driven skill supply chain（SKILL.md 变成执行载体）
2. MIRAGE‑OG+++：capsule + skill ingress + dual‑auth executor 的 reference monitor
3. 用 2‑server PIR (DPF/FSS) + MPC 解决隐私–审计悖论
4. 真实 agent runtime 集成 + artifact 可复现

### 如果你要投 NeurIPS/AAAI（可以，但需要强调“benchmark/agent safety”）

你需要把“学术贡献”更多落到：

* **SkillDocBench（数据集/评测框架）**：系统化刻画 doc‑driven skill poisoning
* 以及“模型/静态规则/系统隔离”的对比
* 你的 MIRAGE‑OG+++ 作为一种“系统型防御基线”，而不是单纯工程

这条路的关键是 **有数据、有对比、有指标**。

---

## 4. 最小“下一步交付清单”（你照着做就能更像顶会）

我按“最小但足够顶会”列一个你可以直接执行的 checklist：

### (1) 写作与形式化

* [x] 在 `EFFECTIVENESS.md` 增加一节：正式定义 NBE/SM/SAP/SCS（1–2 页）并把每条性质映射到哪个测试用例/哪个代码路径
* [x] 在 README 里把“capsule mediation assumption”写成显式假设

### (2) capsule

* [x] 加 UDS 传输模式（让 capsule 网络彻底关闭）
* [x] Linux 最小 capsule（bwrap + netns）+ CI 跑 smoke test
* [x] 增加一个“恶意 skill 直接 requests.post 外联”的 testcase（证明被 capsule 阻断）

### (3) skill ingress

* [x] 加 **per‑skill identity（skill_digest 作为 caller）** + capabilities（每个 skill 最小权限）
* [x] `DescribeSkill` 输出里加 “风险解释模板”（不泄露具体规则，但解释风险类别：下载执行/混淆/IOC 命中）
* [x] 做一个最小 SkillDocBench（哪怕 100 个样本）并把结果写进 `artifact_out/report.json`

### (4) FSS/MPC 不可替代性

* [x] 做 transcript classifier leakage 评估（无 shaping vs shaping）
* [x] 做一个“本地规则 vs 外包规则”的对比：

  * 本地规则 = policy DB 在 gateway 明文
  * 外包规则 = 你现在的 2‑server PIR/MPC
    结论要强调：**外包规则时仍能保持单点隐私**（这是你的 crypto 必要性）

### (5) Baselines（至少 3 个）

* [x] 只 capsule（无 PIR/MPC/dual auth）
* [x] 只 gateway allowlist（无 capsule）
* [x] LLM guardrail / keyword scanner（不做 non‑bypassable enforcement）
  在同一组攻击链上比较 attack success rate + task success rate

---

如果你愿意，我可以在你现有三个文档的基础上，给你输出一个**“camera‑ready 论文大纲（10–12 页）+ 每节该放哪些实验/图/表 + 贡献点表述模板”**，让你写起来更像 CCS/NDSS/NeurIPS 的成稿。
