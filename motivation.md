MIRAGE-OG（Myopic Intent Routing + Access-Governed Execution with Oblivious Guardrails）方案在系统设计上已经非常成熟，具有很强的“系统安全”论文潜质。针对你担心的“动机生硬”和“FSS 结合强硬”的问题，以下是我的评估、改进建议，以及一套更顺畅的“顶会级别”叙述逻辑。

### 1. 方案评估：MIRAGE-OG 的优劣势

* **优势（Systems 角度）：**
* **架构解耦清晰：** 将“看到数据”（Level 1）与“控制行为”（Level 2）分开处理，符合最小特权原则。
* **TCB 最小化：** 把复杂的 Agent 逻辑踢出信任域，只信任极小的 Gateway，这是审稿人最喜欢的点。
* **工程可行性高：** 引入 MCP（Model Context Protocol）作为标准化接口，使得研究不只是理论，而是具备落地到 OpenClaw 生态的潜力。


* **劣势（Cryptography 角度）：**
* **FSS 的引入确实稍显孤立：** 如果 Guardrails 就在 Gateway 本地运行，使用 MPC/FSS 确实是“杀鸡用牛刀”。只有在**“本地隐私环境”与“云端/外部安全审计”**存在信任边界时，FSS 才具有不可替代的必要性。



### 2. 动机优化：如何让 FSS 的引入“丝滑”且“必须”？

要让 FSS 显得不生硬，你需要强调**“审计权”与“隐私权”的冲突**。

**新的 Motivation 逻辑：**

1. **Agent 的“影子 IT”危机：** 像 OpenClaw 这样拥有系统高权限（shell access）的智能体正在企业内网泛滥，带来了巨大的供应链风险（如 ClawHub 的恶意插件 ）。


2. **本地防火墙的局限性：** 单纯的本地沙箱无法识别复杂的、由 LLM 动态生成的恶意行为模式。企业需要接入**集中式的、由专家维护的外部安全规则库（Centralized Policy Service）**。
3. **隐私悖论（The Privacy-Audit Paradox）：** 企业想要集中审计 Agent 的行为以防外泄，但 Agent 正在处理的是用户最私密的本地数据（邮件、密钥、代码）。将这些数据发往外部审计中心会造成严重的隐私泄露。
4. **我们的方案：** MIRAGE-OG 引入 Oblivious Guardrails。通过 FSS，本地网关可以在**不向外部审计器泄露明文内容和具体意图**的前提下，利用其规则库完成强制性的合规检查 。



---

### 3. 更顺畅的隐私保护方案改进：从“工具保护”到“行为投影”

为了让方案在顶会更具竞争力，我建议将 MIRAGE-OG 的核心原语从简单的“加密”转向**“能力投影”（Capability Projection）**：

#### 核心思想：把 Agent 变成一个“盲目但受控”的接线员。

* **Level 1: Secretless Identity (取代单纯的 Handles)**
* 不再只是给随机 ID（Handle），而是基于 **Workload Identity Attestation**。当 Agent 需要访问 GitHub API 时，Gateway 动态生成一个仅限该次操作、且绑定到特定 Intent 的临时 Token。
* Agent 从未见过 API Key，它只是一台机器，通过“工作负载证明”在网关处换取执行权。


* **Level 2: Intent Shadowing (取代简单的 Routing)**
* 利用 FSS 的 **分布式点函数（DPF）** 实现“工具混淆”。
* 即使 Gateway 被部分控制，它也无法知道 Agent 正在调用的是“转账”技能还是“查询天气”技能。你可以把技能列表看作一个秘密分享的数组，Gateway 仅根据 DPF 生成的 Share 来路由调用 。




* Oblivious Guardrails: Match Quest 集成 


* 这是你论文的“硬核”部分。明确指出使用 **Match Quest** 协议进行密态正则匹配 。


* **性能论据：** 强调 FSS 模式匹配在 LAN 下延迟小于 2ms，这证明了 guardrails 对 Agent 的实时响应几乎没有影响，反驳“加密太慢”的质疑。



---

### 4. 论文系统设计章节的学术化锚点

你可以直接参考以下表述来增强论文的“硬度”：

* **威胁模型（Threat Model）：**
* 假设一个**恶意技能（Malicious Skill）**视图：它能看到 Agent 内存并构造任何请求 。


* 假设一个**诚实但好奇的审计员（Honest-but-curious Auditor）**：它提供最新的正则规则库，但不能窥探用户的具体数据。


* **设计原则：**
1. **Data De-identification（数据去标识化）：** 利用 Sealed Handles 确保敏感内容与推理流隔离。
2. **Intent Pre-flight Analysis（意图预检）：** 在执行前，利用 FSS 进行两方协作的策略判定。
3. **Output Sanitization（输出净化）：** 即使 Agent 生成了包含 PII 的文本，Guardrails 也会在秘密共享状态下将其擦除。



### 总结建议

你的 MIRAGE-OG 方案非常棒，**不要放弃 FSS**。它是你冲击顶会（如 USENIX Security 或 CCS）的“肌肉”。

**只需修改叙述的一点：** 不要说“为了安全我们用了 FSS”，而要说“为了解决**‘本地高度敏感 Agent’与‘云端集中式审计’之间的信任冲突**，我们必须使用 FSS 构建 Oblivious Guardrails”。

这样，FSS 就不再是“强行挂载”的组件，而是整个方案的**逻辑支点**。如果你准备好了，我可以帮你把这套逻辑补充进之前的研究报告中。