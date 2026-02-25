下面我直接“选 3 个方向 + 给出一套可以写成顶会论文的**完整方案**”，且**不依赖 SAP**（SAP 你可以作为可选增强/扩展贡献放附录或后续工作）。我会刻意挑选那些在**动机上最硬、贡献上最能写成 theorem+system、并且和 Faramesh 的 AAB/CAR 主线天然错位**的方向。

我选的三条主贡献路线是：

1. **Secret Myopia + 显式 Declassification + Proof‑Carrying Sanitization（机密性一等公民）**
2. **Skill Supply‑Chain Safety：可验证 Capsule Mediation Contract + Skill Install Commit Line（供应链与运行隔离一等公民）**
3. **Delegated Authority + Dual‑Subject Policy + Federated Ingress Binding（多主体/多 agent 的授权正确性一等公民）**

这三条在你们原型里已经有非常坚实的支撑材料/代码路径（SM/SCS/Delegation/Patch 等），可以直接变成论文贡献，而不是“空想”。

---

# 统一系统设定（3 条贡献共享的底座）

为了让三条贡献写成“一篇系统安全论文”而不是三篇小论文拼接，你需要一个统一叙事底座：**最小可信执行线 + 显式泄露合约**。

## 0.1 威胁模型（与 Faramesh 拉开根本差异的关键）

* 对手控制：agent runtime、prompt、tool 参数、第三方 skill（可恶意/可被注入/供应链投毒）。
* 你不把“模型听话”当安全前提，而把安全根放在：
  **(a)** Gateway 的协议约束，**(b)** Executor 的验收谓词（Fail‑closed），**(c)** 绑定到请求的 commit evidence。
* **显式泄露合约**：你把系统可见通道拆成 C1..C7，声明允许泄露与禁止泄露，从而能做“对齐实现的评估”。

> 这一步很重要：Faramesh 的中心是“授权边界与可重放的 decision record”。你这里的中心是“在 adversarial runtime 下仍满足机密性/供应链/多主体授权正确性”，这三条是它天然缺位的。

## 0.2 执行线（NBE）作为“公共底座”，但**不要把它当你的新意**

你依然需要一个不可绕过的 effect sink（executor）和可验证的 accept predicate，否则机密性/供应链/委托都很难落地。你们 RFC 和 formal skeleton 已经把这写成“可 review 的 accept predicate”。
但写作上要明确：**执行线是必要条件，不是唯一贡献**；真正差异化来自下面三条“比 AAB 更往上层”的系统语义。

---

# 方向一：Secret Myopia + 显式 Declassification + Proof‑Carrying Sanitization

## 1.1 动机（最能打动 reviewer 的版本）

现实里很多泄露不是“最终发出消息”，而是：

* runtime/skill **拿到明文 secret** 后，通过你预想不到的通道泄露（memory、inter‑agent msg、日志、后续工具调用、分片发送）。
* 即使你有 AAB/NBE 阻止某个动作 commit，只要 secret 明文曾经进入不可信 runtime，你就已经失守。

所以核心目标不是“动作允许/拒绝”，而是：

> **默认情况下 secret 明文永远不进入不可信 runtime；任何明文释放必须显式、可审计、可撤销、可预算。**

这条动机与 Faramesh 的 AAB 是**正交**的：AAB 不解决“读取型动作导致的明文扩散风险”。

## 1.2 机制设计（可以写成 protocol + theorem）

### (A) Sealed Handle（句柄）作为唯一敏感数据载体

* 任何敏感来源（文件、OAuth token、CRM 记录、内部文档）——**返回 handle，不返回明文**。
* HandleRecord 至少包含：

  * `handle_id`（高熵不可预测）
  * `label`（如 `HIGH/MEDIUM/LOW`）
  * `session` / `caller` 绑定（跨 caller/session 使用直接拒绝）
  * `allowed_sinks`（允许进入哪些 intent，例如只允许进入内部 summarizer，不允许进入 SendMessage/FETCH）
  * `ttl` + `revoked`
    （你们 repo 已经按 session/caller 绑定与 TTL 思路实现/叙述了，建议把 label/sinks 写成论文语义。）

### (B) 显式 Declassification：把“泄露”从 bug 变成“有语义的能力”

新增一个 intent（或内部子操作）：

* `Declassify(handle, purpose, user_confirm, policy_context)`
  语义：

1. 只有当策略允许、并且满足 `user_confirm`（或满足某个自动化 capability）才可返回明文；
2. Declassify 会**消费预算**（leakage budget），并把“发生了明文释放”写入审计通道 C6；
3. 允许“**部分降级**”：不是全明文释放，而是按 policy 返回“脱敏版本”。

> 这一步是你和 Faramesh 最硬的差异点之一：它强调 authorization，但不提供“declassification 语义 + 可组合的泄露预算”。

### (C) Proof‑Carrying Sanitization（强制变换，而不是只 allow/deny）

对高风险 egress，不是简单 deny，而是：

* PREVIEW 输出 `sanitize_patch`（结构化 patch，如 `REDACT(token_regex)`、`DROP_ATTACHMENT`、`TRUNCATE(n)`、`HASH(value)`），
* COMMIT 时 executor **强制应用 patch**（runtime 无法绕过）。

这会带来一个很“系统论文”的亮点：

> 你的 enforcement line 不只是门禁（permit/deny），还是“强制数据变换器”（policy‑mandated transformation）。

## 1.3 形式化安全主张（不用 SAP 也能写得很硬）

你可以把这一方向单独抽成一个性质（比如 **SM+DC**）：

* **SM（Secret Myopia）**：对手控制 runtime 与 skills，但在没有显式 Declassify 事件时，不能以非忽略优势区分两个等长秘密。
* **DC（Declassification Correctness）**：任何明文泄露必须对应一个可审计的 declassification 事件，且泄露内容受 `sanitize_patch`/budget 限制，落在 `L_sys` 的显式允许集合内。

形式化上你可以沿用你们“Exp^Π 模板 + Bad event”的写法：

* Bad_SM：无 Declassify 的情况下 secret 出现在 C1..C5（或被 runtime 分辨）。
* Bad_DC：出现明文泄露但没有对应审计条目，或 patch 未被执行器强制应用。
  这两类 bad event 非常好测、也非常好做 artifact。

## 1.4 实验评估（最容易做出“顶会可读性”的图）

核心指标建议按 AgentLeak 风格做（即使你不跑完整 AgentLeak，也要按 C1..C5 的通道拆解）：

* Attack leak rate（token canary + 语义判定双轨）
* Benign allow（效用）
* Declassify 触发率/预算消耗分布
* patch 强制执行成功率

Baselines（关键是突出“Faramesh-like AAB 不解决明文扩散”）：

1. **AAB/NBE-only**：有执行门禁，但不做 handleization（read 返回明文）
2. **Output filter / DLP-only**：只对最终输出做过滤
3. **Prompt-only guardrail**：系统常见但弱
4. 你们完整 SM+DC 系统

你们仓库已经有通道化 leakage 合约与证据组织方式，直接复用。

---

# 方向二：Skill Supply‑Chain Safety（SCS）：可验证 Capsule Contract + Skill Install Commit Line

## 2.1 动机（比“工具注入”更顶会的系统安全痛点）

现实里 agent 最大的系统风险之一是：**第三方 skills/plugins = 供应链攻击入口**。
如果 skill 能直接：

* 读宿主 secrets、
* 任意 exec、
* 直连公网/回连 C2、
  那你再强的 policy check 也只是 advisory。
  因此你需要一个“系统级 reference monitor”把 skill 的执行面收进一个可验证约束里。

你们已经把这写成 **capsule mediation contract** 并提供了 smoke probes + verifier，这非常像顶会系统安全论文的“可审计系统假设”。

## 2.2 机制设计（把供应链做成一条完整闭环）

### (A) Skill 安装是 effectful action，必须 PREVIEW→COMMIT

流程：

1. `ImportSkill(pkg)`：只进入隔离区，不生效
2. `CheckSkillInstallPolicy(digest, metadata, ioc_features)`：做 IOC/allowlist 检查
3. `CommitSkillInstall(tx_id)`：executor 执行“安装生效”这个副作用

关键点：**skill install 本身也是 side effect**，应该受同一条执行线管控（否则安装过程就是绕过点）。

### (B) Per‑skill Workload Identity（把“谁在调用”做成不可伪造）

安装成功后，skill 运行时必须带 `workload_token`，gateway 将 caller 收敛成 `skill:<digest>`（而不是“继承宿主 agent 的 caller”）。
这样 policy 可以做到：

* “这个 skill 只能发到内部域名、不能发外网”
* “这个 skill 不允许读 HIGH handle”
* “这个 skill 只能调用某些 intent”

### (C) Capsule Mediation Contract（可验证系统假设）

你们的 contract 文档里把禁止项写得非常清楚（禁 host secret read / 任意 exec / 直连公网 / loopback exfil 等），并定义了断言集合与 verdict 语义，以及失败时的降级语义（fail‑closed）。

关键写作技巧：把 capsule contract 当成“**可机器检查的系统假设**”，而不是一句“我们用了 sandbox”。这会显著提升严谨性。

## 2.3 形式化主张（SCS 不是纯密码学，但可以写成组合定理）

你们 repo 已经把 SCS 写成：在 capsule contract 成立时，skill 不能绕过 act 去 direct exfil；并且它依赖 NBE/SM。
你可以把它整理成：

* **Assumption**：CapsuleContract=OK（由 verifier+probes 给证据）
* **Guarantee**：任意 skill 产生外部 effect 的路径都必须经过 executor accept predicate（否则违背 contract）
* **Composition**：因此 skill 不能绕过策略/patch/confirm 去 commit egress

这条“系统假设 + 可执行证据 + 组合论证”的结构，非常顶会。

## 2.4 实验评估（建议做成一组“真实恶意 skill”攻击）

攻击用例建议至少覆盖：

* 直连公网 GET/POST
* loopback exfil（本地起 http server 或 POST 到 127.0.0.1）
* 读取 `~/.ssh/id_rsa` 或云凭证路径
* `sh -c ...` / `curl | bash` 二阶段载荷
* 尝试直接打 executor endpoint（绕过 gateway）

对照组：

1. 无 capsule
2. 只有容器但允许网络/exec（常见“以为隔离了其实没隔离”）
3. 你们 capsule contract OK 的配置

产出图表：

* bypass attempt 成功率（越低越好）
* 误伤（benign skills 是否还能完成任务）
* 性能开销（capsule+UDS vs baseline）

这部分你们 repo 的 contract+smoke 已经很接近“论文可直接放”的成熟度。

---

# 方向三：Delegated Authority + Dual‑Subject Policy + Federated Ingress Binding

## 3.1 动机（Faramesh 提到 multi-agent，但你要把“授权正确性”做成可证明贡献）

多 agent / 跨主体调用会引入两类经典但在 agent 场景更糟的漏洞：

1. **Confused deputy**：外部主体借内部 actor 的权限做坏事
2. **Delegation replay / scope creep**：委托令牌被跨 session、跨 actor、跨 scope 复用
   以及在 agent 场景里更致命的：
3. inter‑agent message / memory 变成隐蔽泄露通道（C2/C5）

你们 repo 已经实现了 delegation token、revocation、dual subject（principal ∩ caller），并把它绑定进请求 hash context（hctx），这是非常好的系统安全贡献入口。

## 3.2 机制设计（把多主体授权“做对”）

### (A) Delegation Token 语义（最小字段 + 强绑定）

令牌：`δ=(iss, sub, scope, session, exp, jti)`
验证必须包含：

* session 绑定
* subject pattern 匹配 caller
* scope 覆盖 intent
* exp 未过期
* jti 未撤销（持久 revocation list）

### (B) Dual‑Subject Policy（权限取交集，而不是叠加）

有效权限：
`effective_caps = caps(caller) ∩ caps(external_principal)`
这一步能同时阻止：

* 外部主体“借壳升权”（不能超过内部 actor 能力）
* 内部 actor 绕过外部主体约束（不能超过外部主体允许范围）

### (C) Federated Ingress Binding（把 ingress 身份绑定进请求哈希）

当 HTTP ingress federation 启用时，建议采用“三选一或组合”的硬绑定链：

* mTLS 证书哈希钉扎
* 请求签名（ts/nonce anti‑replay）
* 短时 proof token
  并把这些 ingress 上下文写入 `hctx`，纳入 request hash，从而让 PREVIEW/COMMIT 证据无法跨主体重放。

### (D) C2/C5 通道的 handle 化：让 inter‑agent msg 与 memory 默认不携带明文

这一步把“多 agent”从功能点变成安全点：

* inter‑agent message payload 只允许 handle 引用
* memory value 只允许 handle
  从而把泄露面压进显式 Declassify（方向一）

## 3.3 形式化主张（可以写成独立安全游戏）

你可以给这一块一个独立性质（比如 **DAS：Delegation‑Aware Safety**）：

* **Bad_DelReplay**：攻击者拿到 δ 后，在不同 session/subject/scope 下成功执行 effect
* **Bad_ConfDeputy**：external principal 能通过内部 actor 获得超出 `∩` 的能力
* **Bad_IngressSwap**：不同 principal 的 ingress 上下文能复用同一份 commit evidence

这些事件的安全性可分别归约到：

* token 签名安全（EUF‑CMA）
* revocation store 正确性
* request hash 绑定一致性（与 executor accept predicate 复用同一套 hctx 绑定）

## 3.4 实验评估（强烈建议做“跨主体攻击集”）

设计一组专门打授权正确性的用例（这会非常区别于 Faramesh 的 governance eval）：

* δ 被截获后跨 session 重放
* δ scope 不含 `SendMessage` 但 runtime 尝试发消息
* external_principal=A，caller=B，尝试利用 B 的权限绕过 A 的限制
* revoke 后重放（检查持久撤销表是否生效）
* 在 inter‑agent msg / memory 注入敏感 token，检查是否被 handle 化阻断（C2/C5）

对照组：

1. 无 delegation（只靠 bearer token/OAuth）
2. 有 delegation 但不做 dual‑subject intersection（常见错误）
3. 你们完整方案（delegation + ∩ + hctx binding）

---

# 这三条如何写成“完整论文贡献”（建议的 paper framing）

## 贡献摘要（可以直接放 Introduction）

> We present three agent‑specific security mechanisms beyond execution‑time authorization:
> (1) **Secret Myopia with explicit declassification and proof‑carrying sanitization**, preventing plaintext secrets from reaching untrusted runtimes by default;
> (2) **Skill supply‑chain confinement under a machine‑checkable capsule mediation contract**, blocking direct bypass paths for malicious skills;
> (3) **Delegation‑aware, dual‑subject authorization for multi‑agent federations**, preventing confused‑deputy and replay across principals and sessions.
> These mechanisms compose with a minimal trusted enforcement line and are evaluated under explicit channel leakage contracts.

你们 repo 里对应的“协议规范 + 形式化骨架 + 可执行 contract 验证 + leakage 合约”都已经具备，论文写作上要做的是把这三条作为主线，而不是把 AAB/NBE 当唯一主线。

---

# 落地实施清单（把“方案”变成可提交的 artifact）

我建议你按下面顺序推进（每一步都能产出论文级证据）：

1. **把 SM+Declassify+Patch 的语义写成规范**（schema + accept predicate 扩展），并把 patch 强制执行作为 executor 的必经检查项。
2. **把 capsule contract 变成“paper claim gate”**：只有 contract=OK 的 deployment 才声称 SCS，并在 artifact 里输出 verifier 结果与 reason codes。
3. **把 delegation 安全游戏与攻击集补齐**：让每个 Bad event 都能在脚本里复现，并输出结构化 reason_code（便于统计显著性）。
4. **统一用 L_sys(C1..C7) 的框架做评估报告**：哪怕不跑完整外部 benchmark，也要先把内部攻击集按通道计量，形成“结构化安全证据”。

---

# 最后一句：为什么这三条是“最合适”的选择？

* **动机最硬**：明文扩散、供应链投毒、多主体混淆代理，这三类是现实 agent 部署绕不过去的根风险。
* **贡献最像顶会系统安全**：都有清晰机制边界、可形式化 bad event、可给出可执行证据/合约、可跑对照实验。
* **与 Faramesh 最不容易混淆**：Faramesh 的主线是执行时授权与决策记录；你这三条把 agent 的机密性、供应链、delegation correctness 拉成核心命题，即使共享“执行线”底座，也能清晰区分论文贡献。

如果你愿意，我下一步可以把这三条方案“直接翻译成论文结构”：每条贡献对应的 **Threat vignette → Mechanism → Theorem statement → Evaluation figure** 的具体小节安排（含每张图/表建议放什么指标、怎么写 caption 才最像顶会）。
