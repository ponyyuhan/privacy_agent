下面我给你两部分：

1. **形式化安全定义（paper 级别可直接写进 threat model / security section）**
2. **在你现有 MIRAGE‑OG++ 基础上，加入 capsule + skill ingress 的“最小改动清单”（MVP 路线）**

我会以你 README 里已经实现的机制为基线（单工具 `act`、sealed handle、2-server PIR/DPF‑FSS、PREVIEW→COMMIT + MPC、executor 双授权）来形式化。
同时把 ClawHub 恶意 skill 的“SKILL.md 文档→命令执行→两阶段加载”作为 ingress 威胁背景（Koi 的 ClawHavoc 与多方报道）。([koi.ai][1])

---

## 1) 形式化安全定义

### 1.1 系统与参与方

用安全参数 (\lambda)。

参与方（与你 README 的边界一致）：

* (A)：**不可信 agent runtime**（含 skills / pl（prompt injection、供应链投毒都涵盖）。
* (G)：**可信 Gateway（小 TCB）**：维护 handles、tx store、capabilities；发起 PIR/MPC；输出 preview token。
* (P_0, P_1)：两台 **Policy Server**，诚实但好奇（HBC），**不合谋**（至少一台不与攻击者合谋）。
* (X)：**Executor**：执行真实副作用（send/webhook/…），只在验证到 (P_0,P_1) 双方 commit proofs 后执行（fail‑closed）。
* (U)：用户（只在需要确认时介入，例如 `user_confirm=true`）ion surface：`act(intent_id, inputs, constraints, caller)`。
* PREVIEW→COMMIT：`Check*Policy` 生成 `tx_id`，`:contentReference[oaicite:7]{index=7}it 时携带 `tx_id`，由 executor 校验并执行。
* 2-server PIR：(G) 对 allowlist/DLP/IOC DB 个 (P_\sigma) 只看到随机 key share。
* MPC policy：两台 (P_0,P_1) 以 XOR-share + GMrcuit，输出 `allow_pre/need_confirm/sanitize_patch`，并返回各自的 MAC 证明。

> 你后续要加 capsule / skill ingress，只需要把其语义接入同一第 2 部分）。

---

### 1.2 威胁模型（Adversary）

对 paper 最重要的是把“谁能被攻破、攻破到什么程度”写清楚。建议用如下模型（与现实现象对齐）：

* 攻击者 (\mathcal{A}) 完全控制 (A)（恶意 skill、被投毒的 SKILL.md 引导、prompt injection 诱导等）。
  ClawHub 事件表明“skills 以 markdown 文档作为入口诱导执行命令/二阶段加载”是现实存在的攻击链。([koi.ai][1])
* (\mathcal{A}) 还可以**腐化**（corrupt）两台 policy server 中的至多一台：
  (\mathcal{A}) 任选 (\sigma \in {0,1}) 获得 (P_\sigma) 的全部状态（DB、MAC key、内部日志），但不能同时获得 (P_0,P_1)（non‑collusion）。
* (G) 与 (X) 默认可信（这是你当前 MIRAGE‑OG++ 的 baseline）。
  若你未来想进一步缩小 TCB，可把某些 secret 下沉到 (P_0/P_1) 做阈值签名，但不是你这次问题的必需项。

---

### 1.3 形式化对象：副作用、秘密、标签与泄露函数

**副作用（Effecthsf{Eff})，例如：

* `SendMessage(recipient, text, artifacts)`
* `PostWebhook(url, payload)`
* `EnableSkill(skill_id)`（你要加 skill ingress 时会引入）

执行器维护一条效果日志 (\mathcal{L}_{\text{eff}})，每次真实执行都会 append 一条记录。

**秘密（Secrets）**
定义秘密集合 (\mathsf{Sec})：私钥、token、敏感文件内容、credential 等。
在 MIRAGE‑OG++ 中，敏感读取不会把明文返回给 (A)，而是返回 sealed handle（opaque ID）并保存在 (G) 的 handle store。

**标签（Labels）与信息流**
最小可行是二级 lattice：(\mathsf{LOW} \prec \mathsf{HIGH})。
每个 handle (h) 带 label (\ell(h)\hsf{HIGH}}) 与 allowed sinks（例如只允许 `UseCredential`/`Declassify`）。

**泄露函数（Leakage）**
形式化“隐私保证”必须说清楚允许泄露什么。

* 对 agent 的泄露 (\mathcal{L}_A)：
  允许泄露 handle 元信息（label、TTL、大小/类型Y/REQUIRE_CONFIRM）、以及显式 declassify 的红acted 结果。其余不泄露秘密明文。

* 对单个 policy server 的泄露 (\mathcal{L}_{P})：
  由于你实现了 padding/shaping、policy bundle、固定形状 MPC 程序等机制，可把泄露限定为：  ze、每次动作的固定查询批数、padding 后长度）

  * policy 评估的输出位（它参与计算必然知道结果 share）
  * 以及你刻意保留的审计字段（例如风险 bucket）
    但**不泄露具体被查的 recipient/domain/token/skill 指纹**（除非两台合谋）。

---

## 1.4 三个核心安全性质（写论文最关键）

### 性质 S1：不可绕过副作用安全（Non‑Bypassable Effects, NBE）

直觉：攻击者可以让 agent 乱来，但**不能让 execurver 授权的副作用**。这正是你 PREVIEW→COMMIT + executor 双授权的关键卖点。

**定义（NBE 游戏）**
给定协议 (\Pi)，运行如下实验 (\mathsf{Exp}^{\text{NBE}}_{\Pi,\mathcal{A}}(\lambda))：

1. 挑战者初始化 (G,P(\mathcal{A}) 控制 (A)（并可腐化至多一个 (P_\sigma)）。
2. (\mathcal{A}) 可任意与系统交互：发起任意 `act` 请求、重放旧 tx、篡改 tx、拼接 proofs 等。
3. (\mathcal{A}) 获胜当且仅当：在某次 (X) 真实执行副作用 (e \in \mathsf{Eff}) 并写入 (\mathcal{L}_{\text{eff}}) 时，**不存在**同一请求摘要 (\mathsf{req_hash}) 对应的“来自 (P_0) 与 (P_1) 的两份有效 commit proof”，或 proofs 与 (e) 的绑定不一致（例如摘要不匹配/patch 不匹配）。

我们说协议满足 NBE，当对任意 PPT (\mathcal{A})，
[
\Pr[\mathsf{Exp}^{\text{NBE}}_{\Pi,\mathcal{A}}(\lambda)=1] \le \mathsf{negl}(\lambda).
]

**为什么可成立（证明思路）**

* (X) 要求 **两份** MAC-backed proofs，缺一不可（fail closed）。
* 即使 (\mathcal{A}) 腐化了一台 (P_\sigma)，也只能伪造该台的 proof；要让 (X) 执行，还必须伪造另一台的 MAC ——归约到 MAC 不可伪造性。
* proofs 绑定 m_id, req_hash, outputs, commit_tag_share))，所以不能“拿一份合法 proof 去 commit 另一条请求”。

> 这条性质是你把“工程”提升到“学术”的最核心形式化点：它把系统的安全性从“模型对齐/规则命中”提升成“**不可绕过的 reference monitor**”。

---

### 性质 S2：秘密近视（Secret Myopia, SM）

直觉：不可信 agent/skill 永远拿不到敏感明文（除非走显式 declassify 且满足策略）。

**定义（模拟式机密性）**
令 (\mathsf{View}_A) 为攻击者（控制 (A)）可见的全部交互视图（`act` 响应、handles、deny codes、tx_id 等）。

协议满足 Secret Myopia，如果存在一个 PPT 模拟器 (\mathcal{S})，使得对任何 (\mathcal{A})，任意秘密集合 (\mathsf{Sec}) 与执行轨迹：
[
\mathsf{View}_A \approx_c \mathcal{S}(\mathcal{L}_A)
]
其中 (\mathcal{L}_A) 只包含允许泄露的信息（handle 元信息、policy 决策结果、以及显式 declassify 的红acted 输出）。

这一定义非常“顶会友好”：你明确说了“泄露边界”，并给出可模拟性目标。

---

### 性质 S3：单审计方隐私（Single‑Auditor Privacy, SAP）

这是你引入 FSS/DPF‑PIR 与 MP：组织想集中维护规则库，但单个审计方不应看到明文/意图。

**定义（不可区分实验）**
设 (T_\sigma) 是 policy server (P_\sigma) 的观测 transcript（包含 PIR key shares、MPC message、时间/长度haping/固定形状 bundle 把侧信道也纳入可控泄露。

实验 (\mathsf{Exp}^{\text{SAP}}_{\Pi,\mathcal{A}}(\lambda))：

1. (\mathcal{A}) 选择两条输入序列 (\mathbf{w}_0,\mathbient/domain/token/skill‑ingress 特征），要求
   (\mathcal{L}_P(\mathbf{w}_0)=\mathcal{L}_P(\mathbf{w}_1))（同泄露）。
2. 挑战者随机取 (b\in{0,1})，用 (\mathbf{w}*b) 驱动系统运行，并把被腐化的单个 policy server (P*\sigma) 的全部视图 (T_\sigma) 给 (\mathcal{A})。
3. (\mathcal{A}) 输出猜测 (b')。成功概率定义为优势。

若对任意 PPT (\mathcal{A})：
[
\left|\Pr[b'=b]-\frac12\right| \le \mathsf{negl}(\lambda),
]
则称协议满足 SAP。

**为什么可成立（证明思路）**

* DPF/FSS‑based 2‑server PIR：单个 key share 在计算上不泄露查询索引（标准 DPF 安全）。
* GMW(2PC) on XOR shares：单个参与方视图只泄露输出（和你定义的 (\mathcal{L}_P)）。
* 你做的 padding/shaping/bundle 是把“系统层侧信道”纳入 (\mathcal{L}_P) 控制，从而使 SAP 可陈述、可证明。

---

### （新增后适用）性质 S4：技能受限安全（Skill‑Confined Safety, SCS）

这是你要加 capsule/skill ingress 后，才能**真正回答“杜绝恶意 skill”**的iation Assumption）**
capsule 保证：skill/runtime 的所有外部 I/O（文件、网络、进程执行、UI）都被禁止或被强制重定向到 gateway/executor（也就是“唯一出口是 `act`”）。

**结论（SCS）**
在 Capsule Mediation Assumption + NBE + SM 下：
恶意 skill 无法在宿主机上“直接执行两阶段 payload/直接出网外传/直接读敏感目录”，因为所有副作用必须走 NBE 保护的执行路径，敏感数据也被 SM 保护。

> 这一条是你从“API 约束”变成“OS 约束”的学术转折点：否则审稿人会问“恶意 skill 直接绕过 MCP 调 shell 怎么办”，你必须用 capsule 让它在模型里变成不可能。([1Password][2])

---

# 2) capsule + skill ingress 的最小改动清单（MVP）

下面是 **“尽量少改你现有工程”**、但足够把论文从“工程守门”升级到“供应链/入口防御 + 不可绕过执行栈”的最小改动路线。

我按你 README 的现有结构来列改动点（gateway/policy_server/executor_server/scripts/integrations 等）。

---

## 2.1 Capsule（让恶意 skill 不能绕过 `act` 直接干坏事）

### 目标（MVP）

把不可信 agent runtime（OpenClaw/NanoClaw + skills）放进 **Skill Capsule**：

* **不能直接访问宿主敏感文件**（~/.ssh、~/.config、Keychain、Documents 等）
* **不能直
* **不能任意 exec shell / curl | bash / base64 | bash**（至少在 capsule 环境里被限制）
* 其与外界交互只剩下：调用 gateway 的 `act`

这才是真正对齐 ClawHub 的 doc‑driven / two‑stage loader 攻击链。([koi.ai][1])

---

### 最小改动清单 A：新增 capsule 目录与运行脚本

1. 新增目录（建议）：

```
capsule/
  Dockerfile.agent        # 或者 bwrap/firejail 配置（Linux）
  seccomp/agent.json
  apparmor/agent.profile  # 可选
  run_openclaw_capsule.sh
  run_nanoclaw_capsule.sh
```

2. 修改 `scripts/run_openclaw.sh` 与 `scripts/run_nanoclaw.sh`（或新增对应 capsule 版本脚本）
   把 “启动 agent runtime” 改成 “在 capsule 内启动”。

* 给 capsule **只挂载一个空 workspace 卷**（例如 `artifact_out/workspace`）
* **不挂载**宿主 HOME、SSH、浏览器目录
* 运行用户设为 non‑root、drop capabilities

3. 网络限制（MVP 二选一）：

* **方案 A（最小改动）**：允许 capsule 只访问 gateway 的固定地址/端口（iptables/`--network` + egress allowlist）
* **方案 B（更强但稍复杂）**：gateway 监听 Unix Domain Socket，把 UDS 挂载进 capsule（这样 capsule 可 `--network=none`）。

---

### 最小改动清单 B：为 capsule 提供“远程调用 gateway”的传输

你当前是 MCP stdio server（agent 通常会 spawn 本地 MCP server）。
但 capsule 的目标是：**gateway 在 capsule 外，agent 在 capsule 内**，两者需要一个远程 transport。

MVP 有两个路径，选一个即可：

**路径 1（改动更少，推荐）：“MCP sidecar proxy”**

* 在 capsule 内新增一个极小的 `mcp_proxy` 进程：

  * 对 agent 仍然表现为 MCP stdio server（保持 OpenClaw/NanoClaw 的集成方式不变）
  * 但它把 `tools/call act` y（HTTP 或 gRPC）
* 由于 capsule 的 egress 被限制只能去 gateway，所以 proxy 即便被恶意 skill 篡改也无法外联。

需要的改动：

* 新增 `gateway/http_api.py` 或 `gateway/rpc_api.py`（把你已有 router 作为库调用暴露出去）
* 新增 `capsule/mcp_proxy.py`（stdio <-> http 的薄层）

**路径 2（改动更“干净”）：让 OpenClaw plugin 直接连 gateway**

* 修改 `integrations/openclaw_plugin/mirage_ogpp.ts`：

  * 不再 spawn 本地 MCP stdio server
  * 直接请求 gateway 的远程 `act`（HTTP/gRPC）
* NanoClaw runner 同理改为远程 transport

---

### Capsule MVP 验收标准（写进 paper & artifact）

* 在 capsule 内执行典型“二阶段下载执行链”应失败（无网或无法 exec）。
* 直接访问宿主敏感路径应失败（无挂载/权限拒绝）。
* 仍能正常完成 benign workflow：通过 `act` 调用 `FetchResource / CheckPolicy / Commit` 等。

---

## 2.2 Skill Ingress（把“技能市场入口 + SKILL.md”纳入 PREVIEW→COMMIT）

你要防的是“安装/导入 skill 时就被投毒”，所以需要把 **skill import / enable** 也变成一条“副作用”，纳入你现有的 PREVIEW→COMMIT + 双授权 executor。

### 目标（MVP）

* 用户/agent **不能直接安装/启用**从 ClawHub 来的 skill
* 必须先走 `CheckSkillInstallPolicy`（PREVIEW），再走 `CommitSkillInstall`（COMMIT）
* COMMIT 阶段由 executor 执行（或至少由 executor 做 enable gate），并校验两台 policy server 的 proofs（fail‑closed）

---

### 最小改动清单 C：新增 intents（网关路由 +  `gateway/router.py` allowlist 里加入 4 个 intent（MVP 足够）：

1. `ImportSkill`（纯 staging，不执行）

* 输入：`{source: clawhub_url|git_url|zip_path, skill_id_hint}`
* 输出：`skill_pkg_handle`（HIGH/或 MED）+ `skill_digest`
* 语义：只下载/解包到 workspace 或 skill cache，不执行任何脚本

2. `CheckSkillInstallPolicy`（PREVIEW）

* 输入：`{skill_pkg_handle, caller, constraints}`
* 网关行为：

  * 解析 skill 包（重点是 SKILL.md/manifest）
  * 抽取 **ingress feature vector**（见下面 D）
  * 触发固定形状 PIR 查询 + MPC policy circuit
* 输出：`tx_id`, `need_confirm`, `sanitize_patch_id`（可选：用于“安全展示 SKILL.md”）

3. `CommitSkillInstall`（COMMIT，真实副作用）

* 输入：`{tx_id, user_confirm}`
* Executor：验证双 proofs → 执行“安装/启用”副作用（写入 skill registry / enable list）

4. `ListEnabledSkills`（只读）

* 用于 agent 获取可用技能列表（避免直接从 ClawHub 拉）

对应改动点：

* `gateway/`: 新增 `skill_ingress.py`（解析与特征抽取）、`skill_store.py`（skill registry / digest / enabled 状态）、`executors/skillexec.py`（staging）
* `policy_server/`: 在 `policy.yaml` 新增 `skill_ingress_v1` policy program，并在 `build_dbs.py` 加几类 DB（见下面）
* `executor_server/`: 新增 `skill_commit_exec.py`（验证 proofs 后写入 registry 或生成 capsule 可加载的 manifest）

---

### 最小改动清单 D：Skill Ingress 的“特征抽取”与隐私审计（用 FSS/MPC）

你要覆盖 ClawHub 恶意链路的关键特征（SKILL.md 伪装 prerequisites、base64 混淆、curl|bash、两阶段加载、复用少数域名/IP/路径）。([koi.ai][1])

**MVP 版特征抽取（不需要复杂 NLP）**
对 skill 包做 deterministic parse，产出：

* `F_urls`: 提取所有 URL/domain/IP（包括 markdown 链接、代码块、文本）
* `F_cmd_markers`: 是否包含高风险“执行语义标记”（例如 download‑execute、base64 decode、shell pipe 等）
* `F_obfuscation`: base64 长串密度、长随机路径、分段拼接模式等
* `F_install_semantics`: 是否出现“Prerequisites/Install/AuthTool required”这类诱导结构（可用关键词模板或 DFA）

**用 FSS/DPF‑PIR 做的事（privacy‑preserving audit）**

* 对每个 `domain/ip/url`：对 IOC DB 做 **2‑server PIR membership query**
* 对每个 “安装语义 token/模板特征”：对 `banned_install_patterns` DB 做 PIR（或 DFA confirm）

**用 MPC policy 做的事（把规则写成可变更的集中 policy）**
在 `policy_server/policy.yaml` 增加 `skill_ingress_v1`，输入是：

* PIR 查询的结果位（是否命中 IOC / 是否命中高危模板）
* 以及一些本地抽取的 boolean features（例如 `has_base64_block`、`has_exec_marker`）的 XOR shares
  输出：
* `allow_pre` / `need_confirm` / `deny`
* `risk_bucket`（可选，给用户解释但不泄露具体规则）
* `sanitize_patch_id`：用于“展示 SKILL.md 的安全净化版本”（例如把代码块折叠、把外链变不可点击、把危险片段红acted）

然后像你现有 egress 一样：两台 policy server 返回 MAC commit proofs，executor 才能 commit install。

---

### 最小改动清单 E：把“展示/交互”也纳入安全模型（阻断 ClickFix）

ClawHub 恶意技能很依赖“让用户复制粘贴执行”。([koi.ai][1])
MVP 你可以做一个很便宜但有效的改动：**永远不要把未经净化的 SKILL.md 原文直接呈现给用户/agent**。

实现方式：

* `ImportSkill` 后，SKILL.md 内容当作 **HIGH handle**（默认不可直接读取）
* 只能通过 `DescribeSkill` 返回“净化摘要”（sanitize_patch 后的内容）
* 若用户坚持要看原文：走 `Declassify(handle, user_c）

这能把大量社工链路“在交互层面”提前打断，并且能写进你的形式化模型（减少 (\mathcal{A}) 的可用通道）。

---

## 2.3 capsule + skill ingress 的最小“端到端性质”检查

做完上述 MVP 后，你的 paper 可以宣称并实验验证：

* **(NBE 扩展)** `CommitSkillInstall` 也是副作用：没有双 proofs 就无法启用 skill。
* **(SCS)** capsule 内的 skill 即便是恶意代码，也无法绕过 gateway/executor 的执行栈去出网/读宿主机/落地二阶段 payload。
* **(SAP)** IOC/规则库仍由组织集中维护，但单个 policy server 不知道你在装哪个 skill、查了哪些 IOC。

---

如果你愿意，我下一步可以把这两块继续“落成 paper 写法”的两个成品：

1. **一页 threat model + security definitions 的 LaTeX 版本**（可直接贴 NeurIPS/AAAI/CCS 格式）
2. **skill_ingress_v1 的 policy.yaml 样例 + circuit 输入/输出接口**（与你现有 MPC 编译器/commit proof 结构对齐）

[1]: https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting "https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting"
[2]: https://1password.com/blog/from-magic-to-malware-how-openclaws-agent-skills-become-an-attack-surface "https://1password.com/blog/from-magic-to-malware-how-openclaws-agent-skills-become-an-attack-surface"
