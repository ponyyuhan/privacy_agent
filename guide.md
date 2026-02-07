下面给你一份“可以直接写进论文系统设计章节”的**完整方案**，把你要的三件事合在一起，并且把**安全模型、保护对象、策略、协议与实现路径**都讲到“能做 demo + 能写证明/评估”的程度：

* **Level 1：Agent/Skill 看不到敏感内容（Secretless + Sealed Handles）**
* **Level 2：Agent/Skill 不知道底层工具/命令细节（Intent API + Myopic Routing）**
* **Oblivious Guardrails：把外发/执行前的策略检查做成两方不合谋的 MPC/FSS（策略服务看不到内容/意图/规则触发）**

我把系统叫做 **MIRAGE‑OG**（Myopic Intent Routing + Access‑Governed Execution with Oblivious Guardrails）。

---

# 1. 目标与直觉

### 你要解决的真实风险

在 agent 生态里，**“不可信 skill + 工具执行”** 是最危险的组合：skill 既可能被供应链投毒，也可能被 prompt injection 诱导，从而读取本机/企业敏感数据并外发；而传统做法（沙箱/权限控制）常常挡不住“业务上必须读写/出网”的需求。

### MIRAGE‑OG 的核心直觉

把 agent 从“能看到秘密、能控制命令、能自由外发”的位置挪走：

1. **敏感内容不进 agent 的眼睛**：永远不把 secret 明文交给 agent/skill，而是给一个**不可外带句柄**（sealed handle）。
2. **底层执行细节不在 agent 的手里**：agent 只表达**Intent（高层意图）**，不再选择 tool_id、不再写命令行；由可信网关把 intent 编译/路由到具体执行器。
3. **把“检查/防外泄”外包也不泄露隐私**：外发前、执行前的策略检查由两个不合谋策略服务用 **MPC/FSS**在密态上完成（policy server 看不到内容/意图/哪条规则触发），但能强制 deny / sanitize。

---

# 2. 系统组件

### 2.1 角色与组件

* **A：Agent Host（不可信）**
  LLM + planner + skill runtime。我们把它视为“可能被攻击者控制”或“容易被注入诱导”。

* **S: Skill（不可信）**
  第三方插件/脚本/工作流。默认假设恶意。

* **G：MIRAGE Gateway（可信最小 TCB，本地）**
  关键职责：

  * 提供唯一工具接口 `mirage.act`（Intent API）
  * 管理 Sealed Handles / Secret Store
  * 生成秘密共享输入，调用策略服务做 oblivious guardrails
  * 只把“净化后的安全动作”提交给执行器

* **E：Executors（受控执行器，最小权限）**
  例如 `NetExec / FSExec / CryptoExec / MsgExec / WorkflowExec`
  执行器只接受经 G 认证、且经策略服务“双授权”的提交（commit tokens）。

* **P0/P1：Policy Servers（两方不合谋）**
  运行 oblivious guardrails：在 **2PC/MPC** 中对“将要执行/将要外发”的参数与内容做检查/净化；每方单独看不到明文，也看不到规则触发结果。

> 你可以把 P0/P1 理解为“外包的隐私保护安全服务”，例如企业把一台放内网、一台放云；或两家云。
> **只要至少有一方不合谋**，隐私就成立。

---

# 3. 安全模型（Threat Model）与假设

### 3.1 对手能力

对手可以：

* 完全控制 A 与所有 skills（读写其内存、篡改逻辑、构造任意 tool 调用请求）。
* 利用 prompt injection / tool poisoning 诱导 A 发起危险动作。
* 尝试通过多次试探调用“学习”你的策略规则（策略探测）。
* 控制网络（被动监听/主动篡改）——但我们假设 G↔P0/P1 与 G↔E 使用 TLS + 认证，网络攻击不改变协议安全性。

对手也可能控制 P0 或 P1 中的一方（最多一方），试图从策略执行中学习内容/意图。

### 3.2 信任假设（必须写清楚，审稿人才会买）

* **G（Gateway）可信**：它是最小 TCB；你要把它设计得很小、可审计（例如 Go/Rust daemon，IPC 接口极少）。

* **至少一个 policy server（P0 或 P1）不与另一方合谋**（两方不合谋模型）。

* **skill 运行环境被强制隔离**：skill 不能直接出网、不能直接读宿主敏感目录、不能直接 exec。
  这可用容器/沙箱实现（demo 可先用容器+seccomp；论文里强调“强制”而非约定）。

* **执行器验证双授权**：E 必须检查来自 P0/P1 的 commit token，缺一不可，否则不执行。

### 3.3 我们保证什么（Security Goals）

**G1（Level1）内容保密（对 agent/skill）：**
任何标记为 `SECRET/HIGH` 的内容，A/S 看到的只有 `handle`，永远拿不到明文（除非经过显式 declassify）。

**G2（Level2）执行细节不透明（对 agent/skill）：**
A/S 只能提交 Intent，不知道底层使用的 tool/命令模板/具体路由细节；Observation 结构统一，尽量降低从返回结构推断底层执行的能力。

**G3（Oblivious Guardrails）策略执行隐私（对 P0 或 P1 单点）：**
任一单独策略服务器看不到：将要外发/执行的明文内容、敏感参数、以及“哪条规则命中”。它只能参与协议并生成 commit token。
（Match Quest 这类工作就是在两方计算模型下做快速模式匹配，并在论文里讨论 FSS/DPF 作为基础原语；也强调实现基于 MOTION2NX 这样的 2PC 框架。([petsymposium.org][1])）

**G4（不可绕过）：**
没有 policy 双授权，执行器不执行；skill 没法绕开 G 直接调用 OS/网络/exec。

---

# 4. 唯一工具接口：MCP `mirage.act`（Intent API）

### 4.1 为什么用 MCP

把 MIRAGE Gateway 做成一个 MCP server，可以让任何支持 MCP 的 agent 框架/客户端接入，工程落地快。MCP 官方仓库提供规范与 schema，且声明 TypeScript schema 也可导出 JSON Schema。([GitHub][2])

### 4.2 核心：只暴露一个工具 `act`

> **agent 永远不能直接调用 `shell.exec`/`http.request`/`file.read`**
> 它只能调用 `mirage.act(intent_id, inputs, constraints)`。

返回统一 `Observation`，避免暴露“底层是 shell 还是 http”这种结构差异。

---

# 5. Level 2：Myopic Routing（让 agent 不知道底层工具/命令）

### 5.1 Intent 设计原则（必须受限）

为了真的做到“agent 不知道命令”，你必须**拒绝提供任意命令 intent**（比如 `RunCommand(cmd)`）。
你只提供一组“高层可审计”的 intents，例如：

* `ReadSecret(name)`
* `UseCredential(handle, op, target)`
* `ReadFile(path_spec, purpose)`
* `WriteWorkspaceFile(relpath, content_or_patch)`
* `FetchResource(resource_id, purpose)`（不是任意 URL）
* `SendMessage(channel, recipient_group, content_spec)`
* `InstallPackage(pkg, version?, scope?)`（内部决定 apt/brew/choco）
* `RunWorkflow(workflow_id, inputs)`（预定义工作流 allowlist）

### 5.2 路由器（Router）在 Gateway 内

Router 负责把 intent 编译成底层动作序列（底层工具/命令模板/代理路由）。
关键点：

* **命令模板与 tool 选择完全在 G 内**（可信域）
* **不回显**底层细节给 agent（返回统一 Observation）

### 5.3 侧信道最小化（现实但要写清）

完全阻止 agent 从延迟/错误码推断底层很难，但你至少做到：

* Observation 字段固定集合、长度上限、padding
* 错误码归一到 coarse bucket（如 `NETWORK_ERROR` vs `PERMISSION_ERROR`）
* 不返回原始 stdout/HTTP body（除非 public view）

---

# 6. Level 1：Sealed Handles（让 agent 看不到敏感内容）

### 6.1 Secret Store 与 Handle Store

Gateway 维护一个本地存储：

* **SecretStore**：凭证/私钥/API token 等（可对接 OS keychain/Vault/KMS；demo 可先本地加密存储）
* **HandleStore**：任意敏感输出（secret 或敏感文件片段）被封装为 `handle`

**handle 结构：**

* `hid = random_128bit`（不可预测）
* 元数据：

  * `label`：`SSH_KEY / API_TOKEN / PII / CONFIDENTIAL_DOC / ...`
  * `sensitivity`：`LOW/MED/HIGH`
  * `allowed_sinks`：允许被哪些 intent 消费
  * `binding`：绑定 session/user/device（防拷贝外带）
  * `ttl`：过期时间
  * `origin`：产生来源（intent + txid）

**强制点：**

* agent/skill 只能拿到 `hid` + 轻量标签（用于策略），拿不到内容
* hid 外发给攻击者没有意义（绑定+TTL+只在本机解引用）

### 6.2 Handle‑typed 数据流策略（防外泄的关键）

你必须做“信息流约束”，否则恶意 skill 仍可把明文 secret 写进文本外发。

最简单、也最有效的一组规则：

* `SendMessage`、`FetchResource`（出网）**禁止**携带 `sensitivity=HIGH` handle
* `UseCredential` 只能消费特定 label（如 `SSH_KEY` 用于签名，不允许解密吐明文）
* `ReadSecret` 永远只产出 handle，从不产出明文
* `ReadFile` 若路径命中敏感目录/内容命中 secret pattern，则产出 handle；否则产出 public view

### 6.3 Declassifier（只允许“受控披露”）

你不可避免会遇到：用户希望 agent “总结某文档/邮件”。
为保持 Level1 的强保证，你把披露集中到一个显式闸门：

`declassify(handle, purpose, policy) -> public_view`

推荐三档（从强到弱）：

1. **结构化抽取**：只抽日期/金额/标题/实体，不给全文
2. **受控摘要**：长度上限 + 敏感词/模式过滤
3. **用户确认**：HIGH 的 handle 必须确认才 declassify

---

# 7. Oblivious Guardrails：MPC/FSS 策略执行（外包也不泄露隐私）

这是你方案里“顶会 crypto+system”最漂亮的地方：

> **策略可以由外部安全服务执行，但它看不到你的内容/意图，也不知道哪条规则命中；同时它能强制 allow/deny/sanitize。**

## 7.1 两阶段事务：PREVIEW → COMMIT

每次 `mirage.act` 都被包装成事务 `ToolTx`：

### PREVIEW（无副作用，策略检查与净化）

G 构造一个“预执行描述” `PreExecDescriptor`，包含：

* `intent_id`
* `canonical_inputs`（对外发内容/参数做 canonicalization + padding）
* `caller_skill_id`
* `handles_used`（只含 label/sensitivity，不含内容）
* `risk_class`（如 `EGRESS/EXEC/READ_SECRET`）

G 将关键字段秘密共享给 P0/P1：

* `[x]_0` 发 P0
* `[x]_1` 发 P1
  单方只见随机噪声。

P0/P1 在 2PC/MPC 中计算：

* `allow`（共享比特）
* `sanitize_patch`（共享的重写/脱敏补丁）
* `reason_code`（共享/或由 G 自行映射）
* `commit_tag_share`（用于双授权）

### COMMIT（有副作用，必须双授权）

G 重构 `allow=1` 后，生成 commit 请求给执行器 E，并附上：

* `txid`
* `sanitized_args`（G 根据 sanitize_patch 应用到输入）
* `token0`（来自 P0）
* `token1`（来自 P1）

E 必须验证两个 token 均有效才执行。缺一不可 → **不可绕过**。

## 7.2 策略算子集合（你可以在论文里定义为 Policy DSL 的可编译子集）

为了让 MPC 可实现，你定义一个可编译 DSL（而不是任意 Python）：

**原子谓词：**

* `EQ(field, const)`
* `LT/GT(field, threshold)`（限额/长度/次数）
* `IN_SET(hash(field), allowlist)`（域名/收件人/路径前缀）
* `MATCH(payload, pattern_id)`（多模式匹配/regex 子集）
* `RATE_LIMIT(key, N, window)`（状态化计数）

**动作：**

* `DENY`
* `ALLOW`
* `REQUIRE_CONFIRM`
* `REWRITE(field, transform_id)`（强制代理域名、clamp 金额、删除危险参数等）

## 7.3 在哪里用 FSS/DPF？在哪里用通用 MPC？

你可以明确分层（写进论文很清晰）：

### (A) 内容扫描/模式匹配：用 MPC + FSS/DPF 加速 equality

* 外发前检查：是否包含 secrets/PII/危险片段
* 执行前检查：是否出现危险命令模式（即使你没有 RunCommand，也可能有 content_spec 里出现脚本/URL）

Match Quest 给了一个非常直接的先例：在两方计算模型下做快速安全模式匹配，并讨论 FSS/DPF 作为核心原语（尤其 DPF‑based equality）。([petsymposium.org][1])

### (B) 隐私化 allowlist/membership：用 DPF（FSS 特例）

* `IN_SET(hash(domain), allowlist)` 等成员测试
* 你可以用 DPF 来做“私有索引/私有选择”或更 data‑oblivious 的 membership 结构

Google 的 DPF 实现仓库给出了 DPF 的 keygen/eval 语义：两把 key，分别 eval 得到加法份额。([GitHub][3])

### (C) 组合逻辑、阈值比较、sanitize mux：用通用 2PC/MPC

* `AND/OR/NOT`
* `LT/GT`
* “若 deny 则把字段重写成安全常量”的 mux
  这些用通用 MPC 直接做更稳。

## 7.4 保护策略本身与“触发哪条规则”

只要你的策略评估在 MPC 中进行：

* P0 或 P1 单独看不到输入明文
* 单独也看不到匹配结果/触发规则（只见共享态中间值）
  这就是“oblivious guardrail”的核心。

---

# 8. 可保护的内容与意图：你能明确写进论文的保护边界

## 8.1 对 agent/skill（Level1/2）保护什么

**强保护（可以宣称 hard guarantee）：**

* 凭证与密钥类：SSH key、API token、cookie、钱包私钥片段
  → 永远以 handle 形式存在，agent 不见明文
* 系统敏感路径内容：`~/.ssh`, `.env`, 浏览器 profile 等
  → 默认 handle；除非用户确认 declassify
* 底层命令/工具选择/路由细节
  → agent 只见 intent 与统一 observation，不见 shell/curl/SDK 等细节

**受控保护（通过 declassify 定义泄露函数）：**

* 文档/邮件等“业务内容”
  → 你可以让 agent 只见结构化字段/摘要，而不是全文

## 8.2 对 policy servers（Oblivious Guardrails）保护什么

* 外发内容/参数明文（payload、domain、recipient、路径等）
* 哪条规则命中、规则触发的具体位置
* 可选：甚至 intent_id 也可以隐藏（通过 DPF 做 oblivious policy fetch；这是增强项）

---

# 9. 策略设计（具体到可以落地成 demo 配置）

下面给你一组“实战策略”，你可以直接当论文 policy 示例：

## 9.1 能力策略（capability）

* 每个 skill 安装时分配 capability：

  * 允许哪些 intents
  * 允许哪些 handle labels（只读/可用）
  * 允许的 recipient_group / resource_id 范围
* PREVIEW 第一关先做 capability check，不满足直接 DENY。

## 9.2 读取策略（ReadFile / ReadSecret）

* `ReadSecret(name)`：只允许运行在允许的 skill 或用户会话中；输出永远 handle。
* `ReadFile(path_spec)`：

  * path 命中敏感目录 → 输出 handle(HIGH)
  * 内容匹配 secret pattern → 输出 handle(HIGH)
  * 否则输出 public view（长度上限）

## 9.3 外发策略（SendMessage / FetchResource）

* 默认拒绝携带任何 `HIGH` handle
* 外发文本走 MPC‑DLP：扫描是否包含常见 secret 结构（token/私钥头/AKIA…）
* 域名/收件人 allowlist（membership 在 MPC/DPF 中检查）
* rate limit：单位时间外发次数上限；连续失败/拒绝则升级到 NEED_CONFIRM

## 9.4 使用凭证策略（UseCredential）

* `UseCredential(SSH_KEY, SIGN)`：允许（输出签名或“认证成功”）
* `UseCredential(API_TOKEN, EXPORT)`：禁止（防止把 token 明文化导出）
* `UseCredential(COOKIE, AUTH, target=KnownService)`：允许，但必须 target 是 allowlist

## 9.5 sanitize 策略（重写而不是只 deny）

* URL 强制改写走公司代理
* message content 自动脱敏（例如替换疑似 token 为 `[REDACTED]`）
* 限制附件大小、限制 MIME types

---

# 10. Demo 架构与实现建议（你能最快做出来的版本）

### 10.1 工程落地路线（两阶段 demo：先跑通，再加 MPC）

* **Demo‑0（无 MPC）**：本地策略引擎（比如 OPA/自写规则）+ handle + intent 路由
* **Demo‑1（论文核心）**：把“外发前 DLP + allowlist/membership”替换成 P0/P1 的 2PC/MPC（oblivious guardrails）

### 10.2 你可以用的开源项目（核心三件）

1. **MCP 规范与参考实现**：用于把 Gateway 做成 MCP server（只暴露 `act`）。([GitHub][2])
2. **MOTION2NX**：一个通用 hybrid 2PC 框架，README 明确它实现多种被动安全（passive security）的 2PC 协议与转换，适合做你 P0/P1 的 MPC guardrail。([GitHub][4])
3. **Google distributed_point_functions**：现成 DPF（FSS 特例）实现，可用作 equality/membership 或 oblivious selection 的底层库。([GitHub][3])

（如果你要严格对齐“模式匹配在 2PC/FSS 下可行”的学术锚点，Match Quest 的 PoPETs 论文可以作为直接相关工作引用，它本身就讨论 DPF/FSS 并在 2PC 框架上实现。([petsymposium.org][1])）

### 10.3 最小 demo 目录结构（建议）

```
mirage-og/
  agent/
    client.py                     # MCP client: 只会调用 mirage.act
    skills/
      benign_skill.py
      malicious_skill.py           # 尝试 ReadFile(~/.ssh) + SendMessage(exfil)
  gateway/
    mcp_server.py                  # 暴露 mirage.act
    intent_schemas/                # intent schema + validation
    router/                        # intent -> executor plan (不回显底层细节)
    handles/
      store.sqlite                 # handle store (demo)
      classify.py                  # label/sensitivity classifier
      declassify.py                # controlled disclosure
    policy_client/
      share.py                     # secret-share + padding
      preview_commit.py            # PREVIEW/COMMIT orchestration
  executors/
    netexec.py                     # 只接受 sanitized_args + dual tokens
    fsexec.py
    cryptoexec.py
    msgexec.py
  policy/
    server0/
      mpc_runner.cpp               # MOTION2NX 2PC program
      rules/                       # patterns/allowlists (编译到电路)
    server1/
      mpc_runner.cpp
      rules/
  configs/
    allowlists.yaml
    capabilities.yaml
    patterns.yaml
```

### 10.4 Demo 场景（最能打动审稿人的三段）

1. 恶意 skill 读取 `~/.ssh/id_rsa` → 只得到 handle → 外发被拒绝
2. prompt injection 想让 agent 执行 `curl|bash` → 系统没有这种 intent，无法表达
3. 外发文本中包含 token → MPC‑DLP 命中但 policy servers 看不到明文，只返回 deny

---

# 11. 你可以在论文里怎么“写得很硬”

### 11.1 形式化泄露函数

* agent view 只包含：intent_id、constraints、Observation（统一）、handles（随机 id + 标签）
* secret 明文只通过 `declassify` 的泄露函数 (L(\cdot)) 输出

### 11.2 关键性质（可以写成 theorem/claim）

* **Secret Myopia**：对所有 `HIGH` label 的对象，agent 无法获得明文（除非显式 declassify）。
* **Command/Tool Opacity**：agent 无法直接指定或观察到底层命令与工具选择（只见 intent 与统一 observation）。
* **Oblivious Guardrail Privacy**：任一策略服务器单独无法区分两条具有相同长度/公共参数的输入内容（语义安全由 MPC/FSS 保证），也无法得知规则触发情况。

---

这就是一份“Level1 + Level2 + Oblivious Guardrails”一体化方案：

* **系统上**：通过 Intent API + 执行器双授权，把不可信 agent/skill 变成“只能提议、不能掌控细节”的实体；
* **数据上**：通过 sealed handles 把敏感内容从语义上隔离出 agent 的可见域；
* **密码学上**：通过两方不合谋的 MPC/FSS guardrails，让策略检查既强制、又不泄露给外包安全服务/云侧节点。

[1]: https://petsymposium.org/popets/2025/popets-2025-0132.pdf?utm_source=chatgpt.com "Match Quest: Fast and Secure Pattern Matching"
[2]: https://github.com/modelcontextprotocol/modelcontextprotocol?utm_source=chatgpt.com "Specification and documentation for the Model Context ..."
[3]: https://github.com/google/distributed_point_functions?utm_source=chatgpt.com "An Implementation of Incremental Distributed Point ..."
[4]: https://github.com/encryptogroup/MOTION2NX?utm_source=chatgpt.com "encryptogroup/MOTION2NX: A framework for generic ..."
