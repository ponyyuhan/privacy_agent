下面我把**融合后的 MIRAGE‑OG++**做成了一个**可运行的最小完整项目代码**（选用我自带的 **nanoclaw** 风格极简 agent），包含：

* **Level 1：Secret Myopia**（agent 永远拿不到敏感明文，只拿到 handle）
* **Level 2：Myopic Intent Routing**（agent 只能调用一个高层 `mirage.act(intent_id, …)`，看不到底层工具/命令细节）
* **Oblivious Guardrails（FSS）**：在“外发/外联”前，网关对**两个不合谋的 policy server**做 **FSS‑PIR** 查询，policy server **看不到被检查的 token / recipient / domain**，但仍能提供集中维护的规则库能力
* **Executor（双授权不可绕过）**：外发/外联由独立执行器执行，执行器验证来自两台 policy server 的 **MAC 证明**（fail-closed）
* **MCP**：网关以 MCP stdio server 暴露单一工具 `mirage.act`


---

## 这个 Demo 的安全模型（明确假设）

**参与方**

1. **Agent（nanoclaw）+ skills：不可信**

   * 可以是恶意插件、被 prompt injection 驱动的 agent、或被供应链投毒的 skill。
2. **Gateway：可信（最小 TCB）**

   * 负责：意图路由、handle 存储、最小特权执行、外发前强制 guardrails。
3. **PolicyServer0 / PolicyServer1：诚实但好奇（honest‑but‑curious），且不合谋**

   * 它们维护“集中式规则库数据库”（DLP/allowlist），但**每个 server 单独看不到你在查什么**。

**你能保护什么**

* **对 agent/skill：**

  * 保护用户敏感内容明文（文件、密钥、token、私钥等）——agent 只能拿到 handle（Level 1）
  * 保护底层工具/命令/网络细节（Level 2）——agent 只会“发 intent”，不直接触达 tool
* **对单个 policy server：**

  * 保护用户外发文本中的具体 token（通过 FSS‑PIR 查询）
  * 保护 recipient / domain（同样通过 FSS‑PIR 查询）
  * 也就是说：policy server 能提供“集中规则库”，但**不知道你在检查谁、检查了什么内容片段**

> 注意：此 demo 的网关仍在可信 TCB 内，因此网关能看到明文（符合你要的“把复杂 agent 踢出信任域，只信任小网关”的系统论文路线）。
> 为了对齐 `guide.md` 的“完整版蓝图”，本仓库已经实现了 **PREVIEW→COMMIT + 2PC/MPC commit proofs**：即使网关逻辑被绕过，executor 仍会在 COMMIT 阶段基于两台 policy server 的双证明 fail-closed，并在 executor 内强制应用 `sanitize_patch`。
> 如果你未来还想进一步弱化对 gateway 的信任（例如连 gateway 也不应看到明文/意图），仍需要把更多流程迁移到 MPC（例如更强的 oblivious routing / policy fetch 等）。

---

## 方案对应代码结构（完整工程）

当前仓库目录结构如下（已把 OG++ 移到根目录）：

```
agent/
  nanoclaw_agent.py            # 极简 agent（benign / malicious 两种场景；通过 MCP 调用网关）
  mcp_client.py                # MCP stdio client（demo 用）
  skills/
common/
  canonical.py                 # request_sha256 绑定（PREVIEW->COMMIT）
  sanitize.py                  # sanitize patch 定义与应用
gateway/
  mcp_server.py                # MCP 网关入口：tool = mirage.act
  router.py                    # intent 路由（Level 2 的核心）
  capabilities.yaml            # per-caller capability 配置
  capabilities.py              # capability projection 实现
  handles.py                   # handle store（Level 1 的核心）
  guardrails.py                # Oblivious Guardrails（调用 PIR；两阶段 DLP：4-gram + DFA confirm）
  fss_pir.py                   # PIR client（使用 DPF/FSS，O(log N) keys）
  egress_policy.py             # “完整版蓝图” egress policy engine（PIR + DSL->电路 + MPC PREVIEW->COMMIT）
  executor_client.py           # 调用 executor（提交双授权证据）
  tx_store.py                  # PREVIEW token/tx_id 存储（可选 SQLite 持久化）
  executors/
executor_server/
  server.py                    # Executor：验证 MAC 证明并执行外发/外联（不可绕过）
policy_server/
  server.py                    # Policy Server：POST /pir/query_batch
  db.py                        # bitset DB + DPF-eval(inner_product)
  dfa.py                       # Aho-Corasick DFA builder（confirm stage）
  build_dbs.py                 # 构建 banned_tokens / allow_recipients / allow_domains + DFA block DB
  mpc_engine.py                # MPC evaluator（GMW + Beaver，提供 /mpc/*）
  data/
policy_server_rust/
  ...                          # 可选 Rust 编译后端 policy server（同 API；更高吞吐）
scripts/
  run_all.sh                   # 一键运行
  run_artifact.sh              # paper artifact（一键产出 report.json）
fss/
  dpf.py                       # 高效 FSS/DPF 实现（key size O(log N)）
```

---

## 这里到底哪里用了 FSS / “MPC”？

### 1) 你要的关键：**Oblivious Guardrails 用了 FSS（2‑server FSS‑PIR）**

核心在（已升级为高效 DPF/FSS）：

* `fss/dpf.py`：DPF/FSS keygen + eval
  * 生成两个 DPF key share：`k0, k1`（**O(log N)** 大小）
  * 单个 key share 在计算上不泄露 idx（policy server 看不到你在查哪个 token/recipient/domain）
  * 当前默认使用 **v2 PRG**（单次 SHA‑512 扩展 + seed-bit 输出）以降低常数开销
* `gateway/fss_pir.py`：把 idx 编译成 DPF key share，并通过 `/pir/query_batch` 发给两台 policy server
* `policy_server/db.py`：对本地 bitset DB 做内积（在 GF(2) 上）得到 answer share

这就是典型的 **2‑server PIR with DPF/FSS** 的“点函数查询”骨架（本仓库已是 DPF 版本）。

### 2) 这份 repo 现在已经实现了“通用 MPC policy engine + PREVIEW→COMMIT”

为了对齐 `guide.md` 的“完整版蓝图”，当前实现新增了：

* **策略语言/DSL**：`policy_server/policy.yaml:policy_programs.egress_v1`，用 `& | ^ ~` 的布尔表达式描述 egress 策略与 sanitize patch 位。
* **DSL→电路编译链**：网关 `gateway/egress_policy.py` 把 DSL 编译成布尔电路（gate list）。
* **2PC/MPC 执行**：两台 policy server 通过 `/mpc/init`, `/mpc/and_mask`, `/mpc/and_finish`, `/mpc/finalize` 执行 GMW（XOR-share）+ Beaver triples（AND gate）。
* **PREVIEW→COMMIT**：PREVIEW 产出 `tx_id` 与 `commit proof`（两台 server 的 MAC 证明），COMMIT 时 executor 验证双证据并在 executor 内应用 `sanitize_patch`（fail-closed）。
* **intent shadowing / capability projection**：通过 secret-shared one-hot intent bits + 固定形状的 PIR 查询，让单个 policy server 更难从“请求形状/DB 选择”推断 `intent_id`；caller 能力由 `gateway/capabilities.yaml` 投影为 MPC 输入位。

---

## Demo 里实现的策略（你能直接在论文里写“策略语言雏形”）

目前实现了三类“外发/外联前的强制策略”：

1. **Handle‑Flow（强 IFC）**

* `HIGH` 级别 handle **禁止流向** `SendMessage`（外发 sink）
* 见：`gateway/guardrails.py::_contains_high_handle`

2. **Recipient Allowlist（oblivious）**

* recipient 被 hash 到 domain `[0..N)`
* 用 FSS‑PIR 查询 `allow_recipients` bitset
* 不允许则 block
* 见：`gateway/guardrails.py::check_egress_message`

3. **DLP Token Blocklist（oblivious）**

* 把外发文本切成 char 4‑gram 作为**第一阶段粗过滤**（快，但可能有 bitset 碰撞误报）
* 每个 4‑gram hash 到 `[0..N)`
* 用 FSS‑PIR 查询 `banned_tokens` bitset
* 若命中：
  * `DLP_MODE=fourgram`：直接 block（更快，但可能误报）
  * `DLP_MODE=dfa`：走**第二阶段 confirm**：oblivious DFA（Aho‑Corasick）扫描，消除粗过滤碰撞误报
* 见：`gateway/guardrails.py::fourgram_indices` + `check_egress_message`

（另有 `FetchResource` 的 domain allowlist）

---

## 一键跑起来（你本地就能复现）

解压后，在项目根目录：

```bash
pip install -r requirements.txt
bash scripts/run_all.sh
```

如果你要跑 **paper artifact**（测试 + benchmark + 端到端 + `report.json`），用：

```bash
bash scripts/run_artifact.sh
```

输出在 `artifact_out/`。
其中会额外产出：

* `bench_e2e.json`：端到端吞吐（短跑）
* `audit.jsonl`：网关审计日志（JSONL）

它会自动：

* build bitset DB
* 起两个 policy server（随机空闲端口）
* 起 executor（验证双授权 MAC 证明）
* 运行 benign 和 malicious 两个 agent 场景（agent 会启动网关 MCP stdio server）

如果你要启用 **Rust 编译后端 policy server**（更高吞吐），可直接：

```bash
POLICY_BACKEND=rust bash scripts/run_all.sh
```

你会看到：

* benign：允许发送到 `alice@example.com`
* malicious：

	  * 读私钥：只拿到 handle（看不到明文）
	  * 试图把 handle 外发：被 `HIGH_HANDLE_BLOCKED`
	  * 试图夹带 `AKIA...` 外发给 allowlisted recipient：
        * PREVIEW 返回 `REQUIRE_CONFIRM` + `sanitize_patch=REDACT` + `tx_id`
        * 随后带 `tx_id` 且 `constraints.user_confirm=true` 的 COMMIT 会放行，但 executor 会强制 redaction 后再“发送”（demo stub）

---

## 接入真实 Agent Runtime（NanoClaw / Claude Agent SDK）

上面用的是 **scripted agent**（不调用任何模型），确保 artifact 可重复。

如果你需要“真实 agent”的接入演示：本仓库提供了一个 **Claude Agent SDK（NanoClaw 使用的 runtime）** 的 MCP runner，通过 MCP 调用网关工具（`act`/`mirage.act`）：

```bash
export ANTHROPIC_API_KEY="..."
bash scripts/run_nanoclaw.sh
```

它会启动两台 policy server，并用 Claude Agent SDK 驱动工具调用，跑一遍 benign/malicious 的相同攻击路径，作为“真实 agents 已接入”的证据。

---

## 你接下来怎么把它“升级到论文级别”

这份 demo 是你论文里“系统骨架+可跑 artifact”的起点。要冲顶会，我建议你下一步按这条路线增强（不用改主架构）：

1. **把 bitset token DLP → 更强的 oblivious 模式匹配**

   * 替换 `banned_tokens` 为“多模式/多串匹配”的数据库或自动机结构
   * 你可以从“4‑gram”逐步替换为：

     * keyword set（更干净的 threat model）
     * 再到 regex/NFA/DFA（MatchQuest 类）

2. **把 DPF/FSS 的 demo 实现 → 更高性能实现**

   * 当前实现是 Python（便于完整落地与写作）；但已使用更快的 v2 PRG（SHA‑512 + seed-bit 输出）来降低常数开销
   * 论文/评测版本可以替换为更高效的 DPF/FSS 库与向量化内核（架构不变）

3. **做“policy bundle oblivious selection”（隐藏 intent 类别）**

   * 现在 policy server 只看到 `db_name`（banned_tokens/allow_recipients/allow_domains），还不能完全隐藏意图类别
   * 下一步：让 gateway 用 FSS 私有选择“某个 policy profile”（不同组织/不同 app 的规则集）

如果你愿意，我可以在这个 repo 的基础上继续给你补：

* MCP JSON‑RPC 层（本仓库已实现：`gateway/mcp_server.py` + `agent/mcp_client.py`）
* policy bundle + intent taxonomy（6–10 intents）
* 更严格的 handle IFC lattice（LOW/MED/HIGH + declassify）
* 性能 profiling 脚本（PIR 次数/延迟/吞吐）

你先把这个 zip 跑通，然后告诉我你想把下一步主贡献押在：

* “更强 oblivious guardrails（regex/automata）”
* 还是 “intent/profile 的隐私（选择/路由隐藏）”
  我就沿着你要冲的那条线继续把代码与论文叙事一起加厚。
