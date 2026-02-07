# MIRAGE-OG++: 有效性与隐私证明（Demo 版）

本文档是本仓库可运行 demo 的“证明/证据”配套材料，用于论文/报告中的有效性与安全性说明。

## 我们证明什么（Demo 范围内）

1. **Level 1（Secret Myopia）**：不可信 agent/skill 永远拿不到敏感明文（密钥/token/敏感文件内容），只能拿到 sealed handle（不透明句柄）。
2. **Level 2（Myopic Intent Routing）**：不可信 agent/skill 不能直接调用底层工具原语（shell/http/file 等），只能向网关提交高层 `intent_id`。
3. **Oblivious Guardrails（2-server PIR via DPF-based FSS）**：在外发/外联前，网关对两个“不合谋”的 policy server 执行隐私保护检查，使得**任意单个 policy server 看不到被检查的 recipient/domain/token**。
4. **双授权不可绕过（Executor + MAC proofs）**：外发/外联动作由独立执行器完成，执行器要求来自两台 policy server 的 **MAC 证明**（绑定 `action_id` + 请求/响应摘要），缺一不可，且可复核 DLP/DFA 的判定结果。

显式假设：

- Agent + skills：**不可信**（可恶意/可被注入/可被供应链投毒）。
- Gateway：**可信最小 TCB**。
- PolicyServer0 / PolicyServer1：**诚实但好奇**（honest-but-curious）且**不合谋**（至少一方不与另一方合谋）。

## 端到端复现实验

在仓库根目录运行：

```bash
python main.py demo
```

这会跑一个**无外部依赖**的 scripted agent（不调用任何模型），用于保证 artifact 可复现。

Artifact 一键跑（包含 JSON 报告）：

```bash
python main.py artifact
```

如果你需要“真实 agent runtime”的接入演示（NanoClaw 使用的 Claude Agent SDK，通过 MCP 调用 `mirage.act`），可运行：

```bash
export ANTHROPIC_API_KEY="..."
bash scripts/run_nanoclaw.sh
```

你应该看到（reason_code 可能略有不同，但语义一致）：

- benign：`SendMessage` 对 `alice@example.com` 放行。
- malicious：
  - `ReadFile(~/.ssh/id_rsa)` 只返回 `handle`（不返回私钥明文；本 demo 会把该路径映射到 repo 内置的假 key 文件）。
  - `Declassify(handle)` 未提供 `user_confirm` 时被拒绝（`REQUIRE_CONFIRM`）。
  - 携带 `HIGH` handle 的 `SendMessage` 被拒绝（`HIGH_HANDLE_BLOCKED`）。
  - 外发文本包含 AWS-like token 子串时被拒绝（`DLP_BLOCKED`）。

如果你需要使用 **OpenAI OAuth** 的“真实 agent”验证（通过 OpenClaw 的 `openai-codex` provider），可运行：

```bash
bash scripts/setup_openclaw.sh

# 使用 Codex CLI 完成一次 OAuth 登录后（生成 ~/.codex/auth.json），将 token 导入 OpenClaw：
OPENCLAW_STATE_DIR="artifact_out/openclaw_state" \
  python scripts/import_codex_oauth_to_openclaw.py

# 运行 benign + malicious（输出 JSON 在 artifact_out/）
bash scripts/run_openclaw.sh
```

你应该看到：

- benign：`FetchResource(domain=api.github.com)` 放行。
- malicious：
  - `ReadFile(~/.ssh/id_rsa)` 只返回 `handle`（不返回明文；本 demo 会把该路径映射到 repo 内置的假 key 文件）。
  - `Declassify(handle)` 未提供 `user_confirm` 时被拒绝（`REQUIRE_CONFIRM`）。
  - `CheckMessagePolicy(..., artifacts=[handle], recipient=evil@attacker.invalid)` 被拒绝（`HIGH_HANDLE_BLOCKED`）。
  - `CheckMessagePolicy(recipient=alice@example.com, text contains "AKIA...")` 被拒绝（`DLP_BLOCKED`）。

## Level 1：为什么 Sealed Handles 能阻止“明文泄露给 Agent”

网关对敏感读操作做分类并在 TCB 内保存“值”，对外只返回 handle：

- `gateway/executors/fsexec.py`：敏感文件返回 `HIGH` handle（artifact），不返回 plaintext。
- `gateway/executors/cryptoexec.py`：`ReadSecret` 只 mint capability handle；`UseCredential` 在可信执行器内生成派生结果（如签名），不泄露 secret 本体。

对 agent 的 `mirage.act` 调用返回里永远不序列化 handle 的 `value`。

## Level 2：为什么 Agent 无法选择底层工具/命令

系统只暴露一个 MCP 工具 `mirage.act` 与一个路由器（`gateway/router.py`）：

- intent 是 allowlist（固定集合），不存在 “RunCommand(cmd)” 或 “Fetch(url)” 这类任意低层原语；
- agent 只能表达意图，不直接触达 executor 的细节。

## Oblivious Guardrails：2-Server PIR（DPF-based FSS）的正确性与隐私证明要点

### 构造（DPF / FSS-PIR）

网关要查询某个 bitset 数据库 `DB` 的 `DB[idx]`，会生成一对 DPF key share（FSS key）并分别发给两台 policy server：

- `k0` 发给 `PolicyServer0`
- `k1` 发给 `PolicyServer1`

满足对任意 `x`：

`Eval(k0, x) XOR Eval(k1, x) = 1  当且仅当 x == idx；否则为 0`

两台 policy server 用自己的 key share 在本地计算 answer share：

`ans_s = XOR_x ( DB[x] & Eval(k_s, x) )`

实现位置：

- DPF/FSS：`fss/dpf.py`
  - 当前默认使用 **v2**（单次 SHA-512 扩展 + seed-bit 输出）以降低常数开销；仍保留 v1 decode 兼容。
- 网关 PIR client：`gateway/fss_pir.py`
- policy server 端 query：`policy_server/db.py` + `policy_server/server.py`

网关重构：

`ans = ans_0 XOR ans_1`

并用于 allowlist / DLP guardrails 判定（`gateway/guardrails.py`）。

### 正确性（Correctness）

由定义，`Eval(k0, x) XOR Eval(k1, x)` 是 idx 位置为 1 的指示函数 `1_{x==idx}`。
因此：

- `ans_0 XOR ans_1`
- `= XOR_x ( DB[x] & (Eval(k0, x) XOR Eval(k1, x)) )`
- `= XOR_x ( DB[x] & 1_{x==idx} )`
- `= DB[idx]`

### 单点隐私（Single-Server Query Privacy，计算安全）

任意单个 policy server 只看到它的一份 DPF key share（以及它自己数据库上的确定性计算结果 `ans_s`）。
在标准 DPF/FSS 安全性假设下（基于 PRG 安全），单个 key share 在计算上无法区分“查询了哪个 idx”，因此：

**PolicyServer0 或 PolicyServer1 的单点视图不泄露被检查的 recipient/domain/token（idx）**。

只有当两台 policy server 合谋并合并 key share 时，才可能恢复查询目标。

## Demo 局限性（诚实说明）

- 当前实现为 Python 版本的 DPF/FSS（key 为 **O(log N)** 字节；默认 v2 使用单次 SHA-512 扩展 + seed-bit 输出以降低常数开销），但 policy server 的 bitset 内积求值仍是 **O(N)** 的朴素实现；生产/高性能版本应替换为向量化/编译实现。
- 本仓库提供了一个可选的 **Rust 编译后端 policy server**（`policy_server_rust/`，API 与 Python 版一致），用于展示“同一协议骨架下，用编译实现显著降低 O(N) 常数”的路径。
- DLP 采用两阶段：第一阶段 **char-4gram + bitset**（快但可能碰撞），可选第二阶段 **oblivious DFA confirm（Aho-Corasick）** 消除碰撞误报（见 `policy_server/dfa.py` 与 `gateway/guardrails.py`）；更一般的 regex/NFA 仍可在此骨架上替换。
- 将 token/recipient/domain hash 到固定域会有 collision（可能带来误报/漏报）；可增大 `FSS_DOMAIN_SIZE` 或换更强结构。
