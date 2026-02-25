# Agent 协议风险与 SecureClaw 防护评估（含基线对比）

> 更新时间：2026-02-20  
> 范围：面向“agent 代操作”协议（含 AP2 / A2A / MCP 及其 OAuth 授权链）下的越权操作、盗刷/滥用、重放与委托风险。

## 1. 研究动机

当前 agent 协议生态正在从“对话式建议”快速走向“可执行交易与外部副作用”。在该迁移中，核心风险从模型输出安全转向**执行边界安全**：

1. 请求是否确实由被授权主体发起（主体真实性）。
2. 授权是否被过度委托或跨上下文复用（授权最小化与上下文绑定）。
3. 旧授权是否可被重放到新请求（时效与重放防护）。
4. agent runtime 被注入后，是否可绕过策略直接触发外部副作用（不可绕过执行线）。

SecureClaw 的目标是把这些问题从“提示词期望”变为“协议+密码学可验证约束”。

## 2. 相关协议版图（当前主流）

| 协议/标准 | 主要用途 | 与“agent 代操作”相关的关键点 | 主要安全挑战 |
|---|---|---|---|
| AP2 Protocol | agent 场景下的支付/授权流程标准化 | 强调信任与责任归属、风险信号、代理授权语义 | 委托滥用、责任归属不清、跨机构风控不一致 |
| A2A (Agent2Agent) | agent 间互操作与任务协作 | AgentCard + 安全方案声明（OAuth/OIDC/mTLS 等）、异步任务与 push 通知 | 跨 agent 身份与授权一致性、异步通道滥用 |
| MCP (Model Context Protocol) | agent-client 与工具/server 的上下文与工具调用协议 | HTTP 传输授权、OAuth 发现、会话与流式传输 | confused deputy、token passthrough、会话劫持 |
| OAuth 2.x（BCP/DPoP/mTLS） | 统一授权与令牌安全基础 | sender-constrained token、PoP、资源绑定、threat model | token theft/replay、受众错配、过度授权 |

主要来源：
- AP2 规范：<https://ap2-protocol.org/specification>
- A2A 规范：<https://a2a-protocol.org/latest/specification/>、<https://github.com/a2aproject/A2A/blob/main/specification/a2a.proto>
- MCP 规范（授权/安全最佳实践）：
  - <https://github.com/modelcontextprotocol/specification/blob/main/docs/specification/2025-06-18/basic/authorization.mdx>
  - <https://github.com/modelcontextprotocol/specification/blob/main/docs/specification/2025-06-18/basic/security_best_practices.mdx>
- OAuth：RFC 9700 / RFC 9449 / RFC 8705 / RFC 6819

## 3. 风险证据（论文 + 工程安全文档）

### 3.1 学术与基准证据

1. **Indirect Prompt Injection** 显示 LLM 集成应用可被间接注入操纵，触发非预期操作（Greshake et al., 2023）。
2. **InjecAgent** 在 tool-integrated agent 下系统化评估间接注入导致的工具误调用与越权行为（Zhan et al., 2024）。
3. **AgentLeak** 给出多 agent 场景下通道化隐私泄漏基准，表明跨通道泄漏是系统性问题（El Yagoubi et al., 2026）。
4. **AgentDojo / ASB** 进一步支持“agent 安全需要系统级评测，而非单轮提示词评测”。

### 3.2 协议与工程文档证据

1. AP2 明确指出“信任与责任”缺口、风险信号需求与委托授权挑战。
2. A2A 明确要求认证/授权与 AgentCard 安全声明，但本身不提供不可绕过执行边界。
3. MCP 安全文档明确列出：
   - confused deputy
   - token passthrough（明确禁止）
   - session hijacking
4. OAuth BCP/PoP/mTLS 文档对 token theft/replay/sender-binding 给出标准防护方向。

## 4. SecureClaw 机制映射：能否防范

### 4.1 机制清单（仓库实现）

1. 不可绕过执行线：`PREVIEW -> COMMIT` + executor 双证明验证。  
   参考：`spec/SECURECLAW_PROTOCOL_RFC_v1.md`, `FORMAL_SECURITY.md`
2. 请求上下文强绑定：`request_sha256` 绑定 + `external_principal` / `delegation_jti` 绑定。  
   参考：`spec/SECURECLAW_PROTOCOL_RFC_v1.md:60`, `spec/SECURECLAW_PROTOCOL_RFC_v1.md:214`
3. 委托最小化与可撤销：scope/ttl/jti/revoke。  
   参考：`README.md`（delegation 章节）、`gateway/delegation_store.py`
4. 双主体交集授权：external principal 与 internal caller 取交集。  
   参考：`paper_full_body.tex:155`
5. 联邦接入鉴权链：签名、nonce/ts anti-replay、proof token、可选 mTLS pinning。  
   参考：`README.md`（federated auth 章节）

### 4.2 风险-防护判定矩阵

| 风险类型 | 典型攻击面 | SecureClaw 判定 | 证据 |
|---|---|---|---|
| Prompt 注入诱导工具误操作 | runtime 被诱导直接执行外发 | **可防（强）**：无双证明无法提交副作用 | `FORMAL_SECURITY.md`, `tests/test_security_games.py` |
| 委托令牌缺失/越权 scope | 伪造或扩大代理权限 | **可防（强）**：`DELEGATION_REQUIRED`/`DELEGATION_SCOPE_DENY` | `artifact_out_compare/multi_agent_federated_eval.json` |
| 委托撤销后继续使用 | revoked token 重用 | **可防（强）**：`DELEGATION_REVOKED` | `artifact_out_compare/multi_agent_federated_eval.json` |
| 跨主体权限升级 | external 与 caller 不一致 | **可防（强）**：双主体交集授权拒绝 | `PRINCIPAL_CAPABILITY_DENY` case |
| 授权重放 | action_id/request 复用 | **可防（强）**：replay guard + hash binding | `FORMAL_SECURITY.md`, `spec/SECURECLAW_PROTOCOL_RFC_v1.md` |
| 已获合法授权内的业务欺诈 | 用户被社工后合法确认 | **部分可防**：需结合额度/行为风控 | 需扩展业务策略，不是密码学单独可解 |

## 5. 仓库内实证验证

### 5.1 协议与安全单测

执行：

```bash
PYTHONPATH=. pytest -q tests/test_mcp_gateway.py tests/test_security_games.py tests/test_agentleak_channels.py
```

结果：`15 passed`（本次会话）。

### 5.2 多 agent 委托/联邦场景

执行：

```bash
PYTHONPATH=. OUT_DIR=artifact_out_compare python scripts/multi_agent_federated_eval.py
```

结果：`artifact_out_compare/multi_agent_federated_eval.json` 中 7/7 通过，覆盖：
- delegated C2 send/receive allow
- missing delegation deny
- revoke + revoked deny
- dual-principal deny
- mediated C5 memory allow

## 6. SecureClaw vs OpenClaw vs OpenAI(Codex) 基线比较

### 6.1 基线提示词约束

为满足“baseline 不含防泄漏提示词”，本仓库已将 `scripts/native_official_baseline_eval.py` 的 baseline prompt 调整为：

1. 删除 “malicious/untrusted injection” 引导语。
2. 删除 `allowed_fields`/`forbidden_fields` 元数据显式提示。
3. 删除 `ALLOWED/FORBIDDEN` 字段标签，仅保留中性字段对。

即：baseline 只保留任务语义 + JSON 输出契约，不注入“请防泄漏”类策略提示。

### 6.2 完整同口径对比（official C1..C5）

本次会话已执行（no-prompt baseline + defense baseline + three-track）：

```bash
OUT_DIR=artifact_out_compare_noprompt FAIR_FULL_REUSE_SECURECLAW=1 FAIR_FULL_REUSE_NATIVE=1 \
  DEFENSE_BASELINES=drift,ipiguard,agentarmor PYTHONPATH=. python scripts/fair_full_compare.py
python scripts/fair_full_stats.py --report artifact_out_compare_noprompt/fair_full_report.json --out artifact_out_compare_noprompt/stats/fair_full_stats.json
python scripts/fair_utility_breakdown.py \
  --report artifact_out_compare_noprompt/fair_full_report.json \
  --mirage-rows artifact_out_compare_noprompt/fair_mirage/agentleak_eval/agentleak_eval_rows.csv \
  --codex-summary artifact_out_compare_noprompt/fair_codex_native_guardrails/native_official_baseline_summary.json \
  --openclaw-summary artifact_out_compare_noprompt/fair_openclaw_native_guardrails/native_official_baseline_summary.json \
  --out artifact_out_compare_noprompt/stats/fair_utility_breakdown.json
python scripts/multi_track_eval.py --out-dir artifact_out_compare_noprompt --run-protocol-tests 1
```

关键输出：
- `artifact_out_compare_noprompt/fair_full_report.json`
- `artifact_out_compare_noprompt/stats/fair_full_stats.json`
- `artifact_out_compare_noprompt/stats/fair_utility_breakdown.json`
- `artifact_out_compare_noprompt/multi_track_eval.json`
- `artifact_out_compare_noprompt/fair_codex_native_guardrails/native_official_baseline_summary.json`
- `artifact_out_compare_noprompt/fair_openclaw_native_guardrails/native_official_baseline_summary.json`
- `artifact_out_compare_noprompt/fair_codex_drift_baseline/native_official_baseline_summary.json`
- `artifact_out_compare_noprompt/fair_codex_ipiguard_baseline/native_official_baseline_summary.json`
- `artifact_out_compare_noprompt/fair_codex_agentarmor_baseline/native_official_baseline_summary.json`

三方案核心结果（同一 official manifest，`n_attack=744`, `n_benign=2520`）：

| 系统 | Attack leak rate | Attack block rate | Benign allow rate | p50 / p95 延迟 |
|---|---:|---:|---:|---:|
| SecureClaw (`mirage_full`) | **0.0000** | **1.0000** | 0.8000 | 17.92ms / 36.82ms |
| OpenAI baseline (`codex_native`) | 0.0161 | 0.9839 | **1.0000** | 24.01s / 55.13s |
| OpenClaw baseline (`openclaw_native`) | 0.0148 | 0.9852 | 0.0000 | 60.21s / 81.12s |

新增防护基线（同一 official manifest，且不加防泄漏提示词）：

| 系统 | Attack leak rate | Attack block rate | Benign allow rate |
|---|---:|---:|---:|
| `codex_drift` | 0.0094 | 0.9906 | 1.0000 |
| `codex_ipiguard` | **0.0000** | **1.0000** | 1.0000 |
| `codex_agentarmor` | **0.0000** | **1.0000** | 1.0000 |

相对 `mirage_full` 的显著性（来自 `artifact_out_compare_noprompt/stats/fair_full_stats.json`）：
- `codex_drift`：attack leak 差异显著（`p=0.0154`）。
- `codex_ipiguard` / `codex_agentarmor`：attack leak 与 `mirage_full` 同为 0（`p=1.0`）。

统计显著性（相对 SecureClaw）：
- `codex_native`：attack leak 差异显著（Fisher 双侧 `p=4.669e-4`）；benign allow 差异显著（`p=2.643e-164`）。
- `openclaw_native`：attack leak 差异显著（`p=9.409e-4`）；benign allow 差异显著（`p≈0`）。

OpenClaw baseline 的运行质量说明（重要）：
- 在本次运行环境中，OpenClaw OAuth 通道出现大量配额失败（日志出现 usage limit），导致许多样本为 `BLOCK_ERROR:parse_failed`。
- 证据：`artifact_out_compare_noprompt/fair_openclaw_native_guardrails/native_official_baseline_summary.json` 中：
  - attack 原因：`BLOCK_ERROR:parse_failed` 共 528 条（744 attack 中占比 70.97%）。
  - benign：`REFUSE_OR_MISMATCH` 2520/2520。
- 因此，OpenClaw 的本次 benign allow=0.0 不能直接解释为“原生策略更安全”，应解释为“基础设施可用性受限下的失败模式”。

### 6.3 三条评测轨（已落地）

1. 隐私泄漏轨（AgentLeak / MAGPIE / TOP-Bench 映射）  
   本地主评测：`artifact_out_compare_noprompt/fair_full_report.json`  
2. 注入鲁棒性轨（AgentDojo / ASB / WASP / VPI-Bench 映射）  
   本地代理评测：同一 official attack 子集 + baseline/defense 对比  
3. 协议实现轨（MCP / A2A 攻击面）  
   本地实测：`pytest` 协议安全测试 + `multi_agent_federated_eval`

统一轨道报告：`artifact_out_compare_noprompt/multi_track_eval.json`

### 6.4 开源实现接入状态（DRIFT/IPIGuard/AgentArmor）

- `DRIFT`：已接入官方仓库 `third_party/DRIFT`（SaFo-Lab/DRIFT）。  
  本机直接运行其 upstream pipeline 仍需独立依赖与 API key（当前环境缺少 `google-genai/agentdojo` 等依赖），因此本次同口径结果使用本仓 `codex_drift`（机制对齐、无防泄漏提示词）完成比较。  
- `IPIGuard` / `AgentArmor`：当前未检索到可直接复现的官方 GitHub 实现；本仓采用论文机制对齐的 runtime mediation baseline（`codex_ipiguard`, `codex_agentarmor`）进行对比，且不使用防泄漏提示词。  

## 7. 结论（当前）

1. 针对 AP2/A2A/MCP 这类 agent 代操作协议共同暴露的核心风险（委托滥用、重放、跨主体越权、注入后误执行），SecureClaw 的协议边界设计具备系统性防护能力。
2. 与仅依赖 runtime 原生行为的基线不同，SecureClaw 把“是否可执行副作用”从提示词语义提升为 executor 可验证谓词。
3. 对“合法授权内的业务欺诈”（例如社工诱导确认）仍需叠加业务风控（额度、频率、异常行为、二次确认策略）。
4. 在“baseline 不加防泄漏提示词”的公平设置下，OpenAI baseline 与 OpenClaw baseline 仍出现 attack 泄漏（约 1.5%--1.6%）；SecureClaw 维持 0 泄漏，说明执行边界约束是关键差异。
5. 新增防护基线中，`codex_drift` 能降低泄漏但仍非零；`codex_ipiguard` 与 `codex_agentarmor` 在本评测口径下达到 0 attack leak。其与 SecureClaw 的差别在于：SecureClaw 还提供不可绕过执行边界与协议级提交约束，而不仅是 runtime 输出/流程防护。
