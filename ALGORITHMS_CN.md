# MIRAGE-OG++：算法与协议（Artifact，中文）

本文档提炼并形式化本仓库中**可写入论文**的算法/协议贡献点。它刻意**不把标准密码学原语本身当作贡献**（例如 DPF/DCF/FSS、GMW/Beaver triples），而聚焦于 MIRAGE-OG++ 在系统/协议/编译层面的新设计：

1. 证明携带（proof-carrying）的不可绕过副作用提交（双授权 token）。
2. Intent shadowing 的统一策略程序编译（多意图共用一套常形状 program）。
3. Oblivious bundle layout + 索引平移（隐藏逻辑 DB 名/意图类别路由）。
4. PIR 侧流量形状隐藏（microbatch mixing + padding + 可选 cover traffic）。
5. MPC 的 AND-depth 分轮调度与 batch 执行（把交互从 O(#AND) 形态降到 O(depth) 形态）。
6. 明确的 leakage model（允许泄露函数 L(.)）作为安全边界。

下述算法均有对应实现与**可执行验证**（单测/安全游戏脚本）；见“验证”一节的命令与文件映射。

---

## 0. 系统模型

### 实体

- G：网关（policy client）。构造隐私保护查询、收集证明并向执行端转发副作用请求。
- P0, P1：两个策略服务器。持有策略数据库并执行策略逻辑，返回份额（shares）与 MAC 证明。
- E：执行器（effect gate）。唯一允许提交外部副作用的组件（发消息/抓取/ webhook / 启用 skill）。

### 威胁模型（Artifact 范围）

- 对手可控制 prompt、skill、以及运行时输入；也可能控制网关进程并尝试绕过策略。
- E 受信任并持有用于验证 P0/P1 的 MAC 验证密钥。
- P0/P1 在正确性上假设诚实执行。
- 隐私目标为“两服务器 PIR 的单服务器隐私”：假设 **P0 与 P1 不串通**。
- 流量形状隐藏是部分实现；允许泄露由 `LEAKAGE_MODEL.md` 中的 leakage 函数 L(.) 明确给出。

---

## 1. 记号与数据结构

### 1.1 XOR 共享（比特）

对任意比特 x ∈ {0,1}，使用 XOR 共享表示为 (x0, x1)，满足：

- x = x0 XOR x1

每个服务器 Pi 仅看到其份额 xi。

### 1.2 上下文绑定（Context Binding）

所有授权都绑定在不可变上下文三元组上：

- action_id：由 G 生成的动作标识（每次 action 唯一）。
- program_id：策略程序标识（例如 `policy_unified_v1`）。
- request_sha256：对规范化请求（intent_id, caller, session, inputs）求哈希得到的绑定值。

代码中 request_sha256 由 `common/canonical.py:request_sha256_v1` 计算。

### 1.3 MAC 证明（Proof）

每个策略服务器 Pi 持有 MAC 密钥 Ki（本 artifact 使用 HMAC-SHA256）。
当 Pi 对某个 action_id 返回结果时，会附带：

- 答案份额（PIR bit shares、MPC outputs shares）。
- 证明对象 proof_i = payload_i || mac_b64，其中：
  - mac_b64 = HMAC(Ki, CanonicalJSON(payload_i))
  - CanonicalJSON 采用稳定序列化（排序 key、固定分隔符；见 executor verifier）。

本 artifact 使用两类证明：

1. Signed PIR bit-batch proof（kind="bit"）：
   - 绑定 (action_id, db, keys_sha256, resp_sha256, ts, kid, server_id)。
2. Signed MPC commit proof（kind="commit"）：
   - 绑定 (action_id, program_id, request_sha256, outputs, commit_tag_share_b64, ts, kid, server_id)。

执行端验证逻辑位于 `executor_server/server.py`。

---

## 2. 算法 A1：双 MAC 的 Proof-Carrying Commit（不可绕过副作用 / NBE）

### 目标

保证任何外部副作用的提交都必须携带来自 P0 与 P1 的**双份有效、及时、且上下文绑定**的授权证明。

### 接口

E 的 effect endpoint 输入：

- effect 请求 req（send message / fetch / webhook / skill install）。
- action_id, caller, session。
- commit 证据：{policy0: proof0, policy1: proof1}，其中每个 proof 的 kind="commit"。

输出：

- OK（并应用 sanitize patch 后提交副作用）或 DENY（带 reason code）。

### 协议

算法 A1.GatewayPreviewCommit（高层描述）：

1. G 计算 request_sha256 := H(canonical(intent_id, caller, session, inputs))。
2. G 运行隐私保护策略评估（PIR 得到特征；MPC 得到策略程序输出）。
3. P0 与 P1 分别返回 commit proof（MAC 签名），绑定到 (action_id, program_id, request_sha256)。
4. G 将 (req, action_id, commit={policy0:..., policy1:...}) 发送给 E。

算法 A1.ExecutorVerifyCommit：

1. E 从 req 本地重新计算 request_sha256（同 canonical 规则）。
2. 分别验证两份 proof：
   - 字段与 kind 检查、freshness 检查（|now - ts| <= TTL）；
   - (action_id, program_id, request_sha256) 必须完全一致；
   - 用对应 server_id 与 kid 选择验证密钥，验证 MAC。
3. 将 P0/P1 的输出份额 XOR 复原得到明文 outputs。
4. 执行判定：
   - allow_pre=0 则 DENY；
   - need_confirm=1 且缺少 user_confirm 则 DENY（可返回 preview）。
5. 应用 sanitize patch（若有）并提交副作用。

### 正确性

若 P0/P1 诚实且对同一上下文 (action_id, program_id, request_sha256) 出具证明，则 E 的接受/拒绝与输出复原结果一致。

### 安全主张（NBE）

若对手在未获得双份有效 commit proof 的情况下让 E 接受，则必须至少破坏以下之一：

- 在未知 Ki 下伪造 MAC；
- 破坏 request_sha256 的绑定（例如构造碰撞使不同请求共享同一 request_sha256）。

形式化安全游戏与命题见 `FORMAL_SECURITY.md`。

### 实现映射

- commit proof 生成：`policy_server/server.py:/mpc/finalize` 与 `policy_server_rust/src/main.rs`（MPC finalize）。
- commit proof 验证：`executor_server/server.py:_verify_commit_evidence`。
- 可执行检查：`scripts/security_game_nbe_check.py`；单测 `tests/test_security_games.py`。

---

## 3. 算法 A2：Oblivious Bundle Layout 与索引平移（隐藏逻辑 DB 名）

### 目标

隐藏被查询的逻辑策略表（如 allow_recipients 与 banned_tokens），做法是：始终查询同一物理 DB（`policy_bundle`），并通过索引平移把不同逻辑表映射到不相交的子区间。

### Bundle 参数

设：

- N_base：逻辑基域大小（2 的幂）。
- stride：两个 bundle 之间的跨度（>= 单个 bundle 的子区间总跨度）。
- bundle_id：选取的 bundle 实例（如 default/prod/expA）。
- offset[L]：每个逻辑 DB 名 L 对应的起始偏移。
- N_bundle：物理 bundle DB 的域大小（2 的幂）。

这些参数由 policy server 的 `/meta` 暴露给网关，并由建库脚本固化到磁盘布局中。

### 映射函数

算法 A2.ShiftIndex

输入：
- L：逻辑 DB 名
- i：原始索引 i ∈ [0, N_base)

输出：
- j：平移后索引 j ∈ [0, N_bundle)

定义：

1. base := bundle_id * stride
2. j := base + offset[L] + (i mod N_base)

### 正确性

若物理 DB 构造满足：对每个逻辑表 L，物理位置 base + offset[L] + i 的 bit 等于逻辑 bit DB_L[i]，则 ShiftIndex 保持 membership 语义：

- PIR(policy_bundle, ShiftIndex(L,i)) 复原后等于 DB_L[i]。

### 隐私/泄露

在单服务器视角中，db_name 恒为 `policy_bundle`，不直接泄露 L。剩余泄露（domain_size、batch size、时序等）由 `LEAKAGE_MODEL.md` 中的 L(.) 明确界定。

### 实现映射

- 平移：`gateway/policy_unified.py:_bundle_shift`
- meta 加载：`gateway/policy_unified.py:_load_bundle_cfg` 与 policy server `/meta`
- bundle 建库：`policy_server/build_dbs.py`

---

## 4. 算法 A3：统一常形状 PIR 查询计划（固定 key 数）

### 目标

对每个 action（send/fetch/webhook/skill-install）都发起**一次** signed PIR bit-batch 查询，且对策略服务器而言：

- 物理 db 恒定（`policy_bundle`）
- DPF key 数恒定（固定 K）

从而降低“逻辑表选择/意图类别”的直接泄露，并使执行端可复核 PIR transcript。

### 参数

- T：token slots 上限（常数）。
- D：skill domain slots 上限（常数）。
- N_base：逻辑基域大小。
- bundle 参数：见算法 A2。

### 计划构造

算法 A3.BuildFixedShapePlan

输入：
- recipient, domain, text
- skill_domains, skill_md
- action_id
- T, D, N_base, bundle 参数

输出：
- idxs：长度为 K 的 shifted indices 列表，其中 K = 2 + T + D + T
- evidence：signed PIR transcript（两台服务器 MAC proof）
- features：(recipient_ok, domain_ok, dlp_hit, ioc_hit, install_hit)

步骤：

1. 将 skill_domains padding/截断到长度恰为 D（不足用 dummy domain 填充）。
2. 从 skill_md 提取 install tokens，并 padding/截断到长度恰为 T（不足用 dummy token 填充）。
3. 在基域 N_base 上计算 raw indices：
   - rec_raw := StableIndex(recipient, N_base)
   - dom_raw := StableIndex(domain, N_base)
   - tok_raw[0..T-1] := FourgramIndices(text, N_base, T)
   - ioc_raw[0..D-1] := StableIndex(skill_domains[k], N_base)
   - inst_raw[0..T-1] := StableIndex(install_tokens[k], N_base)
4. 对每个 raw index 使用算法 A2 平移到 bundle 域：
   - idxs :=
     - ShiftIndex("allow_recipients", rec_raw)
     - ShiftIndex("allow_domains", dom_raw)
     - for k in 0..T-1: ShiftIndex("banned_tokens", tok_raw[k])
     - for k in 0..D-1: ShiftIndex("ioc_domains", ioc_raw[k])
     - for k in 0..T-1: ShiftIndex("banned_install_tokens", inst_raw[k])
5. 对 bundle 物理 DB 发起一次 signed PIR 查询：
   - bits[0..K-1], ev := SignedPIRBitBatch(db="policy_bundle", idxs, action_id, domain_size=N_bundle)
6. 从固定位置复原特征：
   - recipient_ok := bits[0]
   - domain_ok := bits[1]
   - dlp_hit := OR(bits[2 : 2+T])
   - ioc_hit := OR(bits[2+T : 2+T+D])
   - install_hit := OR(bits[2+T+D : 2+T+D+T])

### 正确性

依赖两服务器 PIR 重构正确性：每个 bits[k] 对应其逻辑表 membership bit；OR 聚合得到的特征等于“是否命中任一条规则”的语义。

### 常形状性质

K = 2 + 2T + D 仅由 (T,D) 决定，与以下无关：

- 文本长度、skill_md 长度
- 真实 domain 数量
- 选择的 intent 类别

结合算法 A2，可使策略服务器侧观察到的 db_name 与 key 数都为常量（在给定配置下）。

### 实现映射

- 计划与特征提取：`gateway/policy_unified.py:_pir_unified_plan`
- Stable/fourgram 索引：`gateway/guardrails.py:stable_idx`，`gateway/guardrails.py:fourgram_indices`
- signed PIR：`gateway/fss_pir.py:query_bits_signed`

---

## 5. 算法 A4：PIR Microbatch Mixing + Padding + 可选 Cover Traffic

### 目标

降低策略服务器可见的流量形状泄露：

- 将多个 signed PIR 子请求打包成每台服务器一次 HTTP 调用；
- 每个 tick padding 到固定子请求数 pad_to；
- 可选在空闲时仍发送 dummy-only 批次作为 cover traffic。

该机制刻意限定在 **signed bit-batch PIR** 这一狭窄接口上，以便直接包裹算法 A3。

### 参数（Mixer 配置）

- interval_ms：flush 周期（tick 间隔）。
- pad_to：每个 tick 发送的子请求数（真实 + dummy）。
- fixed_n_keys：每个子请求携带的 DPF key 数（必须是常数，来自 A3 的常形状）。
- db_name：物理 DB 名（一般为 `policy_bundle`）。
- domain_size：bundle 域大小 N_bundle。
- cover_traffic：空闲时是否仍发送 dummy-only 批次。

### 协议

算法 A4.MixAndSendSignedPIR

状态：
- 队列 Q：待发送的子请求。
- 每个子请求包含：
  - action_id
  - dpf_keys_b64（该服务器的 key share，长度固定为 fixed_n_keys）

每个 tick（每 interval_ms）：

1. 从 Q 弹出最多 pad_to 个真实子请求。
2. 若 cover_traffic 开启且数量不足 pad_to，则补齐 dummy 子请求：
   - dummy action_id 随机；
   - dummy DPF key 为随机索引生成（在 DPF 安全性下与真实 key 不可区分）。
3. 分别向 P0 与 P1 发送一次 HTTP：
   - POST `/pir/query_batch_multi_signed`
   - payload: {db: db_name, requests: [{action_id, dpf_keys_b64}, ...]}，requests 长度恰为 pad_to
4. 每台服务器返回每个子请求的 (ans_shares, proof)。对每个真实 action_id：
   - XOR 复原 bits
   - 返回包含两台服务器 proof 的组合 transcript

### 正确性

`/pir/query_batch_multi_signed` 等价于对每个子请求依次调用 `/pir/query_batch_signed` 并分别 MAC 签名响应 payload。
因此每个真实子请求的重构结果与直接 signed 查询一致。

### 隐私/泄露

在 cover_traffic+padding 打开时，策略服务器在每个 tick 看到固定子请求数与固定 key 数。剩余泄露由 `LEAKAGE_MODEL.md` 的 L(.) 给出（例如 tick 间隔、padding 配置等）。

### 实现映射

- Mixer：`gateway/fss_pir.py:_SignedBitBatchMixer`，`gateway/fss_pir.py:MixedPirClient`
- Python 端点：`policy_server/server.py:/pir/query_batch_multi_signed`
- Rust 端点：`policy_server_rust/src/main.rs`（同名 route）

---

## 5.1 算法 A4b：稀疏 Bitset 的 PIR 求值（预计算 1-bit 索引）

### 目标

把 PIR 服务器侧的求值路径做得更接近生产可用：当策略数据库以 bitset 表示但 **1-bit 很稀疏** 时（allowlist/IOC/安装标记通常如此），
可以用 `O(|S| log N)` 的点求值替代 `O(N)` 的全域展开。

bitset DB 的 PIR 答案份额为：

- `ans_share = XOR_i (DB[i] & f_party(i))`。

若 `DB[i]=1` 仅在集合 `S` 上成立，则：

- `ans_share = XOR_{i in S} f_party(i)`。

### 协议（服务器侧内核）

算法 A4b.PrecomputeOnes

输入：
- bitset DB `DB`（域大小 `N`）

输出：
- `S = { i : DB[i] = 1 }` 的有序整数列表

算法 A4b.SparseParityShare

输入：
- DPF key share `k_party`
- 预计算的 `S`

输出：
- `ans_share`（比特）

步骤：
1. `ans_share <- 0`
2. 对每个 `i in S`：
   - `ans_share <- ans_share XOR DPFEvalPoint(k_party, i)`
3. 返回 `ans_share`

### 正确性

由代数恒等式直接得到：因为对所有 `i not in S` 有 `DB[i]=0`，所以内积的 XOR 求和可化简为仅在 `S` 上求 XOR。

### 泄露

这只是策略服务器内部的求值策略，不会新增 transcript 字段；任何潜在的时序差异仍被统一纳入系统显式 leakage 边界 `L(.)`。

### 实现映射

- 预计算 set-bit 索引：
  - Python：`policy_server/db.py:BitsetDB.load`（`self._ones`）
  - Rust：`policy_server_rust/src/main.rs:bitset_ones`（`bitset_ones` 状态）
- 稀疏 parity share：
  - Python：`fss/dpf.py:eval_dpf_pir_parity_share_sparse`
  - Rust：`policy_server_rust/src/main.rs:eval_parity_share_sparse`
- 验证：
  - `tests/test_ogpp.py:test_sparse_parity_share_matches_dense`

---

## 6. 算法 A5：AND-depth 分轮调度 + Batch MPC 执行

### 目标

对包含大量 AND gate 的布尔策略程序，使用分轮批处理把交互“按 AND-depth”组织起来：

- 不是每个 AND gate 一轮交互（O(#AND)）
- 而是每层 AND-depth 一轮交互（O(depth)）

这对于“多意图统一常形状程序”非常关键，否则交互/开销会随 AND gate 数爆炸。

### 电路模型

电路由：

- W 条 wire（XOR 共享比特）。
- gate 列表：XOR/NOT/CONST/AND。
- XOR/NOT/CONST 可本地评估；AND 通过 Beaver triple 交互评估。

### AND-depth 与 rounds

算法 A5.ComputeAndRounds

定义每条 wire 的 and_depth：

- 输入 wire 深度为 0
- CONST 输出深度为 0
- XOR/NOT 输出深度为 max(depth(inputs))
- AND 输出深度为 max(depth(inputs)) + 1

按 AND gate 输出深度 d=1..Dmax 分组：

- rounds[d] = {所有输出深度为 d 的 AND gate 索引}

性质：round d 中任意 AND gate 的输入 wire 深度均 <= d-1，因此在执行 round d 前其输入应当已就绪。

### 分轮批处理执行

算法 A5.RoundBatchedMPC

1. G 向 P0/P1 发送 `/mpc/init`（电路相同、输入份额不同）。
2. 对每个 round：
   - 对 round 内每个 AND gate，G 在明文采样 Beaver triple (a,b,c=a AND b) 并 XOR 共享给两台服务器。
   - G 调用 `/mpc/and_mask_batch` 发送 triple shares，收集每个 gate 的 (d_share,e_share)。
   - G 将两台服务器份额 XOR 打开得到 (d,e)，再用 `/mpc/and_finish_batch` 广播 opens。
   - 每台服务器写回该 AND gate 的输出份额，并 opportunistic 评估新增就绪的本地门。
3. 调用 `/mpc/finalize` 得到输出份额与 MAC 签名 commit proof。

### 正确性（单个 AND gate）

在 XOR 共享 + Beaver triple 下，标准等式成立：各方按本实现计算得到的 z0 XOR z1 等于 x AND y。
分轮调度只改变交互打包方式，不改变每个 AND gate 的数学语义；且 rounds 的深度性质保证输入就绪。
因此最终 outputs 复原结果等于电路明文求值结果。

### 实现映射

- and_rounds 编译：`gateway/policy_unified.py:_compute_and_rounds`
- 网关分轮调用：`gateway/policy_unified.py:_mpc_eval_and_rounds`
- Python MPC 引擎：`policy_server/mpc_engine.py`
- Rust MPC 引擎：`policy_server_rust/src/main.rs`

---

## 7. 算法 A6：Intent Shadowing 的统一策略程序编译（常形状）

### 目标

将多个意图/类别的策略编译进一套统一常形状 MPC 程序，实现：

- 服务器侧不按 intent 分支（减少 intent/category 泄露）
- 所有 covered intents 共用同一 program_id
- 泄露边界由 L(.) 明确界定，而非泛泛宣称“完全不泄露”

### 输入与输出

统一程序使用固定输入向量：

- intent one-hot bits：intent_send, intent_fetch, intent_webhook, intent_skill_install
- capability bits：cap_send, cap_fetch, cap_webhook, cap_skill_install
- 来自 A3 的特征 bits：recipient_ok, domain_ok, dlp_hit, ioc_hit, install_hit 等

固定输出：

- allow_pre, need_confirm, patch0, patch1（patch 位编码 sanitize patch id）

### 编译规则（oblivious mux）

算法 A6.CompileUnifiedProgram

给定每个 intent i 的输出布尔表达式 Expr_i（对每个输出分别一套）：

1. 为所有固定输入分配 wire。
2. 将每个 Expr_i 编译成依赖固定输入的布尔子电路。
3. 用 one-hot mux 进行不可观测选择：
   - out = XOR_i ( intent_bit_i AND Expr_i )

当 intent bits 满足 one-hot（恰有一个为 1）时，XOR 选择等价于 OR 选择，输出等于被选 intent 的 Expr 值。
电路形状常量化：所有 intent 分支都存在并以共享方式执行。

### 正确性

在 one-hot 前提下，对每个输出 out：

- out = Expr_j，其中 j 为唯一满足 intent_bit_j=1 的 intent。

### 实现映射

- 统一电路编译与默认电路：`gateway/policy_unified.py:build_policy_unified_v1_circuit_*`
- program_id：环境变量 `MIRAGE_POLICY_PROGRAM_ID`（默认 `policy_unified_v1`）

---

## 8. 泄露模型边界（允许泄露函数 L(.)）

MIRAGE-OG++ 的安全叙事以“明确允许泄露”为边界：每个策略服务器能从自身 transcript 看到什么，必须被 leakage 函数 L(.) 精确定义。

- 具体定义与当前实现覆盖范围见 `LEAKAGE_MODEL.md`。
- 本文档中所有“隐藏/不泄露”仅在该 L(.) 边界内成立。

---

## 9. 验证（正确性与一致性）

下述命令可验证本文档算法与实现一致且正确。

### 9.1 单元测试（离线、快速）

```bash
python -m unittest discover -s tests -q
```

覆盖：

- A1（commit proof 验证）：`tests/test_security_games.py`
- DPF/PIR plumbing、handles、guardrails：`tests/test_ogpp.py`
- MCP 网关行为：`tests/test_mcp_gateway.py`
- A2/A3/A4/A5/A6 的关键不变量：`tests/test_algorithms.py`

### 9.2 NBE 形式化安全游戏脚本

```bash
PYTHONPATH=. python scripts/security_game_nbe_check.py
```

产物输出到 `artifact_out/security_game_nbe.json`。

### 9.3 Rust 后端构建（可选，性能路径）

```bash
cd policy_server_rust
cargo build --release
```

用于确认 Rust 后端与 Python 端点/proof 格式一致。

---

## 10. 代码索引（Quick Index）

- 统一策略引擎/编译：
  - `gateway/policy_unified.py`
- PIR 客户端、signed proof、mixer：
  - `gateway/fss_pir.py`
- Python policy server：
  - `policy_server/server.py`
  - `policy_server/mpc_engine.py`
- Rust policy server：
  - `policy_server_rust/src/main.rs`
- 执行端 proof 验证与 effect gating：
  - `executor_server/server.py`
- 形式化主张与安全游戏：
  - `FORMAL_SECURITY.md`
- 泄露模型：
  - `LEAKAGE_MODEL.md`
