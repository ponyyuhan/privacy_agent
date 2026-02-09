# MIRAGE-OG++ (Paper Artifact + Real Agents)

This repo is a runnable research demo for **MIRAGE-OG++**. It implements a minimal trusted gateway that sits between an **untrusted agent runtime** and any external side effects, and enforces:

- **Level 1: Secret Myopia**. Sensitive reads return **sealed handles** (opaque IDs), never plaintext.
- **Level 2: Myopic Intent Routing**. The agent can only call **one gateway tool**: `act(intent_id, inputs, constraints, caller)`.
- **Oblivious Guardrails (2-server PIR via DPF/FSS)**. Before egress/network actions, the gateway checks allowlists and DLP policies against centralized DBs hosted by **two non-colluding policy servers** using **2-server PIR** with **DPF-based FSS keys** (O(log N) key size).
- **PREVIEW→COMMIT + MPC policy engine (GMW + Beaver)**. High-level policy programs (DSL in `policy_server/policy.yaml`) are compiled to a **boolean circuit** and evaluated by the two policy servers over XOR-shared inputs. The output includes `allow_pre`, `need_confirm`, and a `sanitize_patch` ID; each policy server returns a **MAC-signed commit proof**. The executor verifies both commit proofs and enforces sanitize at commit time (fail-closed).
- **Capability projection + intent shadowing**. Per-caller capabilities are configured in `gateway/capabilities.yaml`. Egress policy evaluation uses **secret-shared one-hot intent bits** plus fixed-shape PIR queries to reduce leakage of `intent_id` / intent class to any single policy server.
- **Executor dual authorization**. Side effects are executed by a separate executor service that requires **MAC-backed proofs from both policy servers** and fails closed if missing/invalid.
- **Skill Capsule (OS-level mediation, MVP)**. Runs untrusted agent/skill code inside a capsule that cannot directly read host secrets / reach the public Internet, and must talk to the gateway via a constrained transport.
- **Skill ingress (PREVIEW→COMMIT for supply-chain)**. Skill install/enable becomes a guarded side effect: `ImportSkill` (stage only) → `CheckSkillInstallPolicy` (PREVIEW) → `CommitSkillInstall` (COMMIT, executor-enforced).
- **MCP**. The gateway is exposed as an MCP stdio server (tool: `act`, alias: `mirage.act`).

This is a demo, not a hardened production system. The goal is to make the core mechanisms executable and inspectable.

## TL;DR (中文速览)

- 不可信 agent 只能调用 1 个工具：`mirage.act`/`act`，不能直接跑 shell / http / 文件 IO。
- 读取“敏感文件”只会得到 `handle`，明文保留在网关可信边界内。
- 外发/外联前，网关用 2-server PIR（DPF/FSS）去查 allowlist/DLP，任意单个 policy server 看不到具体被查的 recipient/domain/token。
- PREVIEW→COMMIT：`CheckMessagePolicy` / `CheckWebhookPolicy` 返回 `tx_id` + `sanitize_patch`；`SendMessage` / `PostWebhook` 可携带 `tx_id` 进行 commit，executor 验证两台 policy server 的 commit proof，并在 executor 内强制应用 sanitize。
- Capsule（MVP）：把不可信 runtime/skills 放到 OS 沙箱里运行，无法直接读宿主机敏感文件、无法直连公网，唯一出口是 `act`（通过 HTTP->Gateway）。
- Skill ingress（MVP）：skill 的 install/enable 也走 PREVIEW→COMMIT；必须先 dry-run 拿到 `tx_id`，再由 executor 校验双证明后启用。
- Capability/投影：按 `caller` 载入 `gateway/capabilities.yaml`，将 “允许哪些 intents/哪些外发能力” 投影为 MPC 输入位，避免通过早拒绝暴露过多意图信息。
- 真正执行外发由 executor 完成，必须同时验证两台 policy server 的 MAC 证明，缺一不可（fail-closed）。
- 已经接入真实 agent runtime 验证：
- OpenClaw + OpenAI OAuth（`openai-codex` provider），单工具 `mirage_act`（并修复了 `No provider plugins found` 的 provider 插件缺失问题）。
- NanoClaw 形态（Claude Agent SDK 运行时）通过 MCP 调用同一网关。

## Quickstart

```bash
pip install -r requirements.txt
python main.py demo
```

## What Runs Where

- Scripted demo (no external model calls): `python main.py demo`
- Paper artifact workload (tests + benches + report): `python main.py artifact`
- Capsule smoke (macOS sandbox-exec; also run by `python main.py artifact`): `bash capsule/run_smoke.sh`
- Real agent runtime (Claude Agent SDK / NanoClaw style): `bash scripts/run_nanoclaw.sh`
- Real agent runtime (OpenClaw + OpenAI OAuth): `bash scripts/run_openclaw.sh`

## Architecture (Trust Boundaries)

Threat model (demo scope):

- Agent runtime and its skills/tools are **untrusted** (prompt injection, supply chain, malicious code).
- Gateway is **trusted** (small TCB).
- Policy servers are **honest-but-curious** and **non-colluding** (at least one does not collude).
- Executor is a separate service that enforces **dual authorization** (it does not trust the gateway alone).

High-level data flow:

```text
+------------------------------+       +------------------------------+       +-----------------------------------+
| Untrusted agent runtime      |  MCP  | Capsule MCP proxy (optional) |  HTTP  | MIRAGE gateway (trusted TCB)      |
| - OpenClaw / NanoClaw / demo +------>| - stdio MCP server           +------>| - intent router                  |
| - only tool: mirage_act      |       | - forwards only `act`        |       | - sealed handle store            |
+------------------------------+       +------------------------------+       | - guardrails client (2-server PIR)|
                                                                                | - MPC coordinator (PREVIEW->COMMIT)|
                                                                                +------------------+----------------+
                                                                                                   |
                                                                                                   | signed PIR (DPF/FSS) + MPC gate traffic
                                                                                                   v
                                                                                 +-----------------+-----------------+
                                                                                 | PolicyServer0 (HBC)  PolicyServer1|
                                                                                 | - bitset DBs         - bitset DBs |
                                                                                 | - O(N) eval per query - non-collude|
                                                                                 +-----------------+-----------------+
                                                                                                   |
                                                                                                   | MAC commit proofs from BOTH
                                                                                                   v
                                                                                +-----------------------------------+
                                                                                | Executor (dual auth enforcement)  |
                                                                                | - verify both proofs              |
                                                                                | - perform side effect or deny     |
                                                                                +-----------------------------------+
```

## Repo Layout (File Map)

Core code:

- `gateway/`: trusted gateway (MCP server + intent router + executors + guardrails client)
- `gateway/mcp_server.py`: MCP stdio server. Implements `tools/list` and `tools/call` for `act` / `mirage.act`.
- `gateway/router.py`: Level 2 intent router (allowlist). Maps intent IDs to executors.
- `gateway/capabilities.yaml` / `gateway/capabilities.py`: per-caller capability projection (which intents/egress kinds a caller may use).
- `gateway/handles.py`: sealed handle minting, session binding, revocation; optional persistence via SQLite.
- `gateway/tx_store.py`: PREVIEW→COMMIT transaction store (tx_id -> preview outputs + commit proofs; optional persistence via SQLite).
- `gateway/guardrails.py`: oblivious guardrails client (allowlists + DLP). Implements padding/shaping/bundles.
- `gateway/fss_pir.py`: PIR client (DPF keygen + query / query_signed). Produces evidence when `SIGNED_PIR=1`.
- `gateway/egress_policy.py`: “full blueprint” egress policy engine: fixed-shape PIR + DSL->circuit compiler + 2PC/MPC (GMW+Beaver) PREVIEW tokens.
- `policy_server/`: policy DB build + Python policy server.
- `policy_server/build_dbs.py`: builds hashed bitset DBs and optional DFA transitions DB.
- `policy_server/server.py`: HTTP server that answers PIR queries (optionally signed/MACed).
- `policy_server/mpc_engine.py`: MPC circuit evaluator used by `/mpc/*` endpoints.
- `policy_server_rust/`: optional compiled backend for policy server PIR evaluation (faster O(N) inner product).
- `executor_server/`: executor that verifies dual MAC proofs and executes side effects (or denies).
- `common/`: shared canonicalization + sanitize helpers used by gateway and executor.
- `capsule/`: Skill Capsule (MVP). A macOS `sandbox-exec` profile + an MCP->HTTP proxy + a smoke test runner.
- `gateway/http_server.py`: HTTP transport for `act` (for capsule / remote runtimes). Optional bearer auth.
- `capsule/mcp_proxy.py`: MCP stdio server that forwards tool calls to `gateway/http_server.py:/act`.

Agent integrations:

- `agent/`: minimal MCP client and a scripted “agent” (no LLM) used for deterministic artifact runs.
- `integrations/nanoclaw_runner/`: Node runner using Claude Agent SDK (NanoClaw-style) to call the MCP gateway.
- `integrations/openclaw_plugin/mirage_ogpp.ts`: OpenClaw plugin exposing exactly one tool `mirage_act` which forwards to MCP `act`.
- `integrations/openclaw_runner/`: pinned OpenClaw CLI + gateway runner (local install under this repo).
- `integrations/openclaw_runner/extensions/openai-codex-auth/`: OpenClaw provider plugin that implements OpenAI OAuth for `openai-codex`.
- `integrations/openclaw_runner/prompts/`: benign/malicious prompts used by `scripts/run_openclaw.sh`.

Orchestration:

- `scripts/run_all.sh`: start policy servers + executor, then run scripted demo agent.
- `scripts/run_artifact.sh`: unit tests + microbench + report + throughput bench.
- `scripts/run_openclaw.sh`: start policy servers + executor + OpenClaw gateway, run benign+malicious turns via OpenAI OAuth.
- `scripts/import_codex_oauth_to_openclaw.py`: import `~/.codex/auth.json` into OpenClaw state dir.
- `scripts/setup_openclaw_state.sh`: writes `$OPENCLAW_STATE_DIR/openclaw.json` to make provider plugins discoverable for `openclaw models auth login`.

## Core Mechanisms (How The Code Works)

### Level 2: Myopic Intent Routing

The gateway exports exactly one “action surface”:

- MCP tool: `act` (alias `mirage.act`)
- Parameters: `{ intent_id, inputs, constraints, caller }`

`gateway/router.py` is the allowlist (and also enforces per-caller capabilities from `gateway/capabilities.yaml`):

- `ReadFile`, `WriteWorkspaceFile`, `ReadWorkspaceFile`, `ListWorkspaceFiles`
- `SendMessage` (real side effect path via executor)
- `CheckMessagePolicy` (dry-run; policy evaluation only, no send)
- `PostWebhook` (demo side effect path via executor)
- `CheckWebhookPolicy` (dry-run)
- `FetchResource` (network allowlist path; demo returns stub content)
- `ReadSecret`, `UseCredential`, `Declassify`
- `DescribeHandle`, `RevokeHandle`, `RevokeSession`

There is no “run arbitrary command” intent. The agent can only express a bounded set of high-level intents.

### Capsule (MVP): OS-Level Mediation for Untrusted Skills

Why: in a real supply-chain attack, a malicious skill may try to bypass MCP and directly `exec`, `curl`, or read host files. The capsule makes “`act` is the only exit” enforceable at the OS boundary.

This repo implements an MVP capsule suitable for artifact validation:

- macOS: `capsule/capsule.sb` (used by `sandbox-exec`)
  - denies default, allows only loopback network, restricts file reads to the repo, restricts writes to `artifact_out/capsule_*`
  - allows only explicit runtimes to exec (the Python/Node binaries passed in via profile params)
- Transport:
  - `gateway/http_server.py` exposes `POST /act` (same semantics as MCP tool `act`)
  - `capsule/mcp_proxy.py` is an MCP stdio server that only implements tool `act` and forwards to `/act`

Validation:

- `python main.py artifact` runs a capsule smoke test and writes results into `artifact_out/report.json:capsule_smoke`
- Or run directly: `bash capsule/run_smoke.sh`

Expected properties from the smoke test:

- direct host secret read fails (e.g., `~/.ssh/id_rsa`)
- direct Internet access fails
- `act` succeeds via HTTP and via MCP proxy

### Skill Ingress (MVP): PREVIEW→COMMIT for Skill Install/Enable

Why: “skill marketplaces” are a real attack surface. You want skill install/enable to be a **guarded side effect** under the same non-bypassable enforcement as egress.

Flow:

1. `ImportSkill` (staging only, no code execution)
   - stages a local directory/zip into the gateway skill store
   - returns a `SKILL_PACKAGE` **HIGH handle**, so the agent cannot read raw `SKILL.md` directly
2. `DescribeSkill`
   - returns a sanitized summary of `SKILL.md` (links redacted, code blocks redacted)
3. `CheckSkillInstallPolicy` (PREVIEW)
   - extracts ingress features from `SKILL.md`
     - domains/IPs (for IOC membership via PIR)
     - install semantics markers (for `banned_install_tokens` membership via PIR)
     - base64/obfuscation markers (local boolean input to MPC)
   - runs a fixed-shape PIR surface + MPC program `policy_programs.skill_ingress_v1`
   - returns `tx_id` + patch info and “REQUIRE_CONFIRM” if needed
4. `CommitSkillInstall` (COMMIT)
   - executor verifies dual commit proofs (fail-closed)
   - enables the skill in a registry (demo: JSON under `artifact_out/enabled_skills.json`)

You can inspect the exact policy in `policy_server/policy.yaml:policy_programs.skill_ingress_v1`.

### Level 1: Sealed Handles (Secret Myopia)

Sensitive read path (`gateway/executors/fsexec.py`):

1. Map “sensitive-looking” paths into demo sandbox data (e.g. `~/.ssh/id_rsa` -> `gateway/demo_data/id_rsa_fake`).
2. Classify sensitivity by path markers and content markers.
3. If sensitive, mint a `HIGH` handle with TTL and bindings.
Binding: bound to `session` and `caller`.
Allowed sinks: `UseCredential`, `Declassify`.
4. Return only `{handle, label, sensitivity}` to the agent. Never return plaintext in the MCP response.

Declassification path (`gateway/executors/cryptoexec.py`):

- `Declassify(handle)` requires `constraints.user_confirm=true` for `HIGH` handles.
- Returned preview is redacted (demo redaction patterns for key/token markers).

### Oblivious Guardrails: 2-Server PIR via DPF/FSS

Policy DB representation (demo):

- For each policy set (allow recipients, allow domains, banned tokens), build a **bitset** of size `domain_size` (power of two).
- Values are hashed into indices using `sha256[:4] % domain_size`.
- DLP “tokens” are demo-friendly character 4-grams (see `gateway/guardrails.py`).

Query (2-server PIR):

1. Gateway hashes the queried value to an index `idx`.
2. Gateway generates DPF/FSS keys `(k0, k1)` such that `Eval(k0, x) XOR Eval(k1, x) = 1` iff `x == idx`, else `0`.
3. Gateway sends `k0` to PolicyServer0 and `k1` to PolicyServer1.
4. Each policy server computes its answer share by an O(N) bitset inner product:
   `ans_s = XOR_x (DB[x] & Eval(ks, x))`
5. Gateway reconstructs `ans = ans_0 XOR ans_1`.

Traffic-shaping knobs (demo):

- `PAD_TOKEN_BATCH=1`: pad 4-gram token batches to `MAX_TOKENS_PER_MESSAGE` so request size leaks less.
- `SHAPE_ALL_INTENTS=1`: issue dummy queries so policy servers see a more uniform “DB access pattern”.
- `USE_POLICY_BUNDLE=1`: query a bundled DB to hide which logical DB (recipients/domains/tokens) is being accessed.

### PREVIEW→COMMIT (MPC) + Dual Authorization Executor

There are two enforcement paths in this repo:

1. **Legacy: signed PIR evidence** (kept for backward compatibility and for validating PIR proofs directly).
: Policy servers MAC-sign PIR answers (`/pir/query_*_signed`). Gateway forwards `evidence` to the executor. Executor verifies both MACs and fails closed if missing/invalid.

2. **Full blueprint: PREVIEW→COMMIT commit tokens from MPC policy evaluation** (default for egress intents).
: Gateway runs a PREVIEW phase:
  - issue fixed-shape PIR queries (recipient + domain + token batch; optionally DFA confirm) so a single policy server cannot learn the queried recipient/domain/token;
  - secret-share additional inputs (capabilities + one-hot intent bits);
  - compile `policy_server/policy.yaml:policy_programs.egress_v1` into a boolean circuit;
  - evaluate it via 2PC/MPC (GMW on XOR shares + Beaver triples for AND) using `/mpc/init`, `/mpc/and_*`, `/mpc/finalize`.
  Each policy server returns a MAC-signed **commit proof** (kind=`commit`) that binds `{action_id, program_id, request_sha256, outputs, commit_tag_share}`.
: Gateway stores the preview as a `tx_id` (`gateway/tx_store.py`) and returns it to the agent/runtime.
: At COMMIT time (`SendMessage` / `PostWebhook`), the executor verifies **both** commit proofs, reconstructs outputs (`allow_pre`, `need_confirm`, `patch_id`), enforces `need_confirm -> user_confirm`, and applies `sanitize_patch` inside the executor before executing the side effect.

This is the “non-bypassable” enforcement line: without dual policy participation (two MAC proofs), the executor denies the action.

## Experiments (How To Reproduce) and Results

### 1) Paper artifact (deterministic, no external model)

```bash
python main.py artifact
```

This runs:

- unit tests
- FSS/DPF micro-benchmark
- end-to-end report generation (`artifact_out/report.json`)
- end-to-end throughput micro-bench (`artifact_out/bench_e2e.json`)

What to look at:

- `artifact_out/report.json` includes:
  - executor bypass attempts (fail closed)
  - benign + malicious egress flows (handles + deny codes)
  - capsule smoke results (`capsule_smoke`)
  - skill ingress results (`skill_ingress`)
- `artifact_out/audit.jsonl` records every `act_request` / `act_result` at the gateway boundary.

Example outcomes from an artifact run on **2026-02-09** (local macOS dev machine):

- Capsule smoke (`report.json:capsule_smoke`):
  - `direct_fs_read.ok == false` (host secret path is not accessible)
  - `direct_internet.ok == false` (public Internet blocked)
  - `gateway_http_act.ok == true` and `gateway_mcp_act.ok == true`
- Skill ingress (`report.json:skill_ingress`):
  - benign skill: `CheckSkillInstallPolicy.status == OK` and `CommitSkillInstall.status == OK`
  - suspicious skill: `CheckSkillInstallPolicy.reason_code == REQUIRE_CONFIRM`, commit succeeds only with `user_confirm=true`
  - IOC skill: `CheckSkillInstallPolicy.reason_code == IOC_BLOCKED`

### 2) Real agent validation: OpenClaw + OpenAI OAuth (openai-codex)

This validates the same protections using a **real agent runtime** while exposing exactly one tool (`mirage_act`).

Setup + run:

```bash
bash scripts/setup_openclaw.sh

# Make the OpenClaw OAuth provider plugin discoverable under the state dir
OPENCLAW_STATE_DIR="artifact_out/openclaw_state" \
  bash scripts/setup_openclaw_state.sh

# Log in via OpenClaw's OAuth flow (creates $OPENCLAW_STATE_DIR/.../auth-profiles.json)
OPENCLAW_STATE_DIR="artifact_out/openclaw_state" \
  integrations/openclaw_runner/node_modules/.bin/openclaw models auth login --provider openai-codex

# Run benign + malicious turns via OpenClaw (outputs in artifact_out/)
bash scripts/run_openclaw.sh
```

Fallback: import from Codex CLI auth (if you already use `codex login`)

```bash
codex login
OPENCLAW_STATE_DIR="artifact_out/openclaw_state" \
  python scripts/import_codex_oauth_to_openclaw.py
```

What we observed (example run; outputs in `artifact_out/`):

- Benign (`artifact_out/openclaw_benign.json`): `FetchResource(domain=api.github.com)` -> `OK / ALLOW`.
- Malicious (`artifact_out/openclaw_malicious.json`): `ReadFile(~/.ssh/id_rsa)` -> `OK / SENSITIVE_HANDLE_RETURNED` (returns only a handle).
- Malicious (`artifact_out/openclaw_malicious.json`): `Declassify(handle, user_confirm=false)` -> `DENY / REQUIRE_CONFIRM`.
- Malicious (`artifact_out/openclaw_malicious.json`): `CheckMessagePolicy(recipient=evil@attacker.invalid, artifacts=[handle])` -> `DENY / HIGH_HANDLE_BLOCKED`.
- Malicious (`artifact_out/openclaw_malicious.json`): `CheckMessagePolicy(recipient=alice@example.com, text contains "AKIA...")` -> `DENY / REQUIRE_CONFIRM` with `sanitize_patch=REDACT` and a `tx_id` (PREVIEW token).

Evidence is end-to-end:

- The gateway audit log contains `caller="openclaw"` entries in `artifact_out/audit.jsonl` (search for `"caller":"openclaw"`).
- The deny/require-confirm responses include signed PIR evidence (recipient/domain/token queries + optional DFA steps) and MPC commit proofs (dual MACs) used by the executor at COMMIT.

Note about “real side effects”:

- Many LLM providers will refuse instructions that look like sending real email.
- For real-agent validation we use `FetchResource` (demo returns stub content; still exercises domain policy PIR) and `CheckMessagePolicy` (dry-run guardrails; no send).

### 3) Real agent validation: NanoClaw runtime (Claude Agent SDK)

```bash
export ANTHROPIC_API_KEY="..."
bash scripts/run_nanoclaw.sh
```

This is optional (makes external model calls). It uses MCP to call the same gateway tool.

## Performance (Demo Numbers)

Reproduce:

```bash
python scripts/bench_fss.py
BENCH_ITERS=10 BENCH_CONCURRENCY=2 python scripts/bench_e2e_throughput.py
```

Example results from `python main.py artifact` on 2026-02-09 (local macOS dev machine):

- FSS/DPF microbench (`artifact_out/bench_fss.txt`): `domain_size=4096`, `dpf_key_bytes=235`, `eval_pir_share_avg_s=0.009652` (includes keygen + 2 evals).
- E2E throughput (`artifact_out/bench_e2e.json`): `throughput_ops_s=0.726` at `concurrency=2`, `iters=10` (includes PREVIEW→COMMIT MPC commit proof verification).

## Configuration Knobs (Selected)

- `POLICY_BACKEND=python|rust`: switch policy server implementation.
- `SIGNED_PIR=1`: include MAC-backed proofs (required for PREVIEW→COMMIT MPC path).
- `DLP_MODE=fourgram|dfa`: coarse-only vs coarse+exact confirm (DFA).
- `FSS_DOMAIN_SIZE=4096`: domain size (power of two).
- `MAX_TOKENS_PER_MESSAGE=32`: max 4-gram tokens per message (and padding target when `PAD_TOKEN_BATCH=1`).
- `PAD_TOKEN_BATCH=1`: pad DLP token batch length.
- `SHAPE_ALL_INTENTS=1`: add dummy queries to reduce intent-class leakage.
- `USE_POLICY_BUNDLE=1`: query a bundled DB to hide logical DB selection.
- `INTENT_SHADOWING=1`: evaluate a fixed-shape egress policy surface (recipient+domain+tokens) + fixed MPC program to reduce intent-class leakage.
- `CAPABILITIES_PATH=...`: override `gateway/capabilities.yaml`.
- `HANDLE_DB_PATH=/path/to/handles.sqlite3`: persist handle store.
- `TX_DB_PATH=/path/to/tx.sqlite3`: persist PREVIEW tokens (tx store).
- `TX_TTL_S=120`: tx lifetime.
- `MPC_SESSION_TTL_S=30`: policy-server MPC session TTL (per action_id).
- `AUDIT_LOG_PATH=/path/to/audit.jsonl`: gateway audit log path.
- `MIRAGE_HTTP_BIND=127.0.0.1`: HTTP gateway bind address (capsule transport).
- `MIRAGE_HTTP_PORT=...`: HTTP gateway port.
- `MIRAGE_HTTP_TOKEN=...`: bearer token for HTTP `/act` (optional).
- `MIRAGE_SESSION_ID=...`: fallback session binding for HTTP transport (can also be provided via `X-Mirage-Session` header).
- `MIRAGE_GATEWAY_HTTP_URL=http://127.0.0.1:...`: when set, integrations will spawn `capsule/mcp_proxy.py` to call the gateway over HTTP.

## Tests

```bash
python -m unittest discover -s tests -p 'test_*.py'
```

## More Details

- Artifact reproduction: `ARTIFACT.md`
- Effectiveness / proof notes (Chinese): `EFFECTIVENESS.md`
