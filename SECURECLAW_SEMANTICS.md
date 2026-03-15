# SecureClaw Semantics

This document specifies what must remain true for a system to count as **SecureClaw**, and what an integration layer must implement so SecureClaw does not silently degrade into false denies, false allows, or low-utility behavior.

The key distinction is:

- **Core SecureClaw protocol semantics**: owned by SecureClaw itself.
- **Integration semantics**: tool/runtime-specific glue that each host environment must implement correctly.

The recent AgentDojo fixes were mostly in the second category. They are **generic semantics**, but they currently live inside the AgentDojo adapter path because that is where the tool/runtime contract is realized.

## 1. Core SecureClaw Semantics

These are the non-negotiable properties. If any of these are removed, the system is no longer the same SecureClaw design.

### 1.1 Dual policy servers

- Authorization is not a single gateway decision.
- External side effects must be authorized by **two policy servers**.
- The executor must not trust a single server, a single gateway, or a local heuristic alone.

### 1.2 Preview -> Commit discipline

- Side-effectful actions must go through a two-stage flow:
  - `preview`
  - `commit`
- The executor only commits effects after verifying valid commit evidence bound to the same request/action context.

### 1.3 Non-bypassable executor commit line

- The executor is the only place allowed to actually commit external effects.
- Missing, forged, replayed, or mismatched commit evidence must fail closed.
- This is the main integrity line of SecureClaw.

### 1.4 Request-bound authorization

- Authorization must be bound to the exact request context, not to a vague intent string.
- Recipient/domain/target binding must survive the entire chain:
  - model/tool call
  - preview
  - commit
  - executor verification

### 1.5 Internal read outputs are not plaintext

- Sensitive read results must not be copied through internal agent/tool messages as raw plaintext.
- Internal read results are represented as handles/sanitized summaries.
- Any declassification to final user-visible output must be explicit and tightly constrained.

### 1.6 Task-intent gating

- SecureClaw may allow readonly operations and deny off-task side effects.
- Side effects require alignment with the user’s actual request, not just local model momentum.

### 1.7 Strict sink binding

- Sends, webhooks, fetches, and other externally relevant effects must be checked against concrete targets.
- “Looks related” is not enough; the effect target must be bound to authorized context.

## 2. Integration Semantics

These are not benchmark-specific hacks. They are the **tool/runtime semantics** an integration must provide so the SecureClaw core can be applied correctly.

If these are missing, SecureClaw can still preserve its core commit-line security, but it can become:

- too conservative
- utility-poor
- prone to false denies
- inconsistent across tools

### 2.1 Tool taxonomy

Every integration must classify tools correctly, at minimum into categories such as:

- `readonly`
- `send`
- `fetch`
- `webhook`
- `local_state`

If a tool is misclassified, SecureClaw may authorize it under the wrong rule set.

Examples of generic failure modes:

- `get_webpage` treated like harmless readonly instead of `fetch`
- a side-effectful Slack admin action treated like benign local state

### 2.2 Target extraction from the user request

The integration must extract explicit targets from the user request robustly, including cases such as:

- names
- email addresses
- IBANs
- domains and URLs
- quoted entities
- `Name (url)` structures
- channel/user prefixes

This is not benchmark logic. It is the basic problem of grounding model actions to the user’s request.

### 2.3 Contextual targets from trusted tool outputs

The integration must be able to learn legitimate follow-on targets from **trusted structured outputs**, not from arbitrary free text.

The required pattern is:

- read result stays non-plaintext internally
- structured summary carries a separate `safe_targets` field
- later actions can bind to those `safe_targets`

This is the generic way to preserve both:

- “internal messages are not plaintext”
- legitimate multi-step workflows

### 2.4 Provenance-aware follow-on fetch

The integration must distinguish:

- fetches that are grounded in trusted structured context and requested by the user
- fetches that are merely suggested by untrusted text

This is why a follow-on `get_webpage` rule is needed. Without it:

- benign workflows get falsely blocked

With an over-broad rule:

- attacker-supplied URLs can leak through

### 2.5 Environment-aware target canonicalization

The integration must canonicalize tool arguments against observed environment state when the tool ecosystem has named principals such as:

- users
- channels
- accounts
- resources

Typical generic problems:

- `eve` vs `Eve`
- `external_0` vs `External_0`
- scalar vs list-valued arguments

This is not benchmark tuning; it is standard runtime normalization.

### 2.6 Tool schema alias normalization

Different tools or models may express equivalent concepts under different argument keys.

Examples:

- `company_name`
- `hotel_names`
- `restaurant_names`

The integration must normalize these schema aliases before authorization and execution. Otherwise the policy sees the wrong argument shape.

### 2.7 Reservation / side-effect intent tightening

The integration must not let generic browsing/planning language silently escalate into commits.

For example:

- “find the best hotel” is not the same as “reserve the hotel”
- “find car rental options” is not the same as “book the car”

This is part of SecureClaw’s generic task-intent semantics, not a benchmark patch.

### 2.8 Request-bound final-output declassification

If final user output declassifies aliases such as:

- `URL_REF_n`
- `EMAIL_REF_n`
- `IBAN_REF_n`

then the rule must be narrow:

- only when the user explicitly requested that kind of value
- only when the alias matches the requested brand/domain/entity context
- never as a blanket plaintext release

This preserves the “internal non-plaintext” property while allowing necessary final answers.

## 3. What Is Currently First-Party vs Adapter-Local

### 3.1 SecureClaw-owned core

These are first-party SecureClaw components:

- `gateway/`
- `executor_server/`
- `policy_server/`
- `policy_server_rust/`
- `scripts/run_agentdojo_native_plain_secureclaw.py`

These are where the core protocol and execution-line guarantees live:

- dual policy servers
- preview/commit
- commit proof verification
- request binding
- executor fail-closed behavior

### 3.2 AgentDojo adapter-local semantics

These currently live in:

- shared SecureClaw-owned module: `secureclaw/semantics.py`
- AgentDojo adapter call sites:
  - `third_party/ipiguard/agentdojo/src/agentdojo/agent_pipeline/tool_execution.py`
- `third_party/ipiguard/agentdojo/src/agentdojo/task_suite/task_suite.py`
- `third_party/ipiguard/agentdojo/src/agentdojo/default_suites/v1/tools/slack.py`

This is where the recent generic fixes landed:

- query target extraction
- `safe_targets`
- canonicalization
- alias normalization
- trusted follow-on fetch
- final-output request-bound declassification

They live there **not because they are benchmark-specific**, but because the current AgentDojo integration expresses tool semantics there.

## 4. Answer to the Portability Concern

Yes — your concern is valid.

If another person uses SecureClaw by reusing only the core gateway/policy/executor path, but does **not** implement the integration semantics above, then they can still see errors such as:

- false denies
- low utility
- broken recipient binding
- wrong target grounding
- brittle follow-on fetch behavior

In other words:

- **core SecureClaw security can still hold**
- but **the integrated system can still behave badly**

So the correct statement is:

- the current fixes are **generic**
- but they are **not yet fully centralized in SecureClaw-owned code**

## 5. Practical Rule for Future Integrations

To integrate SecureClaw correctly, a host environment must satisfy both layers:

### Layer A: SecureClaw core

- dual policy servers
- preview -> commit
- executor-side proof verification
- request-bound authorization
- internal non-plaintext read path

### Layer B: integration contract

- correct tool taxonomy
- robust target extraction
- trusted structured `safe_targets`
- canonicalization against runtime state
- schema alias normalization
- provenance-aware follow-on fetch
- narrow final-output declassification

If Layer A exists without Layer B, the system is secure in a narrow commit-line sense but can be operationally poor.

## 6. What We Should Do Next

The right long-term fix is to move the generic integration semantics into a first-party shared module and make adapters call into it.

Recommended direction:

1. create a SecureClaw-owned shared semantics module
2. move generic helpers out of `third_party` adapter code
3. keep only tool-environment-specific glue in each adapter
4. add adapter conformance tests so every integration proves it satisfies this contract

## 7. Bottom Line

The recent fixes are **not benchmark hard-coding**.

But your portability concern is correct: because these semantics currently live inside the AgentDojo adapter, another integration can still regress if it does not implement the same contract.

So the current state is:

- **generic semantics**: yes
- **fully centralized in SecureClaw-owned code**: not yet
- **safe to assume every future integration gets them automatically**: no
