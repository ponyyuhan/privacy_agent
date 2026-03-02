## 1) Restructuring the paper around *one thesis* + a crisp privacy model for SAP

### 1.1 What feels “too complex” today (and how to fix it)

From the current draft, the work is trying to sell **many named properties** (NBE/SM/PEI/SCS/DAS/SAP) as *co-equal* contributions. This is a common reviewer reaction trigger: *“too many moving parts; unclear what the paper’s central idea is.”* Your own formal note already hints at the right remedy: anchor everything around **a single reviewable proposition** and make the rest either (i) enabling mechanisms, or (ii) optional modules. 

**Concrete change:** reduce the “main contributions” to **3 items** (plus an optional fourth), and move the rest under *Design Components* and *Ablations* rather than “core contributions”.

---

### 1.2 The re-centered thesis (what reviewers should remember)

> **Thesis (one sentence):** In agentic tool-use systems, preventing privacy loss under *adversarial or compromised runtimes* requires a **cryptographically non-bypassable effect boundary**, and enforcing it at scale creates a **control-plane privacy paradox** that we resolve with **Single‑Auditor Privacy (SAP)**—outsourcing policy checks while provably hiding sensitive query values from any single policy server. 

That sentence gives you a narrative spine that naturally explains why SAP matters (it is not a “nice add-on”; it resolves the paradox created by real enforcement).

---

### 1.3 Revised contribution list (top-tier framing)

Here is a “top conference style” contribution list that is *pain-point first* and avoids micro-contributions.

**C1. Non-bypassable execution for agent actions (core).**
A protocol + reference architecture that enforces: *no external effect occurs unless an executor verifies a bound authorization artifact.* The artifact is **bound to a canonical request hash** and requires **dual proof shares** from two independent policy servers (or equivalent separation), so a compromised runtime cannot bypass policy by sending a direct COMMIT. 

**C2. The control-plane privacy paradox + Single‑Auditor Privacy (SAP) (core).**
We formalize the paradox: policy enforcement needs sensitive inputs (recipients/domains/tokens), but centralizing checks leaks those values to the policy plane. We give SAP: a **fixed‑shape** PIR+MPC policy outsourcing design with an explicit **leakage contract** (L_{\text{policy}}) and a **simulation-based proof** that a single policy server’s transcript is simulatable from (L_{\text{policy}}) (and thus learns nothing else). 

**C3. Confidentiality + multi-principal correctness under compromised runtimes (core).**
A coherent story: secrets are never exposed to the untrusted runtime unless explicitly declassified; egress is integrity-protected; and multi-agent delegation cannot be replayed across principals/contexts (binding delegation claims to the same request hash). Treat SM/PEI/DAS as *one combined confidentiality-and-binding contribution*, not three separate ones. 

**C4 (optional, if space permits). End-to-end evidence on agent leakage benchmarks + real protocol case study.**
You already have a benchmark-driven evaluation narrative (AgentLeak-style channels and your additional channels) and a plan for external evaluation. Make AP2 a **case study** to emphasize real-world relevance (see §3 below). 

---

### 1.4 Revised paper outline (what to move where)

A structure that better matches top-tier reviewer expectations:

1. **Introduction** (problem → paradox → solution → contributions)
2. **Background & Motivation**

   * Agent tool-use and leakage surfaces
   * Why “guardrails” fail under compromised runtimes
3. **Threat Model & Goals**

   * Adversarial runtime model (your “strong” model)
   * Trust assumptions (gateway/executor, non-collusion, etc.)
4. **Design Overview**

   * SecureClaw architecture at a glance (1 figure)
   * Two core ideas: NBE boundary + SAP privacy
5. **Non-bypassable Effects Protocol**

   * Request canonicalization + `ReqHash`
   * PREVIEW/COMMIT flow
   * Executor acceptance predicate
6. **Control-plane Privacy Paradox and SAP**

   * Define leakage contract (L_{\text{policy}})
   * SAP protocol (fixed-shape PIR + MPC + confirmation)
7. **Formal Security**

   * System-level theorem statement (one)
   * SAP theorem (single-auditor transcript privacy)
8. **Implementation**
9. **Evaluation**

   * RQ1: leakage prevention under benchmark attacks
   * RQ2: SAP privacy (distinguishability/MI)
   * RQ3: multi-agent delegation tests
   * RQ4: cost/latency breakdown
   * **Case study:** AP2 / agent payments (new, see §2–§3)
10. **Limitations & Discussion**
11. Related Work
12. Conclusion

This avoids scattering SAP/security definitions across appendices and makes “control-plane privacy paradox” a first-class storyline.

---

### 1.5 A tightened Introduction (draft text you can paste and iterate)

Below is a draft that is “security-systems top-tier tone” and naturally tees up SAP.

> **Draft Intro (condensed):**
> LLM agents increasingly execute irreversible actions—sending messages, invoking APIs, and operating over sensitive user data. Recent research shows that **prompt injection** can cause tool-calling agents to **exfiltrate personal data observed during task execution**, even when the agent’s primary goal is benign. ([arXiv][1]) At the same time, emerging *agent protocols* for real commerce amplify stakes: the Agent Payments Protocol (AP2) proposes interoperable agent-driven payments, yet red-teaming demonstrates prompt-injection-driven manipulation and information leakage risks in such workflows. ([AP2 Protocol][2])
>
> A natural response is to enforce runtime policies at the moment an action is executed. However, two obstacles arise. First, **agent runtimes are not trustworthy**: a compromised runtime can bypass in-process guardrails by invoking tools directly or fabricating “approved” requests. Second, enforcing policies centrally introduces a new privacy failure mode: the control plane must inspect sensitive inputs (e.g., recipients, domains, identifiers) to decide whether an action is allowed, turning policy servers into high-value privacy sinks. We call this tension the **control-plane privacy paradox**.
>
> We present **SecureClaw**, an execution control plane that (i) enforces a **cryptographically non-bypassable effect boundary**—no external effect can be committed unless an independent executor verifies authorization proofs bound to a canonical request hash—and (ii) resolves the control-plane privacy paradox via **Single‑Auditor Privacy (SAP)**, which outsources policy evaluation to two non-colluding servers using fixed-shape PIR+MPC while proving that any single server’s transcript reveals only a precisely stated leakage function.
>
> We formalize SecureClaw’s threat model, specify the leakage contract required for intent-hiding, and provide simulation-based security theorems for both the effect boundary and SAP. We evaluate SecureClaw on agent leakage benchmarks and show that it prevents exfiltration channels that evade native guardrails, while incurring modest overhead. ([arXiv][1])

---

### 1.6 The control-plane privacy paradox: a precise security model + what SAP protects

#### 1.6.1 Problem definition (paradox)

**Control-plane privacy paradox:**
To *prevent* privacy leaks, an enforcement layer often needs to check sensitive values (recipient addresses, domains, tokens, identifiers) against dynamic policy databases (allowlists, blocklists, IOC feeds, compliance rules). If these checks are performed by a centralized “policy brain,” then the policy plane becomes the place where secrets accumulate (logs, caches, debug traces, compromise). SAP is your answer.

#### 1.6.2 Parties and trust assumptions

Use the clean model you already wrote, but pull it into the main body.

* Runtime (A): adversarial / compromised.
* Gateway (G): trusted mediator that holds secrets/handles and speaks to policy servers and executor.
* Policy servers (P_0, P_1): each holds its own secret key share; **assume non-collusion** (single auditor threat).
* Executor (X): trusted sole effect sink; verifies accept predicate and commits effects.
  This matches your stated assumptions and “single reviewable proposition” framing. 【100:14†FORMAL_SECURITY.md†L1-L29】

#### 1.6.3 What exactly can leak (define it as a leakageady has the right structure: (L_{\text{policy}} = (L_{\text{PIR}}, L_{\text{MPC}}, L_{\text{CONFIRM}}, L_{\text{TIME}})). 【149:11†LEAKAGE_MODEL.md†L1-L24】

In the paper, you should make this *explicitly normative*es you already list):

* endpoint class, public domain size, bundling parameters, tick schedule, padded batch size (PIR side) 【149:11†LEAKAGE_MODEL.md†L1-L24】
* fixed circuit shape / program id, tick schedule, paddeLEAKAGE_MODEL.md†L1-L24】
* confirmation marker/step counters but not secret text ng (time)
* **Forbidden leakage**:

  * true queried index/value (PIR)
  * predicate inputs and raw secrets (MPC/confirm)
  * any “unshaped” per-request metadata that would let a single server infer the sensitive value or the intent class

Then you define:

> **Intent-hiding condition:** two intents are indistinguishable to a single auditor iff they induce identical (L_{\text{policy}}). This is already in your model. 【149:11†LEAKAGE_MODEL.md†L1-L24】

This is crucial: it prevents reviewers from saying “you cleaks the intent.”

#### 1.6.4 SAP security game (simulation-based, single auditor)

You already have a clean experiment definition; promote it.

Let (W) be a workload (sequence of policy queries + confirmations) and (\text{View}*\sigma) be the transcript of one policy server (P*\sigma).

**Experiment (\text{Exp}^{\text{SAP}}(A)):**

1. Adversary outputs (W_0, W_1) s.t. (L_{\text{policy}}(W_0)=L_{\text{policy}}(W_1)).
2. Challenger picks (b\leftarrow{0,1}), runs SAP on (W_b), gives (A) the transcript (\text{View}_\sigma).
3. (A) outputs guess (b'). Advantage is (|\Pr[b'=b]-1/2|). 【149:0†appendix_security copy.txt†L1-L42】

**Goal:** negligible advantage for any PPT adverrotects)
State it as a theorem with explicit assumptions.

> **Theorem (Single‑Auditor Transcript Privacy):**
> Under (i) standard two-server PIR privacy for the query stage, (ii) semi-honest security of the MPC stage, (iii) fixed-shape scheduling that enforces the leakage contract (L_{\text{policy}}), and (iv) non-collusion between (P_0) and (P_1), for each (\sigma\in{0,1}) there exists a simulator (\text{Sim}*\sigma) such that (\text{View}*\sigma) is computationally indistinguishable from (\text{Sim}*\sigma(L*{\text{policy}}(W))). 【149:0†appendix_security copy.txt†L1-L42】

**Interpretation (“what SAP protects”):**
Any  you allow in (L_{\text{policy}}). In particular, it does **not** learn the actual query value (recipient/domain/token) or the predicate inputs used inside the MPC policy evaluation, beyond circuit shape and batch scheduling.

**What SAP does *not* protect (must be explicit):**

* If (P_0) and (P_1) collude, they can reconstruct queries (by design).
* If shapes differ across intents (program_id, endpoint class, batch geometry), a single server can infer intent class; this is captured as *allowed leakage* unless you enforce intent-hiding by construction. 【149:11†LEAKAGE_MODEL.md†L1-L24】
* SAP does not stop leakage through other planes (e.g., ththose are separately handleized / access controlled.

#### 1.6.6 Proof outline (rigorous hybrid you should include)

You already have the right approach; present it as a short but formal hybrid:

* **Lemma 1 (PIR transcript simulation):** Given (L_{\text{PIR}}), simulate (P_\sigma)’s PIR messages using PIR security (one share reveals nothing about index).
* **Lemma 2 (MPC transcript simulation):** Given (L_{\text{MPC}}), simulate (P_\sigma)’s MPC view using semi-honest MPC security (view depends only on circuit shape + allowed metadata).
* **Lemma 3 (Composition under fixed shape):** Because the scheduler and confirmation logic are deterministic functions of (L_{\text{CONFIRM}}, L_{\text{TIME}}), the entire transcript is simulatable from (L_{\text{policy}}).
* **Theorem:** Combine by hybrid argument and union bound. (You already sketched this logic.) 【149:0†appendix_security copy.txt†L1-L42】

This is “strict enough” for top-tier if written ives.

---

### 1.7 Difference vs Faramesh (arXiv:2601.17744)

Faramesh is **very close in spirit** to your NBE story, so you must be extremely crisp: “overlap” is okay, but you must show **orthogonal contribution** that is non-trivial.

**What overlaps:**

* Faramesh proposes an **Action Authorization Boundary (AAB)** with non-bypassable enforcement, deterministic authorization over canonical actions, replayable decision records, fail-closed semantics, and multi-agent support. 【153:0†2601.17744.pdf†L4-L23】
* It explicitly separates reasoning space from execution spacent on a prior PERMIT artifact. 【153:4†2601.17744.pdf†L6-L13】

**Where SecureClaw must claim a distinct contribution (and yfidentiality / privacy is not Faramesh’s focus.**
Faramesh frames intent correctness as out-of-scope and focuses on determinism/replayability at the boundary. 【153:0†2601.17744.pdf†L19-L22】 It does not give a *control-plane privacy* model or a *singlur SAP section is therefore not incremental—it addresses a different axis.

2. **Control-plane privacy paradox + SAP is genuinely orthogonal.**
   Faramesh assumes a control plane that evaluates policies; it does not attempt to hide query values from that plane. Your paper should explicitly say: Faramesh strengthens “decision-before-execution,” while SecureClaw additionally addresses “**who learns the decision inputs**.”

3. **Your binding story is “cryptographic and multi-principal,” not just canonicalization.**
   Faramesh canonicalizes intents into canonical actions (A=\text{Canon}(I)) and binds decisions to (H(A)). 【153:1†2601.17744.pdf†L19-L33】
   SecureClaw’s strongest differentiator is: you bind **deler principal, and handle context** into `ReqHash`, and the executor verifies proof shares bound to that exact hash. This matters for multi-agent and cross-principal replay; make it a headline, not a detail. (Your docs already define `ReqHash` as a canonical JSON hash of required fields.) 【149:9†appendix_security copy.txt†L31-L45】

**Recommendation (to avoid “same paper” revieweork, but add a **one-paragraph “Positioning” box** near the end of the intro:

* “We share the execution-boundary philosophy of Faramesh (AAB), but our paper focuses on two additional problems that AAB does not address: (i) confidentiality under compromised runtimes, and (ii) control-plane privacy when policies are outsourced.”

If you do this, reviewers are much less likely to argue “duplicate.”

---

## 2) Empirical gaps: what to add, and how to design it rigorously

### 2.1 The key evaluation pitfall to fix: mixing threat models

Your own fairness doc states a crucial point: **native guardrails** (Codex/Claude Code/OpenClaw) are not designed for the “compromised runtime” threat model, and the benchmark’s “attack leak rate” is measured as secret token appearance, which does not capture bypass attacks. 【104:6†BASELINES_FAIRNESS.md†L1-L36】

**Actionable change:** In the evaluation section, expA (Native / honest runtime):** attacks are prompt/tool-content injections but runtime cannot bypass enforcement mechanisms.

* **Threat Model B (Compromised runtime):** runtime can exfiltrate and can attempt to bypass policies by calling tools directly, reusing credentials, crafting requests, etc.

Then make it explicit which baselines are meaningful under which model. This avoids the “unfair baseline” critique.

---

### 2.2 Add the missing benchmark class: *bypass* and *control-plane* attacks

Right now, your headline results emphasize C1–C5-style leak channels. Reviewers will ask: “but can the runtime bypass your gateway?”

#### Experiment E1: Bypass suite (compromised runtime)

**Goal:** show NBE is necessary, not just “good policy rules.”

* **Attack:** runtime attempts to:

  1. call the executor directly (no PREVIEW),
  2. replay a previous PERMIT/commit token with modified parameters,
  3. alter a single field (recipient) while keeping other fields constant,
  4. forge `ReqHash` by reordering JSON / injecting extra fields (schema confusion),
  5. replay delegation credentials across principals.
* **Expected outcome:** all are rejected by executor accept predicate due to missing or mismatched proof shares bound to `ReqHash`. 【108:6†SECURECLAW_PROTOCOL_RFC_v1.md†L54-L63】【149:9†appendix_security copy.txt†L31-L45】
* *d to fail under this model; make that explicit)
* **Metrics:**

  * bypass success rate (% effects committed)
  * false positives on benign commits
  * reject reason histogram

This directly defends your main systems claim.

#### Experiment E2: Control-plane compromise (single auditor)

**Goal:** demonstrate SAP’s promise: a single policy server cannot infer sensitive query values.

* **Setup:** instrument each policy server to log its full network transcript and timing.
* **Task:** run two workloads (W_0, W_1) with equal (L_{\text{policy}}) but different sensitive query values (recipient/domain).
* **Adversary:** train best-effort distinguishers:

  * supervised classifier on transcript features,
  * mutual information estimates,
  * timing-only distinguisher.
* **Expected outcome:** accuracy ~50% and MI ~0 under SAP; substantial signal under single-server policy. (This matches the logic of your current distinguishability tables.) 【149:0†appendix_security copy.txt†L1-L42】

**Important:** report *confidence intervals* andaining size, etc.) so reviewers cannot dismiss “classifier failed” as weak.

---

### 2.3 Add a real-world *agent protocol* case study: AP2 (high impact, high novelty)

This is the most important missing empirical addition for 2026-era agent papers: show relevance to an actual agent protocol ecosystem.

#### Experiment E3: AP2 prompt-injection red-team reproduction + mitigation

**Why AP2:** it is an explicit “agent protocol for payments,” widely publicized and open-source. ([GitHub][3])
And there is already a red-teaming paper showing prompt-injection-based attacks against it. ([arXiv][4])

**Design:**

* Use the official AP2 sample agents (shopping agent + credential provider + merchant) as the workload. ([GitHub][3])
* Implement/port the attack patterns from “Whispers of Wealth” (prompt injection leading to manipulation/leakage). ([arXiv][4])
* Wrap AP2’s effectful operations (mandate creation/submission, merchant requests, credential retrieval) behind SecureClaw’s PREVIEW/COMMIT path.

**Metrics:**

* unauthorized payment mandate rate (should be 0 unless user confirms)
* sensitive data leakage rate (tokens, addresses, credentials)
* utility drop (successful shopping completion)
* latency overhead (p50/p95 for authorization path)

**Baselines:**

* Vanilla AP2
* AP2 + “prompt shields / DLP style filter” (e.g., a content-safety gate), noting that such tools scan prompts but do not enforce a non-bypassable execution boundary. ([Microsoft Learn][5])
* AP2 + SecureClaw (with and without SAP)

**What you can claim if results are good:**
SecureClaw is not just a benchmark toy; it composes with real agent protocols.

---

### 2.4 Add an academic benchmark that targets “personal data exfiltration” explicitly (AgentDojo extension)

A strong recent paper shows prompt injection can cause **tool-calling agents** to leak personal data observed during execution, using AgentDojo-based tasks and banking conversations. ([arXiv][1])

#### Experiment E4: AgentDojo exfiltration tasks

* Integrate SecureClaw with the fictitious banking agent / AgentDojo harness.
* Reproduce their “data-flow based attacks.”
* Compare:

  * vanilla agent,
  * vanilla + prompt shields / filters,
  * SecureClaw (SM on/off, SAP on/off).

This will directly answer reviewers asking “does this generalize beyond your benchmark?”

---

### 2.5 Add a multimodal / computer-use benchmark (if you claim coverage)

If you claim coverage over computer-use agents (CUAs), you need to acknowledge that **visual prompt injection** is now benchmarked and can induce unauthorized actions and leaks. VPI-Bench reports 306 test cases and non-trivial deception rates. ([iclr.cc][6])

#### Experiment E5: VPI-Bench subset as a “stress test”

* Pick a subset where the harmful outcome is an effect you can route through the executor (file write, network send, credential access).
* Show: without an effect boundary, CUA can be tricked; with SecureClaw, harmful effects require proof + confirmation.
* If some actions bypass the executor (true UI mouse moves), explicitly call that a limitation and propose a wrapper architecture (route UI primitives through a controlled “UI executor”).

Even a partial experiment is better than handwaving.

---

### 2.6 Fixing performance evaluation presentation (avoid unfair comparisons)

Your own docs recommend that “native baseline” end-to-end time includes LLM latency, so don’t conflate it with control-plane overhead. Present overhead as:

* microbench for PIR/MPC/proof verification,
* end-to-end overhead **conditional on identical agent runtime** (ablation modes such as `single_server_policy`, `policy_only`, `mirage_full`, and shaping variants). 【104:11†README.md†L1-L22】

This avoids the reviewer complaint: “you compared against a system that spends 20s in LLM inference.”

---

## 3) Recent (last ~12 months) privacy-leakage pain points for agents/multi-agent/AP2 — and whether SecureClaw addresses them

Below are concrete pain points with credible sources, and a mapping to SecureClaw.

### 3.1 Prompt injection → personal dool use

**Pain point:** prompt injection can cause tool-calling agents to leak personal data they observe while completing tasks; the AgentDojo-integrated study reports attack success and shows no built-in AgentDojo defense fully prevents leakage in their extended evaluation. ([arXiv][1])
**Does SecureClaw help?** Likely **yes**, if you deploy:

* **Secret myopia (SM):** the runtime never sees plaintext secrets unless explicitly declassified.
* **Non-bypassable effect boundary (NBE):** network send / message send cannot occur without executor authorization.

**What you still need to prove empirically:** E4 (AgentDojo exfil tasks) above.

---

### 3.2 Multimodal / computer-use agents: visual prompt injection and unauthorized actions/leaks

**Pain point:** VPI-Bench defines an end-to-end threat model for visual prompt injection that can induce CUAs to perform unauthorized actions or leak data; it introduces 306 test cases and reports deception rates up to 51%/100% on some platforms. ([iclr.cc][6])
**Does SecureClaw help?** **Partially**, depending on deployment:

* If all effectful actions (file/network/privileged ops) are routed via the executor, NBE can block unauthorized outcomes.
* If the CUA can directly operate the OS/UI without mediation, SecureClaw cannot prevent those UI-level side effects unless you *architecturally* route them through the boundary (which you should discuss as a limitation + mitigation design).

**Benchmark to use:** VPI-Bench subset (E5).

---

### 3.3 Enterprise “zero-click / second-order” prompt injection across connected systems (multi-agent / connectors)

**Pain point:** security researchers report second-order prompt injection chains in enterprise tools (e.g., ServiceNow Now Assist examples) where untrusted content can trigger downstream agent actions and data exposure. ([arXiv][4])
**Does SecureClaw help?**

* **Yes for egress**: if the harmful effect requires COMMIT, it is gated.
* **Yes for cross-principal replay**: if a low-priv agent tries to coerce a high-priv agent, your delegation-binding story should stop replays across principals if you bind delegation claims to `ReqHash` and enforce capability intersection.
* **But**: if the high-priv agent is legitimately allowed to declassify data and the attacker tricks it into requesting declassification, you still need UI confirmation or explicit policy.

**Experiment to add:** multi-agent “second-order injection” campaign (build from E1/E3/E4 style workloads).

---

### 3.4 AP2 (Agent Payments Protocol): privacy leakage and prompt-injection manipulation

**Pain point:** AP2 is intended to enable secure agent-driven payments via a role-based architecture (shopping agent, merchant, credential provider, etc.). ([AP2 Protocol][2])
But a recent red-teaming study reports prompt-injection-based attacks against AP2. ([arXiv][4])
**Does SecureClaw help?** Potentially **yes**, in two ways:

1. **Effect integrity:** payment submission becomes a COMMIT requiring authorization artifacts and (optionally) user confirmation.
2. **Secret containment:** credentials and sensitive identifiers can be handleized so the shopping agent cannot exfiltrate them directly.

**But you cannot claim this without data.**
You should run E3 (AP2 case study) and report end-to-end results.

---

### 3.5 Industry governance: DLP for AI prompts/responses creates new privacy sinks (control-plane paradox in the wild)

**Pain point:** vendors are actively shipping **DLP and compliance controls for generative AI**, including Microsoft Purview protections for Copilot and other AI apps. ([Microsoft Learn][7])
These controls often rely on scanning/recording prompts and responses for monitoring (which can itself create sensitive logs). ([CIAOPS][8])
Additionally, recent incidents show that even when sensitivity labels/DLP are configured, bugs can cause unintended AI processing of confidential items. ([BleepingComputer][9])

**Does SecureClaw help?**

* **Directly relevant to SAP:** SAP is precisely about enabling policy enforcement without revealing query values to a single policy server. That’s a concrete answer to “the policy plane is now a privacy sink.”
* **However:** SAP does not automatically solve *misconfiguration or code-path bugs* in an upstream retrieval system that hands data to an agent. To address those, you need the broader SecureClaw architecture: keep sensitive data behind handles and require explicit declassification.

**Experiment to add:** an “enterprise DLP proxy” baseline showing that central inspection can leak, while SAP single-auditor privacy holds.

---

## Suggested next steps (what you should do *next* to maximize acceptance odds)

1. **Rewrite intro + contributions** to the 3-core-contribution structure above, with the control-plane privacy paradox as the “why SAP exists.”
2. **Move SAP leakage model + theorem into the main body** (not appendix), because reviewers treat privacy proofs as core correctness.
3. **Add two killer evaluations:**

   * E1 Bypass suite (proves necessity under compromised runtime)
   * E3 AP2 case study (proves real-world relevance and distinguishes from Faramesh)
4. **Add one external benchmark:** AgentDojo exfiltration tasks (E4), because it is a strong, recent academic signal. ([arXiv][1])
5. **Cleanly separate performance overhead from LLM latency** using your own ablation modes. 【104:11†README.md†L1-L22】

---

### Repository / draft artifacts referenced



[1]: https://arxiv.org/abs/2506.01055 "https://arxiv.org/abs/2506.01055"
[2]: https://ap2-protocol.org/topics/privacy-and-security/ "https://ap2-protocol.org/topics/privacy-and-security/"
[3]: https://github.com/google-agentic-commerce/AP2 "https://github.com/google-agentic-commerce/AP2"
[4]: https://arxiv.org/abs/2601.22569 "https://arxiv.org/abs/2601.22569"
[5]: https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection "https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection"
[6]: https://iclr.cc/virtual/2026/poster/10009231 "https://iclr.cc/virtual/2026/poster/10009231"
[7]: https://learn.microsoft.com/en-us/purview/ai-microsoft-purview "https://learn.microsoft.com/en-us/purview/ai-microsoft-purview"
[8]: https://blog.ciaops.com/2025/01/10/viewing-copilot-prompt-and-responses-across-the-organisation/ "https://blog.ciaops.com/2025/01/10/viewing-copilot-prompt-and-responses-across-the-organisation/"
[9]: https://www.bleepingcomputer.com/news/microsoft/microsoft-says-bug-causes-copilot-to-summarize-confidential-emails/ "https://www.bleepingcomputer.com/news/microsoft/microsoft-says-bug-causes-copilot-to-summarize-confidential-emails/"
