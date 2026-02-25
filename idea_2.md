According to a document from **2026-02-24**, your SecureClaw snapshot already has the right *spine* for “threat vignette → mechanism → theorem”: a single PREVIEW→COMMIT enforcement line (executor accept predicate) with **request-hash binding**, **dual proofs**, **replay+TTL**, and **sanitization patch enforcement**. 

Below I refine **three non-SAP-centric contribution directions** into *paper-grade*, strictly-defined mechanisms with explicit games and theorem statements. I keep notation consistent with your artifact: `rho`, `hctx`, `ReqHash`, `pi_s`, `Accept`. 

---

## Shared system model and notation (used by all three directions)

### Parties and interfaces

* Untrusted runtime/skills adversary: (\mathcal A) (PPT).
* Trusted gateway: (\mathcal G).
* Two policy servers: (\mathcal P_0,\mathcal P_1) (honest for integrity; HBC for privacy when applicable).
* Trusted executor (only effect sink): (\mathcal X).
* User confirmation source: (\mathcal U).
* Optional capsule boundary: (\mathcal C). 

Gateway entrypoint:
[
\texttt{act}(\mathsf{intent_id},\mathsf{inputs},\mathsf{constraints},\mathsf{caller})
]
returns ((\mathsf{status},\mathsf{reason},\mathsf{data},\mathsf{artifacts})). Executor exposes effectful endpoints that require commit evidence. 

### Request tuple, hash context, and binding hash

Define the bound request tuple:
[
\rho := (\mathsf{intent_id},\mathsf{caller},\mathsf{session},\mathsf{inputs_eff},\mathsf{hctx})
]
where the **hash context** is:
[
\mathsf{hctx} := (\mathsf{external_principal},\mathsf{delegation_jti})
]
(serialized with absent fields omitted; empty object if none). 

Request binding hash:
[
\mathsf{ReqHash}(\rho)=\mathrm{SHA256}(\mathsf{CanonJSON}({\texttt{v}=1,\texttt{intent_id},\texttt{caller},\texttt{session},\texttt{inputs},\texttt{context}=\mathsf{hctx}}))
]
with an engineering assumption that canonicalization is consistent between (\mathcal G) and (\mathcal X). 

### Commit proof shares and executor acceptance predicate

Each policy server (\mathcal P_s) produces a commit proof share:
[
\pi_s=(\mathsf{meta}_s,\mathsf{mac}_s)\quad s\in{0,1}
]
where (\mathsf{meta}_s) includes ((\mathsf{action_id},\mathsf{program_id},\mathsf{request_sha256}=\mathsf{ReqHash}(\rho),\ldots)) and (\mathsf{mac}*s=\mathrm{HMAC}*{K_s}(\mathsf{Canon}(\mathsf{meta}_s))). 

Executor accepts iff the predicate (\mathsf{Accept}(\mathsf{req},\pi_0,\pi_1)) holds, including:

* dual MAC validity + distinct server IDs,
* freshness: (|\mathrm{now}-\tau|\le \mathrm{TTL}),
* request binding: recomputed (\mathsf{ReqHash}(\rho(\mathsf{req}))) matches proof hash,
* replay rejection,
* policy bits (allow/confirm),
* **sanitization patch constraints**. 

This gives the “non-bypassable effects” backbone: any bypass implies MAC forgery, hash collision/inconsistency, or replay-store assumption failure. 

---

# Direction 1: Myopic Secrets + Explicit Declassification + Patch-Carrying Egress Enforcement

### Threat vignette (what breaks without this)

A prompt-injected runtime coerces the agent to:

1. fetch a secret (PII/API key) from a tool,
2. embed it into an outbound email/Slack/webhook,
3. try multiple formatting tricks until a policy lets it pass.

Even if PREVIEW blocks some attempts, a single “allowed” attempt could exfiltrate plaintext unless (i) secrets never enter runtime plaintext, and (ii) the executor *enforces* any required sanitization patch at COMMIT.

Your artifact already frames this as “secret myopia” (handles) plus confirm-gated declassification plus sanitize enforcement at the executor. 

---

## Mechanism

1. **Handleization discipline (Secret Myopia)**: sensitive plaintext is stored only inside (\mathcal G) as a record keyed by a random opaque handle (h); (\mathcal A) sees only (h) + non-sensitive metadata. 

2. **Explicit declassification**: plaintext can be released only via an explicit interface that requires user confirmation and is policy-controlled and audited. 

3. **Patch-carrying enforcement at COMMIT**: policy output includes a sanitize patch identifier and/or patch parameters; executor applies `apply_required_sanitize_patch(outs, req)` before performing the effect, and acceptance requires patch constraints hold. 

---

## Strict definitions

### Data types

* Secret space (S): fixed-length strings (or equal-length padded).

* Handle ID space (\mathcal H): uniform identifiers with ≥128-bit entropy.

* Handle record:
  [
  \mathsf{HR}=(s,\ell,\mathsf{sinks},\mathsf{ttl},\mathsf{session},\mathsf{caller})
  ]
  where (\ell) is a sensitivity label. 

* Sanitization patch space (\mathcal P). We model the patch as a deterministic function:
  [
  \mathsf{Sanitize}:\mathcal P\times \mathsf{Req}\to \mathsf{Req}
  ]
  and define (\mathsf{Req}'=\mathsf{Sanitize}(p,\mathsf{Req})) as the payload actually committed.

### Leakage function for SM

Define the allowed leakage to the untrusted runtime for “secret myopia”:
[
L_{\mathsf{SM}} := (\text{handle ids},\text{labels},\text{ttls},\text{policy bits},\text{sanitize patch ids},\text{explicitly declassified outputs})
]
This matches your appendix definition. 

---

## Algorithms (paper-pseudocode level)

### Algorithm 1 — HandleizeSensitiveFields

**Input:** (\mathsf{inputs}), (\mathsf{caller}), (\mathsf{session})
**Output:** (\mathsf{inputs_eff})

For each key (k) in (\mathsf{inputs}):

1. If (k) is sensitive, sample (h \leftarrow \mathcal H) uniformly; store (\mathsf{HR}_h) with plaintext and bindings; set (\mathsf{inputs_eff}[k]=h).
2. Else set (\mathsf{inputs_eff}[k]=\mathsf{inputs}[k]).

**Invariant:** (\mathcal A) never receives sensitive plaintext from (\mathcal G) except via Declassify. 

### Algorithm 2 — Declassify

**Input:** handle (h), sink (t), user-confirm flag, request context
**Output:** plaintext (s) or DENY

1. Require `user_confirm=true` if (\ell) is high-sensitivity.
2. Require policy decision allows declassification to sink (t).
3. Emit audit event (with reason code + bindings).
4. Return (s). Otherwise DENY.

(Exactly the “explicit declassification requires confirmation and is policy-controlled” condition used by your SM theorem.) 

### Algorithm 3 — ExecutorCommit with patch enforcement

Use your executor pseudocode, emphasizing the patch step before effect:

1. verify dual proofs & binding
2. replay check
3. check `allow_pre` and confirmation bit
4. **apply_required_sanitize_patch(outs, req)**
5. perform effect
6. append audit record. 

---

## Security experiments and theorems

### Game (G_{\mathsf{SM}}) (Secret Myopia)

Challenger samples (b\in{0,1}), stores one of two equal-length secrets (s_b) behind a handle, and gives (\mathcal A) oracle access to `act` and to declassification subject to policy+confirmation. (\mathcal A) wins if it outputs (b') with non-negligible advantage without a declassification event that reveals (s_b). 

### Theorem (T_{\mathsf{SM}}) (as in your model)

Assume:

1. gateway returns only opaque handles for sensitive values,
2. handle IDs are independent of plaintext with ≥128 bits entropy,
3. declassification is explicit, logged, and policy-controlled.
   Then runtime view is simulatable from (L_{\mathsf{SM}}), and for at most (q_h) online handle guesses:
   [
   \Pr[\mathsf{Bad}_{\mathsf{SM}}]\le q_h/2^{128}+\mathrm{negl}(\lambda).
   ]


### Game (G_{\mathsf{PATCH}}) (Patch-carrying egress integrity)

Adversary outputs an effect request (\mathsf{req}^\star) and commit evidence ((\pi_0^\star,\pi_1^\star)). It wins if:

1. (\mathsf{Accept}(\mathsf{req}^\star,\pi_0^\star,\pi_1^\star)=1), but
2. the committed effect payload (\mathsf{payload}_{\mathrm{commit}}\neq \mathsf{payload}(\mathsf{Sanitize}(\mathsf{patch}^\star,\mathsf{req}^\star))).

### Theorem (T_{\mathsf{PATCH}})

Assume the executor implements (\mathsf{Accept}) and `apply_required_sanitize_patch` exactly as specified, and all effect sinks go through (\mathcal X). Then:
[
\Pr[\mathsf{Bad}*{\mathsf{PATCH}}] \le \varepsilon*{\mathrm{impl}}
]
where (\varepsilon_{\mathrm{impl}}) is the probability of implementation/spec divergence (ideally 0 under mechanized checks / tests). The “patch constraints hold” condition is explicitly part of acceptance. 

**Proof sketch:** If (\mathsf{Accept}=1), the algorithm must apply the patch before performing the effect; thus a mismatch implies a violation of the executor’s specified behavior.

---

# Direction 2: Skill Supply-Chain Safety via a Verifiable Capsule Mediation Contract + Effectful Skill Install

### Threat vignette

A malicious skill package (supply chain):

* reads host secrets (SSH keys, cloud credentials),
* directly exfiltrates to the public internet,
* or spawns a process to escape restrictions,
  without ever invoking the gateway/executor enforcement line.

This is *not* solved by policy-only or prompt-only defenses; it needs a **runtime confinement assumption** that is explicit and testable, and then composition with NBE/SM. Your docs already position this as “Skill-Confined Safety (SCS) is conditional on a capsule mediation contract.” 

---

## Mechanism

1. **Capsule mediation contract** (MC): a predicate over the runtime environment guaranteeing filesystem/network/process confinement + constrained transport to gateway. It is validated by a smoke-test/verifier and has fail-closed downgrade semantics. 

2. **Treat skill install as an effectful action**: installs go through the same PREVIEW→COMMIT and executor verification (so you can’t install without dual authorization). The paper explicitly claims skill supply chain ingress is protected by the same transaction and dual-proof executor verification. 

3. **Post-install identity narrowing**: after install, caller becomes `skill:<digest>` and capabilities are not inherited wholesale (as stated in your eval plan). 

---

## Strict definitions

### Capsule contract predicate (MC)

Let (MC(\mathcal C)) be true iff the runtime capsule enforces, at minimum:

* no host secret reads,
* no public internet access,
* no loopback HTTP exfil (when disallowed),
* no arbitrary exec,
* gateway `act` path remains usable.
  These are explicitly listed as mandatory assertions for claiming SCS. 

Downgrade rule: if contract verification fails, SCS claim is invalid and deployment must fail closed for skill operations or enter a reduced-claim mode (keep NBE/SM/SAP if still valid). 

---

## Algorithms

### Algorithm 4 — VerifyCapsuleContract

Run platform-specific probes and output verdict JSON:

* if any mandatory assertion fails → `status=FAIL`, disable SCS claim.
* else `status=OK`, enable SCS claim for that environment profile. 

### Algorithm 5 — SkillInstall as PREVIEW→COMMIT

1. Gateway computes `skill_digest` of package and policy features (IOC hits etc.).
2. `PREVIEW` returns `(action_id, request_sha256, commit_evidence)` for intent `SkillInstall(digest, …)`.
3. Executor `COMMIT` verifies dual proofs and then performs the install.

(You already treat skill ingress as effectful and route it through the same enforcement line in your positioning text.) 

---

## Security experiment and theorem

### Game (G_{\mathsf{SCS}})

Adversary controls skill code running inside capsule and attempts forbidden direct actions:

1. host secret reads, 2) arbitrary exec, 3) direct public internet exfil, 4) disallowed loopback exfil.
   Win event (\mathsf{Bad}_{\mathsf{SCS}}): a forbidden direct action succeeds while (MC) is declared active. 

### Theorem (T_{\mathsf{SCS}}) (as in your model)

Assume:

1. (MC) holds,
2. all effectful operations require the executor path,
3. NBE and SM hold for the gateway-executor path.
   Then:
   [
   \Pr[\mathsf{Bad}*{\mathsf{SCS}}]\ \le\ \Pr[\neg MC]\ +\ \Pr[\mathsf{Bad}*{\mathsf{NBE}}]\ +\ \Pr[\mathsf{Bad}_{\mathsf{SM}}]\ +\mathrm{negl}(\lambda),
   ]
   i.e., bounded by contract-violation probability plus negligible cryptographic failures of NBE/SM. 

**Proof sketch:** Under (MC), direct exfil/secret reads/exec are blocked. Remaining routes go through gateway/executor; NBE prevents bypassing commit authorization; SM prevents plaintext access by the runtime absent declassification.

---

# Direction 3: Delegated Authority + Dual-Subject Authorization + Federated Ingress Binding (anti-confused-deputy as a cryptographically bound property)

### Threat vignette

In a multi-agent / federated deployment, an attacker causes “confused deputy” behavior:

* reuse a delegation token across sessions,
* swap the caller identity or external principal,
* replay a previously authorized PREVIEW under a different principal,
* bypass revocation by racing replays.

Without binding *delegation context* and *ingress identity* into the request hash that the executor checks, you can get replay/impersonation even if effects are “non-bypassable” in a narrow sense.

Your paper already states the key defense: (i) delegation tuple (\delta) with `jti` revocation, (ii) effective authorization is an intersection of internal+external capabilities, and (iii) ingress claims are bound into request hashing context so PREVIEW cannot be replayed under a different principal or delegation identifier. 

---

## Mechanism

1. **Delegated authority token**:
   [
   \delta := (\mathsf{iss},\mathsf{sub},\mathsf{scope},\mathsf{session},\mathsf{exp},\mathsf{jti})
   ]
   signed by an operator-managed key. Gateway verifies session binding, subject pattern, scope coverage, and revocation (`jti` not revoked), failing closed otherwise. 

2. **Dual-subject / intersection authorization**:
   [
   \mathsf{effective_caps} = \mathsf{caps}(\mathsf{caller})\ \cap\ \mathsf{caps}(\mathsf{external_principal})
   ]
   This prevents “external principal upgrades internal actor” and “internal actor bypasses external policy constraints.” 

3. **Federated ingress binding into (\mathsf{hctx})**: gateway may require pinned client cert hash, signed request envelope with nonce/ts anti-replay, and short-lived proof token; when enabled, these ingress claims are bound into request hashing context so PREVIEW authorization cannot be replayed under different principal/identifier. 

---

## Strict definitions

### Delegation verification predicate

Let (\mathsf{VerifyDelegation}(\delta,\mathsf{caller},\mathsf{session},\mathsf{intent_id})) be 1 iff:

1. signature verifies,
2. (\delta.\mathsf{session}=\mathsf{session}),
3. (\mathsf{caller}\in \delta.\mathsf{sub}) (pattern match),
4. (\mathsf{intent_id}\in \delta.\mathsf{scope}),
5. (\delta.\mathsf{jti}\not\in \mathsf{Revoked}),
6. (\mathrm{now}\le \delta.\mathsf{exp}). 

### Hash context binding

Define:
[
\mathsf{hctx}:=(\mathsf{external_principal}=\delta.\mathsf{iss},\ \mathsf{delegation_jti}=\delta.\mathsf{jti},\ \mathsf{ingress_claims})
]
where (\mathsf{ingress_claims}) is empty unless federated ingress is enabled. The key property is: (\mathsf{hctx}) is included in (\mathsf{ReqHash}), so the executor’s recomputation binds authorization to the delegation+ingress context. 

---

## Algorithms

### Algorithm 6 — GatewayAct with delegation + dual-subject caps

1. Parse constraints to extract (\delta) and ingress claims; set (\mathsf{hctx}).
2. If (\delta) present: require (\mathsf{VerifyDelegation}=1). Else (\mathsf{external_principal}) absent.
3. Compute (\mathsf{effective_caps} = \mathsf{caps}(\mathsf{caller})\cap\mathsf{caps}(\mathsf{external_principal})) when external principal exists.
4. Handleize sensitive fields → (\mathsf{inputs_eff}).
5. Compute (h=\mathsf{ReqHash}(\rho)).
6. Run privacy-preserving policy checks (or plaintext policy checks; this direction is orthogonal to SAP).
7. Return PREVIEW artifacts (dual commit evidence) if allowed. 

---

## Security experiment and theorem

### Game (G_{\mathsf{DEL}}) (Delegation/ingress binding soundness)

Challenger runs the system with honest (\mathcal G,\mathcal X). Adversary controls runtime and can:

* request legitimate PREVIEWs under some valid (\delta),
* later attempt to COMMIT a request under *different* (\delta'), different (\mathsf{external_principal}), different ingress identity, or different session/caller.

Win event (\mathsf{Bad}_{\mathsf{DEL}}) occurs if executor accepts an effect request whose effective authorization context (caller/session/hctx) is not the one bound into the commit evidence used for acceptance.

### Theorem (T_{\mathsf{DEL}}) (Binding prevents confused-deputy replays)

Assume:

1. delegation signatures are EUF-CMA secure (forgery negligible),
2. (\mathsf{ReqHash}) is collision-resistant and canonicalization is consistent,
3. executor enforces (\mathsf{Accept}) including recomputation of (\mathsf{ReqHash}) over (\mathsf{hctx}),
4. time/replay assumptions of NBE hold.

Then any attempt to reuse commit evidence under a different caller/session/hctx fails except with negligible probability plus explicit assumption-failure terms:
[
\Pr[\mathsf{Bad}*{\mathsf{DEL}}] \le \Pr[\mathsf{Bad}*{\mathsf{NBE}}] + \mathrm{Adv}^{\mathrm{euf\text{-}cma}}*{\mathsf{Sig}} + \mathrm{Adv}^{\mathrm{coll}}*{\mathrm{SHA256}} + \varepsilon_{\mathrm{canon}}.
]

**Why this is tight in your artifact:** you already note that session/caller/TTL binding is incorporated because they are included in (\mathsf{ReqHash}) together with (\mathsf{hctx}); reusing proofs for different caller/session/hctx must fail or imply collision. 

---

## What makes these three directions “top-tier-ready” as contributions (in reviewer language)

* **Direction 1** is a crisp confidentiality+integrity story: *myopic secret storage* + *explicit declassification* + *executor-enforced patching*. It yields a simple, checkable leakage function and an explicit bound (q_h/2^{128}). 
* **Direction 2** elevates “sandboxing” from a hand-wavy assumption into a **verifiable contract** with mandatory assertions and downgrade semantics; then composes it with NBE+SM. That’s exactly the kind of “systems+security” rigor reviewers reward. 
* **Direction 3** turns “OAuth-ish delegation” into a *cryptographically bound anti-confused-deputy property* by binding delegation + ingress context into (\mathsf{ReqHash}) that the executor enforces, and by using intersection capabilities. This is concrete, mechanizable, and measurably valuable in federated/multi-agent setups. 

If you want, I can next turn these into **camera-ready theorem blocks + definition blocks** exactly in NeurIPS appendix style (matching your existing Theorem environments and the “single reviewable proposition” framing). 
