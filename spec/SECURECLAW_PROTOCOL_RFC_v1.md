# SecureClaw Protocol RFC v1

Status: Draft for artifact and paper reproducibility  
Version: `1`  
Normative language: `MUST`, `MUST NOT`, `SHOULD`, `MAY`

This document specifies the interface contracts for `act`, `PREVIEW`, `COMMIT`, commit evidence, and the executor acceptance predicate. It is intentionally aligned with machine-checkable artifacts in `spec/`.

## 1. Scope

This RFC defines:

1. The stable request and response envelope for gateway entrypoint `act`.
2. PREVIEW outputs that are required to authorize COMMIT.
3. COMMIT evidence structure and semantic validation.
4. Executor acceptance predicate and failure codes.
5. Versioning and compatibility rules for evolving wire formats.

This RFC does not define:

1. The internal cryptographic implementation details of PIR or 2PC.
2. The full policy language semantics beyond the output bits consumed by the executor.
3. Host kernel side channel guarantees.

## 2. Normative Artifacts

The following files are normative for wire semantics:

1. `spec/secureclaw_executor_accept_v1.schema.json`
2. `spec/secureclaw_accept_predicate_v1.json`
3. `spec/secureclaw_capsule_contract_v1.schema.json`
4. `spec/secureclaw_capsule_contract_v1.json`

The following code paths are normative for runtime behavior:

1. `gateway/mcp_server.py`
2. `gateway/router.py`
3. `gateway/egress_policy.py`
4. `gateway/policy_unified.py`
5. `executor_server/server.py`
6. `scripts/verify_accept_predicate.py`

## 3. Data Model

### 3.1 Action Request Tuple

Define the bound request tuple:

`rho = (intent_id, caller, session, inputs_eff)`

where:

1. `intent_id` is a high-level action name.
2. `caller` is an untrusted identity string.
3. `session` is the runtime session binding.
4. `inputs_eff` are the effectful fields used by request hash binding.

Define the hash context tuple:

`hctx = (external_principal, delegation_jti)`

Define the commit context tuple:

`ctx = (action_id, program_id, request_sha256, hctx)`

`request_sha256` MUST be computed by the canonical hash function in `common/canonical.py:request_sha256_v1`.

### 3.2 `act` Request

`act` MUST accept a JSON object with fields:

1. `intent_id: string` REQUIRED
2. `inputs: object` REQUIRED
3. `constraints: object` REQUIRED
4. `caller: string` REQUIRED

No additional top-level fields are allowed by the MCP tool schema.

`constraints` MAY include:

1. `external_principal: string`
2. `delegation_token: string`
3. `user_confirm: boolean`

When HTTP ingress federation is enabled, these fields are bound to trusted ingress headers and runtime-supplied conflicting values MUST be rejected.

### 3.3 `act` Response Envelope

Gateway responses are normalized into:

1. `status: "OK" | "DENY"` REQUIRED
2. `reason_code: string` REQUIRED
3. `summary: string` OPTIONAL
4. `data: object` OPTIONAL
5. `artifacts: array` OPTIONAL

For effectful intents, PREVIEW results MUST include `tx_id`, `action_id`, and `request_sha256` either in `data` or inside a documented artifact record.

## 4. PREVIEW and COMMIT

### 4.1 PREVIEW Output Contract

A successful PREVIEW MUST produce:

1. `tx_id` with TTL bounded by `TX_TTL_S`.
2. `action_id`.
3. `request_sha256`.
4. `allow_pre` and `need_confirm` bits.
5. `patch` object used for sanitize semantics.
6. `commit_evidence` containing dual policy shares.

PREVIEW MUST bind `tx_id` to:

1. `session`.
2. `caller`.
3. `action_id`.
4. `request_sha256`.
5. `auth_context` which includes `external_principal` and `delegation_jti` when present.

### 4.2 COMMIT Input Contract

A COMMIT request to executor endpoints MUST include:

1. Effect-specific input fields.
2. `action_id`.
3. `commit` object with `policy0` and `policy1`.
4. Optional user confirmation flag for confirm-required actions.
5. Optional `external_principal` and `delegation_jti` fields when delegation is in use.

Executor MUST recompute `request_sha256` from received request payload and compare with both proof shares.

## 5. Commit Evidence

### 5.1 Structural Requirements

Commit evidence MUST satisfy `spec/secureclaw_executor_accept_v1.schema.json`.

Each share (`policy0`, `policy1`) MUST contain:

1. `v`, `kind`, `server_id`, `kid`, `ts`.
2. `action_id`, `program_id`, `request_sha256`.
3. `outputs`.
4. `commit_tag_share_b64`.
5. `mac_b64`.

### 5.2 Semantic Requirements

Semantic validation MUST satisfy `spec/secureclaw_accept_predicate_v1.json` and `scripts/verify_accept_predicate.py`:

1. `kid` MUST resolve to a key in the corresponding executor keyring.
2. MAC verification MUST succeed for both shares.
3. Share timestamps MUST satisfy `POLICY_MAC_TTL_S`.
4. `program_id` MUST equal configured program id.
5. Required output keys MUST exist in both shares.
6. `commit_tag_share_b64` decoded length MUST equal `commit_tag_share_len_bytes`.
7. Reconstructed outputs MUST satisfy policy acceptance conditions.

## 6. Executor Acceptance Predicate

Executor MUST return `status="OK"` with allow semantics only if all checks pass:

1. Structural schema valid.
2. Dual MAC valid and server identities consistent.
3. `request_sha256` equals recomputed request hash.
4. Replay guard has not seen this `action_id`.
5. `allow_pre == 1`.
6. If `need_confirm == 1`, user confirmation is true.
7. Sanitize patch constraints are respected.

Any failed check MUST fail closed.

## 7. Error Code Registry

### 7.1 Gateway-Side Common Codes

1. `UNKNOWN_INTENT`
2. `CAPABILITY_DENY`
3. `PRINCIPAL_CAPABILITY_DENY`
4. `WORKLOAD_TOKEN_INVALID`
5. `TX_INVALID`
6. `TX_SESSION_MISMATCH`
7. `TX_CALLER_MISMATCH`
8. `TX_AUTH_CONTEXT_MISMATCH`
9. `POLICY_DENY`
10. `REQUIRE_CONFIRM`
11. `ALLOW`
12. `HIGH_HANDLE_BLOCKED`
13. `IOC_BLOCKED`
14. `DELEGATION_REQUIRED`
15. `DELEGATION_REVOKED`
16. `DELEGATION_SCOPE_DENY`

### 7.2 Executor-Side Common Codes

1. `BAD_COMMIT_PROOF`
2. `POLICY_DENY`
3. `REQUIRE_CONFIRM`
4. `REPLAY_DENY`
5. `MISSING_EVIDENCE`
6. `ALLOW`
7. `ALLOW_INSECURE` for explicitly insecure mode only

### 7.3 Invariant on Insecure Mode

If `EXECUTOR_INSECURE_ALLOW=1`, responses MAY return `ALLOW_INSECURE`; this mode MUST be treated as out of claim scope.

## 8. Safety Invariants

The following invariants are normative:

1. No side effect commit without dual valid proofs and request hash match.
2. No side effect commit on replayed `action_id` within replay window.
3. No bypass from PREVIEW binding through caller or session mismatch.
4. No bypass from PREVIEW binding through `external_principal` or `delegation_jti` mismatch.
5. No plaintext high-sensitivity release without explicit declassification path.
6. No silent downgrade from verified capsule mediation to unverified mode.

## 9. Versioning and Compatibility

### 9.1 Versioned Objects

1. Commit shares use `v = 1`.
2. Capsule contract uses `version = 1`.
3. Accept predicate semantic spec uses `version = 1`.

### 9.2 Compatibility Rules

1. New optional fields MAY be added if existing required fields and semantics remain unchanged.
2. Changes to required fields, acceptance logic, or hash binding semantics MUST bump major version.
3. Executors MUST reject unknown major versions.
4. Mixed-version deployments MUST pin to the lowest mutually supported major version.

## 10. Validation Procedure

The following checks SHOULD be part of CI:

1. `python scripts/validate_specs.py`
2. `python scripts/verify_accept_predicate.py --spec spec/secureclaw_accept_predicate_v1.json --commit <evidence.json> --request <request.json>`
3. `python -m unittest discover -s tests -p 'test_*.py'`

For capsule mediation:

1. `bash capsule/run_smoke.sh`
2. `python -m capsule.verify_contract --contract spec/secureclaw_capsule_contract_v1.json --report artifact_out/capsule_smoke.json --out artifact_out/capsule_contract_verdict.json`
