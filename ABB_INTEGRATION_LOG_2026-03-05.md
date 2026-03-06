# ABB Integration Log (2026-03-05)

This note records what was adopted from `update_ABB.md` and `update_ABB2.md` into the current code/docs.

## Applied Now

1. Keyed request commitment for PREVIEW->COMMIT binding
- Implemented in `common/canonical.py` via `SECURECLAW_REQUEST_BINDING_KEY_HEX`.
- Behavior:
  - keyed mode (recommended): `HMAC-SHA256(key, CanonJSON(payload))`.
  - legacy compatibility mode: `SHA256(CanonJSON(payload))`.
- Wire field remains `request_sha256` for protocol v1 compatibility.

2. Deployment hardening: binding key isolation from policy servers
- `scripts/run_agentdojo_native_plain_secureclaw.py` now generates a per-run binding key (if absent).
- The key is propagated to gateway/executor runtime but removed from policy server env.

3. Tooling support for keyed mode verification
- Added `--request-binding-key-hex` to `scripts/verify_accept_predicate.py`.

4. Documentation alignment
- Updated RFC/formal/algorithm/paper docs to describe keyed+legacy request binding semantics and residual-risk boundary.

## Deferred (Not Yet Implemented)

1. Privacy-preserving provenance/replay (PDR)
- Valuable but requires broader log schema and replay workflow updates.

2. Safe output builder for benign leakage reduction
- Requires output-generation pipeline design and new evaluation hooks.

3. Handle data-flow operator expansion
- Requires extending handle semantics and executor-side operations.

4. UI-mediated executor extension
- Out of current sprint scope; needs a separate subsystem design.

## Rationale

The keyed request commitment directly addresses an existing documented residual risk
(low-entropy offline guessing against unkeyed request digest observability) with minimal protocol churn.
It is generic (non-benchmark-specific), backward compatible, and testable in current artifact pipelines.
