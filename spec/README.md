# SecureClaw Machine-Checkable Specifications

This directory contains machine-checkable specifications for the SecureClaw artifact.

The specs are intended to serve two roles.

First, they provide an interface-level contract that can be validated on concrete JSON objects that appear in logs and request traces.

Second, they define the exact fields that are bound by the executor acceptance predicate and the capsule mediation contract, so that the paper statements can be grounded in implementable and testable artifacts.

Contents

- `spec/secureclaw_executor_accept_v1.schema.json` specifies the JSON structure of commit proof shares and the `commit` evidence object consumed by the executor commit path.
- `spec/secureclaw_accept_predicate_v1.json` specifies additional semantic constraints that the executor enforces on top of the JSON schema.
- `spec/secureclaw_capsule_contract_v1.schema.json` specifies the JSON structure of a capsule mediation contract.
- `spec/secureclaw_capsule_contract_v1.json` is the artifact contract instance for this repository.
- `spec/SECURECLAW_PROTOCOL_RFC_v1.md` specifies interface-level contracts for `act`, PREVIEW, COMMIT, evidence, accept predicate semantics, error codes, invariants, and versioning.

Validation

The repository provides a schema validator script.

```
python scripts/validate_specs.py
```

The repository also provides semantic and contract verifiers.

```
python scripts/verify_accept_predicate.py \
  --spec spec/secureclaw_accept_predicate_v1.json \
  --commit <commit.json> \
  --request <request.json>
```

```
python -m capsule.verify_contract \
  --contract spec/secureclaw_capsule_contract_v1.json \
  --report artifact_out/capsule_smoke.json \
  --out artifact_out/capsule_contract_verdict.json
```
