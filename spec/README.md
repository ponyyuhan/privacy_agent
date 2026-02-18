# SecureClaw Machine-Checkable Specifications

This directory contains machine-checkable specifications for the SecureClaw artifact.

The specs are intended to serve two roles.

First, they provide an interface-level contract that can be validated on concrete JSON objects that appear in logs and request traces.

Second, they define the exact fields that are bound by the executor acceptance predicate and the capsule mediation contract, so that the paper statements can be grounded in implementable and testable artifacts.

Contents

- `spec/secureclaw_executor_accept_v1.schema.json` specifies the JSON structure of commit proof shares and the `commit` evidence object consumed by the executor commit path.
- `spec/secureclaw_capsule_contract_v1.schema.json` specifies the JSON structure of a capsule mediation contract.
- `spec/secureclaw_capsule_contract_v1.json` is the artifact contract instance for this repository.

Validation

The repository provides a schema validator script.

```
python scripts/validate_specs.py
```

