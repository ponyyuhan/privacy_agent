# SecureClaw Mechanized Consistency Checks

This directory provides a mechanized, explicit state model checking harness for key interface level properties of SecureClaw.

The goal is not to prove cryptographic assumptions. The model treats MAC and hash as ideal primitives by construction, and it checks that the event definitions used in the paper are consistent with the interface specification and acceptance predicates.

In particular, the checker enumerates all adversary behaviors within a bounded finite domain and confirms that no trace can reach a state where the executor commits an external side effect without a valid dual commit proof bound to the exact request context and within the freshness and replay constraints.

Run

```
python formal/secureclaw_model_check.py
```

The unit test `tests/test_formal_model_check.py` runs the same checker in CI.

