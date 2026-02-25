# SecureClaw A/B/C/D Executable Checklist (Paper + Artifact)

This checklist turns the A/B/C/D plan into execution-tracked tasks with concrete commands, artifact paths, and acceptance criteria.

Scope:
- A: SAP + constant-shape policy outsourcing
- B: SM + measurable declassification
- C: Skill supply chain ingress + SCS capsule contract
- D: Multi-agent federation + delegated authority

Date baseline:
- Authoring date: 2026-02-25
- Target run root for external baselines: `artifact_out_external_runtime/external_runs/<RUN_TAG>`
- Paper primary text: `paper_full_body.tex`
- Security model source: `FORMAL_SECURITY.md`, `LEAKAGE_MODEL.md`, `capsule/MC_CONTRACT_SPEC.md`

## 0. Global Freeze and Repro Preconditions

- [x] `G-01` Freeze benchmark and run tags
  - Deliverable: one immutable run manifest (`seed`, model, suite set, config knobs).
  - Command:
    ```bash
    python scripts/write_repro_manifest.py
    ```
  - Acceptance:
    - Manifest exists under `artifact_out/` and records all core env knobs used for A/B/C/D claims.
    - All subsequent reports reference the same manifest id or commit hash.

- [x] `G-02` Run mandatory formal/spec checks before new claim updates
  - Command:
    ```bash
    PYTHONPATH=. python formal/secureclaw_model_check.py
    PYTHONPATH=. python scripts/security_game_nbe_check.py
    PYTHONPATH=. python -m unittest discover -s tests -p 'test_security_games.py'
    PYTHONPATH=. python scripts/validate_specs.py
    ```
  - Acceptance:
    - `artifact_out/security_game_nbe.json` status is `OK`.
    - No failing tests/spec validation errors.

## A. SAP + Constant-Shape Policy Outsourcing

- [x] `A-01` Lock `L_policy` contract terms and claim boundaries
  - Files:
    - `LEAKAGE_MODEL.md`
    - `paper_full_body.tex`
  - Required statement:
    - SAP claim is only for single-policy-server view under explicit leakage terms:
      `L_policy = (L_PIR, L_MPC, L_CONFIRM, L_TIME)`.
    - Intent-hiding requires constant `program_id`, endpoint class, and batch shape.
  - Acceptance:
    - No ambiguous wording implying stronger privacy than leakage contract permits.
    - Claim text in paper and model docs is consistent.

- [x] `A-02` Enforce and document shape-hiding runtime knobs
  - Required knobs to appear in config table:
    - `USE_POLICY_BUNDLE`
    - `UNIFIED_POLICY`
    - `MIRAGE_POLICY_PROGRAM_ID`
    - `PIR_MIX_ENABLED`, `PIR_MIX_PAD_TO`, `PIR_MIX_INTERVAL_MS`
    - `MPC_MIX_ENABLED`, `MPC_MIX_PAD_TO`, `MPC_MIX_INTERVAL_MS`
    - `PAD_DFA_STEPS`, `MAX_DFA_SCAN_CHARS`
  - Acceptance:
    - Each knob has "claim impact" description (what leaks when disabled).
    - Defaults for paper-mode and privacy-mode are explicit.

- [x] `A-03` Run transcript distinguishability sweep (`L_policy`) as primary evidence
  - Command:
    ```bash
    OUT_DIR=artifact_out_compare/leakage_sweep \
      PYTHONPATH=. python scripts/leakage_model_sweep.py

    PYTHONPATH=. python scripts/leakage_channel_report.py \
      --out artifact_out_compare/leakage_channel_report.json
    ```
  - Expected outputs:
    - `artifact_out_compare/leakage_sweep/leakage_model_sweep.json`
    - `artifact_out_compare/leakage_channel_report.json`
  - Acceptance:
    - Report includes MI and classifier metrics across shaping tiers.
    - Full mode (`unified + bundled + fixed-shape`) is near chance-level distinguishability.
    - Ablated modes retain separable signal.

- [x] `A-04` Run SAP ablation matrix (must report both privacy and utility)
  - Matrix dimensions:
    - `USE_POLICY_BUNDLE`: on/off
    - `UNIFIED_POLICY`: on/off
    - mixer/padding: off -> on
    - `PAD_DFA_STEPS`: 0/1
  - Command template:
    ```bash
    # Example: run one cell with env overrides
    USE_POLICY_BUNDLE=1 UNIFIED_POLICY=1 PIR_MIX_ENABLED=1 MPC_MIX_ENABLED=1 \
    PAD_DFA_STEPS=1 PYTHONPATH=. python scripts/leakage_model_sweep.py
    ```
  - Acceptance:
    - Each cell has reproducible JSON output and explicit interpretation.
    - No claim uses settings that violate its own threat-model assumptions.

- [x] `A-05` Quantify privacy-cost tradeoff (not only privacy metric)
  - Command:
    ```bash
    PYTHONPATH=. python scripts/bench_e2e_shaping_curves.py
    PYTHONPATH=. python scripts/bench_policy_server_curves.py
    PYTHONPATH=. python scripts/bench_policy_server_scaling.py
    ```
  - Acceptance:
    - Paper includes shaping overhead decomposition (dummy compute, queueing, transport).
    - Throughput/latency plots are linked to exact shaping knobs used in SAP claims.

## B. SM + Declassification as Explicit Capability

- [x] `B-01` Confirm handle invariants in code+docs
  - Invariants:
    - Opaque secrecy by default
    - Session/caller binding
    - Explicit declassification with confirmation
  - Files:
    - `paper_full_body.tex`
    - `LEAKAGE_MODEL.md`
    - `README.md`
  - Acceptance:
    - Text consistently states that runtime receives handles, not plaintext by default.
    - Declassification path updates leakage budget and audit trail.

- [x] `B-02` Run SM-focused channel tests (`C1..C7`)
  - Command:
    ```bash
    # Official-like channels C1..C5 via fair compare
    OUT_DIR=artifact_out_compare_noprompt FAIR_FULL_REUSE_NATIVE=1 FAIR_FULL_REUSE_SECURECLAW=1 \
      PYTHONPATH=. python scripts/fair_full_compare.py

    # Synthetic full channels including C6/C7
    OUT_DIR=artifact_out_compare/leakage_sys_synth_v2 \
      AGENTLEAK_CASESET=synthetic PYTHONPATH=. python scripts/agentleak_channel_eval.py
    ```
  - Expected outputs:
    - `artifact_out_compare_noprompt/fair_full_report.json`
    - `artifact_out_compare/leakage_sys_synth_v2/agentleak_eval/agentleak_channel_summary.json`
  - Acceptance:
    - Attack leak rate semantics are reported per channel, not only aggregate.
    - `REQUIRE_CONFIRM` outcomes are separated from hard-deny in analysis.

- [x] `B-03` Validate leakage-budget enforcement path
  - Required fields:
    - `LEAKAGE_BUDGET_ENABLED`, `LEAKAGE_BUDGET_C1..C7`
  - Acceptance:
    - Budget exhaustion yields explicit reason code and appears in error-mode breakdown.
    - Paper text does not claim "zero leakage" beyond contract terms.

- [x] `B-04` Run SM regression tests
  - Command:
    ```bash
    PYTHONPATH=. pytest tests/test_mcp_gateway.py tests/test_agentleak_channels.py -q
    ```
  - Acceptance:
    - No regression on handle/declassify behavior and channel harness checks.

## C. Skill Ingress + SCS Capsule Contract

- [x] `C-01` Treat skill ingress as effectful PREVIEW->COMMIT in evidence path
  - Required paths:
    - skill import/check/commit should carry reason codes and commit evidence semantics.
  - Acceptance:
    - `C7` evidence in reports is tied to policy + commit flow, not ad hoc checks.

- [x] `C-02` Verify capsule mediation contract with smoke report
  - Command template:
    ```bash
    # Run capsule smoke (platform-specific entrypoints exist)
    bash capsule/run_smoke.sh || true
    bash capsule/run_smoke_linux.sh || true

    # Verify against machine-checkable contract
    PYTHONPATH=. python capsule/verify_contract.py \
      --contract spec/secureclaw_capsule_contract_v1.json \
      --report <capsule_smoke_report.json> \
      --out artifact_out/capsule_contract_verdict.json
    ```
  - Acceptance:
    - Contract verdict is `OK` for SCS claim enablement.
    - If not `OK`, SCS claim is explicitly downgraded/disabled in paper text.

- [x] `C-03` Run SCS-related tests and explicit bypass baselines
  - Command:
    ```bash
    PYTHONPATH=. pytest tests/test_capsule_contract_verifier.py -q
    PYTHONPATH=. python scripts/artifact_report.py
    ```
  - Acceptance:
    - Report includes both secure path and bypass baseline outcomes.
    - "No-capsule" / "loopback-relaxed" conditions are clearly marked as weaker modes.

- [x] `C-04` Ensure downgrade semantics are documented
  - Files:
    - `capsule/MC_CONTRACT_SPEC.md`
    - `FORMAL_SECURITY.md`
    - `paper_full_body.tex`
  - Acceptance:
    - SCS claim conditioned on contract verdict.
    - Failure mode and downgrade path are explicit and test-backed.

## D. Multi-Agent Federation + Delegated Authority

- [x] `D-01` Keep delegation context in request hash binding (`hctx`)
  - Required binding:
    - `hctx = (external_principal, delegation_jti)` is part of request hash context.
  - Files:
    - `FORMAL_SECURITY.md`
    - `paper_full_body.tex`
    - `spec/SECURECLAW_PROTOCOL_RFC_v1.md`
  - Acceptance:
    - Protocol/spec/model wording is consistent about anti-replay across principals.

- [x] `D-02` Run deterministic federation protocol campaign
  - Command:
    ```bash
    PYTHONPATH=. OUT_DIR=artifact_out_compare python scripts/multi_agent_federated_eval.py
    cat artifact_out_compare/multi_agent_federated_eval.json
    ```
  - Acceptance:
    - Includes delegated allow cases and mandatory deny cases:
      missing delegation, revoked token, dual-principal mismatch.
    - Report records latency percentiles and reason codes.

- [x] `D-03` Validate token/signature toolchain for ingress tests
  - Command examples:
    ```bash
    PYTHONPATH=. python scripts/mint_delegation_token.py --help
    PYTHONPATH=. python scripts/sign_gateway_request.py --help
    ```
  - Acceptance:
    - CI or manual recipe includes mint/sign/replay-negative test.
    - Replay under changed principal/delegation_jti is rejected.

- [x] `D-04` Run federation tests
  - Command:
    ```bash
    PYTHONPATH=. pytest tests/test_delegation_and_dual_principal.py tests/test_federated_auth.py -q
    ```
  - Acceptance:
    - All federation and dual-principal checks pass.

## Paper Integration Tasks (Reviewer-Facing)

- [x] `P-01` Main claim alignment
  - Ensure single reviewable claim explicitly includes:
    - NBE effect commit line at executor
    - SAP via explicit leakage function
  - Acceptance:
    - Claim text appears identically in abstract/introduction/security section.

- [x] `P-02` Motivation-to-evidence closure
  - Must include:
    - Control-plane privacy paradox motivation
    - `L_policy` transcript attack evidence
    - A/B/C/D mechanism mapping
  - Acceptance:
    - Each motivation claim has at least one experiment or contract verifier anchor.

- [x] `P-03` Result table hygiene
  - Required:
    - Separate official (`C1..C5`) from synthetic (`C6/C7`) coverage.
    - Distinguish `DENY` vs `REQUIRE_CONFIRM` vs runtime failure buckets.
  - Acceptance:
    - No mixed-rate table that conflates different coverage or outcome semantics.

## Final Submission Gate (Must All Pass)

- [x] `S-01` Formal checks pass (`G-02`)
- [x] `S-02` `L_policy` sweep reproduced with chance-level full mode (`A-03`)
- [x] `S-03` Channel evidence complete for official and synthetic coverage (`B-02`)
- [x] `S-04` Capsule contract verdict `OK` or SCS downgraded explicitly (`C-02`, `C-04`)
- [x] `S-05` Federation campaign and tests pass (`D-02`, `D-04`)
- [x] `S-06` Paper text/data paths frozen and cross-referenced

## Quick Runbook (Minimal End-to-End)

```bash
# 1) Formal/spec sanity
PYTHONPATH=. python formal/secureclaw_model_check.py
PYTHONPATH=. python scripts/security_game_nbe_check.py
PYTHONPATH=. python scripts/validate_specs.py

# 2) SAP distinguishability + unified leakage report
OUT_DIR=artifact_out_compare/leakage_sweep PYTHONPATH=. python scripts/leakage_model_sweep.py
PYTHONPATH=. python scripts/leakage_channel_report.py --out artifact_out_compare/leakage_channel_report.json

# 3) Official/synthetic channel evidence
OUT_DIR=artifact_out_compare_noprompt FAIR_FULL_REUSE_NATIVE=1 FAIR_FULL_REUSE_SECURECLAW=1 \
  PYTHONPATH=. python scripts/fair_full_compare.py
OUT_DIR=artifact_out_compare/leakage_sys_synth_v2 AGENTLEAK_CASESET=synthetic \
  PYTHONPATH=. python scripts/agentleak_channel_eval.py

# 4) Federation protocol campaign
PYTHONPATH=. OUT_DIR=artifact_out_compare python scripts/multi_agent_federated_eval.py
```


## Execution Evidence Snapshot (2026-02-25)

- `G-01` manifest:
  - `artifact_out/repro_manifest.json`
- `G-02` formal/spec/tests:
  - `artifact_out/security_game_nbe.json` (status `OK`)
  - run logs: `artifact_out/task_runs/20260225_095417`

- `A-03` transcript distinguishability sweep:
  - `artifact_out_compare/leakage_sweep/leakage_model_sweep.json`
  - `artifact_out_compare/leakage_channel_report.json`
  - key signal: `unshaped.pir.mi_bits=0.4143`, `unshaped.pir.map_acc=0.5144`, `chance=0.3333`; shaped modes collapse toward chance.

- `A-04` ablation/matrix evidence:
  - base matrix (bundle/unified/mix/pad/cover): `artifact_out_compare/leakage_sweep/leakage_model_sweep.json`
  - `PAD_DFA_STEPS` sweeps:
    - `artifact_out_compare/leakage_sweep_pad_dfa0/leakage_model_sweep.json`
    - `artifact_out_compare/leakage_sweep_pad_dfa1/leakage_model_sweep.json`

- `A-05` performance curves:
  - run logs: `artifact_out/task_runs/20260225_100359`

- `B-02` channel evidence:
  - official-like: `artifact_out_compare_noprompt/fair_full_report.json`
  - synthetic C6/C7: `artifact_out_compare/leakage_sys_synth_v2/agentleak_eval/agentleak_channel_summary.json`

- `B-03` leakage budget enforcement evidence:
  - focused run: `artifact_out_compare/leakage_budget_exhaust/agentleak_eval/agentleak_channel_summary.json`
  - contains explicit `LEAKAGE_BUDGET_EXCEEDED` reason entries.

- `B-04` SM regressions:
  - run logs: `artifact_out/task_runs/20260225_100430`

- `C-02` capsule contract verification:
  - `artifact_out/capsule_contract_verdict.json` (`status=OK`, `n_ok=7`, `n_fail=0`)
  - `artifact_out/capsule_smoke.json`

- `C-03` artifact synthesis:
  - `artifact_out/report.json`

- `D-02` federation campaign:
  - `artifact_out_compare/multi_agent_federated_eval.json` (`n_cases=7`, `n_pass=7`, `pass_rate=1.0`)

- `D-03` toolchain checks:
  - `PYTHONPATH=. python scripts/mint_delegation_token.py --help`
  - `PYTHONPATH=. python scripts/sign_gateway_request.py --help`

- `D-04` federation tests:
  - run logs: `artifact_out/task_runs/20260225_095553`
