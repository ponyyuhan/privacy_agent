# polish.md Closure Checklist (2026-02-26)

This file maps each actionable block in `polish.md` to concrete repository changes, evidence paths, and verification runs.

## 1) Thesis/Model/Positioning Rewrite

Status: Completed.

1. Single-thesis framing and 3-core contribution packaging:
   - `paper_full_body.tex` (`Thesis`, `C1/C2/C3`, optional `C4`).
2. Main-body SAP model instead of appendix-only treatment:
   - `paper_full_body.tex` (control-plane paradox, leakage contract, SAP section).
3. SAP proof chain tightened with explicit hybrids:
   - `appendix_security.tex` (Lemma 1 PIR simulation, Lemma 2 MPC simulation, Lemma 3 fixed-shape composition, Theorem `thm:sap`).
4. Faramesh differentiation moved to explicit positioning paragraph:
   - `paper_full_body.tex` (`Positioning versus Faramesh`).

## 2) Empirical Design Closure

Status: Completed for measured tracks E1/E2 and official C1..C5; extension protocols defined for E3/E4/E5/E6.

1. Threat-model split (fairness guardrail):
   - `paper_full_body.tex` (`Threat Model A/B`).
   - `LEAKAGE_EVIDENCE.md` (Section `0. Threat-Model Split`).
   - `EXPERIMENT_DESIGN.md` (Section `1`).
2. E1 bypass suite (measured):
   - Artifacts:
     - `artifact_out/compromised_bypass_report.json`
     - `artifact_out/compromised_bypass_report.md`
     - `artifact_out/security_game_nbe.json`
   - Current snapshot: `n_rows=16`, `n_pass=16`, `pass_rate=1.0`.
3. E2 single-auditor compromise simulation (measured):
   - Artifacts:
     - `artifact_out_compare/leakage_sweep/leakage_model_sweep.json`
     - `artifact_out_compare_noprompt/leakage_channel_report.json`
   - Current snapshot:
     - `unshaped.pir.mi_bits=0.4143349401222639`
     - `shaped_pad4_cover1.pir.mi_bits=0.0`
     - `shaped_pad4_cover1.mpc.mi_bits=1.0614695895005673e-06`
4. E3 AP2 case-study protocol (designed):
   - `paper_full_body.tex` (`E3--E6` subsection).
   - `EXPERIMENT_DESIGN.md` (`3.1`).
   - `LEAKAGE_EVIDENCE.md` (`6.1`).
5. E4 AgentDojo exfiltration protocol (designed):
   - `paper_full_body.tex` (`E3--E6` subsection).
   - `EXPERIMENT_DESIGN.md` (`3.2`).
   - `LEAKAGE_EVIDENCE.md` (`6.2`).
6. E5 VPI-Bench mediated subset protocol (designed):
   - `paper_full_body.tex` (`E3--E6` subsection).
   - `EXPERIMENT_DESIGN.md` (`3.3`).
   - `LEAKAGE_EVIDENCE.md` (`6.3`).
7. E6 enterprise DLP-proxy privacy-sink baseline protocol (designed):
   - `paper_full_body.tex` (`E3--E6` subsection).
   - `EXPERIMENT_DESIGN.md` (`3.4`).
   - `LEAKAGE_EVIDENCE.md` (`6.4`).
8. Performance fairness presentation (control-plane overhead vs LLM latency):
   - `paper_full_body.tex` (`RQ4`).
   - `README.md` (performance/reporting sections and artifact references).

## 3) Recent Pain-Point Mapping (Last ~12 months)

Status: Completed.

1. Added explicit pain-point-to-mechanism mapping in motivation docs:
   - `MOTIVATION_PAPER.md` (`1.2.1 2025--2026 pain-point map`).
   - `MOTIVATION_PAPER_CN.md` (`1.2.1 2025--2026 现实痛点映射`).
2. Mapping covers:
   - AgentDojo-style exfiltration risk -> SM/NBE (+ E4).
   - Visual prompt injection in CUA -> mediated subset + explicit scope limits (+ E5).
   - Second-order multi-agent/connector injection -> DAS/hctx binding.
   - AP2 manipulation risk -> PREVIEW->COMMIT + confirmation (+ E3).
   - Control-plane logging privacy sink -> SAP leakage-contract model (+ E6).

## 4) Verification and Build Status

Status: Completed and passing.

1. Formal model checker:
   - `PYTHONPATH=. python formal/secureclaw_model_check.py` -> `ok=true` (`NBE/SM/PEI/DAS/SCS`).
2. Security-game harness:
   - `PYTHONPATH=. python scripts/security_game_nbe_check.py` -> output `artifact_out/security_game_nbe.json`.
3. Spec validator:
   - `PYTHONPATH=. python scripts/validate_specs.py` -> `OK: specs validate`.
4. Targeted tests:
   - `PYTHONPATH=. pytest -q tests/test_security_games.py tests/test_formal_model_check.py tests/test_federated_auth.py tests/test_native_defense_oracle_free.py` -> `15 passed`.
5. LaTeX build:
   - `latexmk -pdf -interaction=nonstopmode neurips_2025.tex` -> `neurips_2025.pdf` generated (no undefined citation/reference errors).

## 5) Scope Note

Measured claims in the paper are limited to completed tracks (E1/E2 and official C1..C5 comparison).
E3/E4/E5/E6 are intentionally marked as protocolized extension tracks to avoid over-claiming.
