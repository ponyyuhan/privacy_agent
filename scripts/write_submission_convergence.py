from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _f(x: Any, digits: int = 4) -> str:
    try:
        return f"{float(x):.{digits}f}"
    except Exception:
        return "NA"


def _mode_name(k: str) -> str:
    m = {
        "mirage_full": "SecureClaw Full",
        "policy_only": "SecureClaw Policy-Only",
        "sandbox_only": "SecureClaw Sandbox-Only",
        "single_server_policy": "SecureClaw Single-Server Policy",
        "codex_native": "Codex Native Guardrails",
        "openclaw_native": "OpenClaw Native Guardrails",
    }
    return m.get(k, k)


def _render_system_table(systems: dict[str, Any]) -> str:
    keys = [
        "mirage_full",
        "policy_only",
        "sandbox_only",
        "single_server_policy",
        "codex_native",
        "openclaw_native",
    ]
    lines = [
        "| System | n_attack | n_benign | attack_leak_rate | benign_allow_rate | p50_ms | p95_ms | ops_s |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for k in keys:
        d = systems.get(k)
        if not isinstance(d, dict):
            continue
        lines.append(
            "| "
            + " | ".join(
                [
                    _mode_name(k),
                    str(int(d.get("n_attack", 0))),
                    str(int(d.get("n_benign", 0))),
                    _f(d.get("attack_leak_rate"), 4),
                    _f(d.get("benign_allow_rate"), 4),
                    _f(d.get("latency_p50_ms"), 2),
                    _f(d.get("latency_p95_ms"), 2),
                    _f(d.get("ops_s"), 2),
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def _render_fp_breakdown(utility: dict[str, Any]) -> str:
    bd = utility.get("breakdown")
    if not isinstance(bd, dict):
        return "- Missing utility breakdown."
    by_mode = bd.get("secureclaw_by_mode")
    if not isinstance(by_mode, dict):
        return "- Missing per-mode utility breakdown."

    keys = ["mirage_full", "policy_only", "sandbox_only", "single_server_policy"]
    out: list[str] = []
    for k in keys:
        d = by_mode.get(k)
        if not isinstance(d, dict):
            continue
        denies = int(d.get("benign_denies", 0))
        reasons = d.get("benign_deny_by_reason")
        top_reason = "NA"
        if isinstance(reasons, dict) and reasons:
            top_reason = sorted(reasons.items(), key=lambda kv: (-int(kv[1]), str(kv[0])))[0][0]
        out.append(f"- `{k}`: benign_denies={denies}, top_reason={top_reason}")
    if not out:
        return "- No mode breakdown found."
    return "\n".join(out)


def _render_channel_table(leakage: dict[str, Any]) -> str:
    chs = leakage.get("channels")
    if not isinstance(chs, dict):
        return "| Channel | source | attack_leak_rate | benign_allow_rate |\n|---|---|---:|---:|"
    lines = [
        "| Channel | source | attack_leak_rate | benign_allow_rate |",
        "|---|---|---:|---:|",
    ]
    for c in ["C1", "C2", "C3", "C4", "C5", "C6", "C7"]:
        d = chs.get(c)
        if not isinstance(d, dict):
            continue
        lines.append(
            f"| {c} | {d.get('source', 'NA')} | {_f(d.get('attack_leak_rate'), 4)} | {_f(d.get('benign_allow_rate'), 4)} |"
        )
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fair-report", default="artifact_out_compare/fair_full_report.json")
    ap.add_argument("--fair-stats", default="artifact_out_compare/stats/fair_full_stats.json")
    ap.add_argument("--utility", default="artifact_out_compare/stats/fair_utility_breakdown.json")
    ap.add_argument("--perf", default="artifact_out_compare/perf_production_report.json")
    ap.add_argument("--leakage", default="artifact_out_compare/leakage_channel_report.json")
    ap.add_argument("--out", default="artifact_out_compare/SUBMISSION_CONVERGENCE.md")
    args = ap.parse_args()

    fair = _load_json(Path(args.fair_report))
    stats = _load_json(Path(args.fair_stats))
    utility = _load_json(Path(args.utility))
    perf = _load_json(Path(args.perf))
    leakage = _load_json(Path(args.leakage))

    systems = fair.get("systems") if isinstance(fair.get("systems"), dict) else {}
    case_meta = fair.get("case_meta") if isinstance(fair.get("case_meta"), dict) else {}
    n_cases = int((case_meta.get("n_cases_total") or 0))
    if n_cases <= 0 and isinstance(systems.get("mirage_full"), dict):
        n_cases = int(systems["mirage_full"].get("n_total") or 0)
    n_groups = int((case_meta.get("n_scenarios_total") or case_meta.get("dataset_total_rows") or 0))

    perf_e2e = perf.get("e2e_throughput") if isinstance(perf.get("e2e_throughput"), dict) else {}
    perf_scaling = perf.get("policy_server_scaling") if isinstance(perf.get("policy_server_scaling"), dict) else {}

    fisher = (
        stats.get("fisher_tests_vs_mirage_full")
        if isinstance(stats.get("fisher_tests_vs_mirage_full"), dict)
        else stats.get("significance_vs_mirage_full")
        if isinstance(stats.get("significance_vs_mirage_full"), dict)
        else {}
    )
    sig_lines: list[str] = []
    for k in ("policy_only", "sandbox_only", "single_server_policy", "codex_native", "openclaw_native"):
        t = fisher.get(k)
        if isinstance(t, dict):
            leak_key = "attack_leak_pvalue" if "attack_leak_pvalue" in t else "attack_leak_rate_pvalue"
            block_key = "attack_block_pvalue" if "attack_block_pvalue" in t else "attack_block_rate_pvalue"
            if leak_key not in t and "attack_leak_fisher_p_two_sided" in t:
                leak_key = "attack_leak_fisher_p_two_sided"
            if block_key not in t and "benign_allow_fisher_p_two_sided" in t:
                block_key = "benign_allow_fisher_p_two_sided"
            sig_lines.append(
                f"- `{k}`: attack_leak_p={_f(t.get(leak_key), 6)}, attack_block_p={_f(t.get(block_key), 6)}"
            )
    if not sig_lines:
        sig_lines = ["- Missing Fisher exact test output."]
    sig_block = "\n".join(sig_lines)
    dist_block = json.dumps(
        leakage.get("distinguishability") if isinstance(leakage.get("distinguishability"), dict) else {},
        ensure_ascii=True,
    )
    scaling_block = json.dumps(perf_scaling, ensure_ascii=True)

    text = f"""# SecureClaw Submission Convergence

## Canonical claim
SecureClaw provides a non bypassable side effect execution line and leakage aware outsourced policy enforcement, where no external side effect commits without dual bound evidence, and any single policy server view is simulatable from an explicit allowed leakage function.

## Fair strong baselines on one official harness
- Cases manifest: `{args.fair_report}` input reports `{n_cases}` per-channel cases and `{n_groups}` scenario groups.
- Baseline set: Codex Native Guardrails, OpenClaw Native Guardrails, and four SecureClaw modes.

{_render_system_table(systems)}

## Utility recovery and false positive decomposition
{_render_fp_breakdown(utility)}

## Performance to production profile
- Best mixed constant-shape throughput: `{_f(perf_e2e.get('best_mixed_cover_ops_s'), 3)} ops/s`
- Best mixed p50 and p95: `{_f(perf_e2e.get('best_mixed_cover_p50_ms'), 3)} ms`, `{_f(perf_e2e.get('best_mixed_cover_p95_ms'), 3)} ms`
- Target check `{_f(perf_e2e.get('target_ops_s'), 1)} ops/s`: `target_met={str(bool(perf_e2e.get('target_met'))).lower()}`
- Policy scaling summary: `{scaling_block}`

## Leakage evidence across C1..C7
{_render_channel_table(leakage)}

### Distinguishability summary
`{dist_block}`

## Statistical protocol and significance
{sig_block}

## Formal and deployment consistency anchors
- Main paper body: `paper_full_body.tex`
- Security appendix: `appendix_security.tex`
- Leakage appendix: `appendix_leakage.tex`
- Formal game checks: `scripts/security_game_nbe_check.py`, `formal/secureclaw_model_check.py`
- MC contract spec and verifier: `spec/secureclaw_capsule_contract_v1.json`, `capsule/verify_contract.py`
- Accept predicate spec and verifier: `spec/secureclaw_accept_predicate_v1.json`, `scripts/verify_accept_predicate.py`
"""

    out_path = Path(args.out).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text.rstrip() + "\n", encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()
