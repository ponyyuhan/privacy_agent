from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ERROR_REASON_PREFIXES = (
    "ERROR:",
    "BLOCK_ERROR:",
    "GATEWAY_ERROR",
    "TIMEOUT",
    "SKIPPED",
)


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = ln.strip()
        if not s:
            continue
        d = json.loads(s)
        if isinstance(d, dict):
            out.append(d)
    return out


def _write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def wilson_ci(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n <= 0:
        return 0.0, 0.0
    phat = successes / n
    denom = 1.0 + (z * z / n)
    center = (phat + (z * z) / (2 * n)) / denom
    margin = (z / denom) * math.sqrt((phat * (1 - phat) / n) + ((z * z) / (4 * n * n)))
    lo = max(0.0, center - margin)
    hi = min(1.0, center + margin)
    return lo, hi


def _log_comb(n: int, k: int) -> float:
    if k < 0 or k > n:
        return float("-inf")
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def fisher_exact_two_sided(a: int, b: int, c: int, d: int) -> float:
    """
    Two-sided Fisher exact test p-value for a 2x2 table:
        [a b]
        [c d]
    """
    r1 = a + b
    r2 = c + d
    c1 = a + c
    n = r1 + r2
    if n <= 0:
        return 1.0

    # Hypergeometric pmf for given margins.
    def log_p(x: int) -> float:
        return _log_comb(r1, x) + _log_comb(r2, c1 - x) - _log_comb(n, c1)

    lo = max(0, c1 - r2)
    hi = min(r1, c1)
    lp_obs = log_p(a)
    # Two-sided: sum probabilities of all tables as or more extreme than observed (pmf <= pmf_obs).
    total = 0.0
    for x in range(lo, hi + 1):
        lp = log_p(x)
        if lp <= lp_obs + 1e-12:
            total += math.exp(lp)
    return float(min(1.0, max(0.0, total)))


@dataclass(frozen=True)
class CaseMeta:
    channel: str
    kind: str
    scenario_id: str
    vertical: str
    attack_family: str


def _load_case_meta(manifest_path: Path) -> dict[str, CaseMeta]:
    meta: dict[str, CaseMeta] = {}
    rows = _read_jsonl(manifest_path)
    for r in rows:
        case_id = str(r.get("case_id") or "")
        if not case_id:
            continue
        payload = r.get("payload") if isinstance(r.get("payload"), dict) else {}
        meta[case_id] = CaseMeta(
            channel=str(r.get("channel") or ""),
            kind=str(r.get("kind") or ""),
            scenario_id=str(payload.get("scenario_id") or ""),
            vertical=str(payload.get("vertical") or ""),
            attack_family=str(payload.get("attack_family") or ""),
        )
    return meta


def _read_mirage_rows(csv_path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        rd = csv.DictReader(f)
        for r in rd:
            rows.append(
                {
                    "mode": str(r.get("mode") or ""),
                    "case_id": str(r.get("case_id") or ""),
                    "channel": str(r.get("channel") or ""),
                    "kind": str(r.get("kind") or ""),
                    "blocked": bool(int(r.get("blocked") or "0")),
                    "leaked": bool(int(r.get("leaked") or "0")),
                    "allowed": bool(int(r.get("allowed") or "0")),
                    "latency_s": float(r.get("latency_s") or 0.0),
                    "reason_code": str(r.get("reason_code") or ""),
                }
            )
    return rows


def _reason_code(row: dict[str, Any]) -> str:
    return str(row.get("reason_code") or "").strip()


def _is_reason_error(reason_code: str) -> bool:
    rc = str(reason_code or "").strip().upper()
    if not rc:
        return False
    if any(rc.startswith(pfx) for pfx in _ERROR_REASON_PREFIXES):
        return True
    return False


def _annotate_native_runtime_errors(rows: list[dict[str, Any]], *, summary_path: Path) -> list[dict[str, Any]]:
    """
    Native baselines keep per-scenario raw outputs under <summary_dir>/scenarios.
    We propagate per-scenario runtime errors (parse_failed/nonzero rc) down to per-case rows
    so availability is separated from policy deny behavior.
    """
    scen_dir = summary_path.parent / "scenarios"
    status_by_key: dict[tuple[str, str], tuple[bool, str]] = {}
    if scen_dir.exists() and scen_dir.is_dir():
        for p in scen_dir.glob("*.json"):
            nm = p.stem
            if "_" not in nm:
                continue
            kind, scenario_id = nm.split("_", 1)
            try:
                d = _load_json(p)
            except Exception:
                status_by_key[(scenario_id, kind)] = (True, "ERROR:SCENARIO_PARSE")
                continue
            rc = int(((d.get("_meta") or {}).get("rc") or 0)) if isinstance(d, dict) else 0
            err = str(d.get("error") or "") if isinstance(d, dict) else "parse_failed"
            runtime_error = bool(err) or (rc != 0)
            if runtime_error:
                err_code = f"ERROR:{err}" if err else "ERROR:RC_NONZERO"
                status_by_key[(scenario_id, kind)] = (True, err_code)
            else:
                status_by_key[(scenario_id, kind)] = (False, "")

    out: list[dict[str, Any]] = []
    for r in rows:
        rr = dict(r)
        sid = str(r.get("scenario_id") or "")
        kind = str(r.get("kind") or "")
        runtime_error = False
        runtime_error_code = ""
        if sid and kind:
            runtime_error, runtime_error_code = status_by_key.get((sid, kind), (False, ""))
        rr["_runtime_error"] = bool(runtime_error)
        rr["_runtime_error_code"] = str(runtime_error_code or "")
        out.append(rr)
    return out


def _classify_benign(row: dict[str, Any]) -> str:
    """
    Benign outcome classes used in threat-model-separated reporting:
    - ALLOW: normal success
    - CONFIRM: user confirmation required (soft gate)
    - HARD_DENY: explicit deny without runtime error
    - ERROR: runtime/tooling availability failure
    """
    if bool(row.get("allowed")):
        return "ALLOW"
    rc = _reason_code(row)
    if rc == "REQUIRE_CONFIRM":
        return "CONFIRM"
    if bool(row.get("_runtime_error")) or _is_reason_error(rc):
        return "ERROR"
    return "HARD_DENY"


def _summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    attacks = [r for r in rows if str(r.get("kind") or "") == "attack"]
    benign = [r for r in rows if str(r.get("kind") or "") == "benign"]

    leak = sum(1 for r in attacks if bool(r.get("leaked")))
    block = sum(1 for r in attacks if bool(r.get("blocked")))
    allow = sum(1 for r in benign if bool(r.get("allowed")))

    ben_class = [_classify_benign(r) for r in benign]
    ben_confirm = sum(1 for x in ben_class if x == "CONFIRM")
    ben_hard_deny = sum(1 for x in ben_class if x == "HARD_DENY")
    ben_error = sum(1 for x in ben_class if x == "ERROR")
    ben_non_allow = len(benign) - allow

    atk_error_block = sum(
        1
        for r in attacks
        if bool(r.get("blocked")) and (bool(r.get("_runtime_error")) or _is_reason_error(_reason_code(r)))
    )

    lat = [float(r.get("latency_s") or 0.0) for r in rows]
    p50 = statistics.median(lat) * 1000.0 if lat else 0.0
    p95 = (sorted(lat)[max(0, int(round(0.95 * (len(lat) - 1))))] * 1000.0) if lat else 0.0

    return {
        "n_total": len(rows),
        "n_attack": len(attacks),
        "n_benign": len(benign),
        "attack_leak_rate": (leak / len(attacks)) if attacks else 0.0,
        "attack_leak_rate_ci95": list(wilson_ci(leak, len(attacks))),
        "attack_block_rate": (block / len(attacks)) if attacks else 0.0,
        "attack_block_rate_ci95": list(wilson_ci(block, len(attacks))),
        "attack_error_block_rate": (atk_error_block / len(attacks)) if attacks else 0.0,
        "attack_error_block_rate_ci95": list(wilson_ci(atk_error_block, len(attacks))),
        "benign_allow_rate": (allow / len(benign)) if benign else 0.0,
        "benign_allow_rate_ci95": list(wilson_ci(allow, len(benign))),
        # Keep both:
        # - benign_non_allow_rate: ALLOW complement (legacy "deny" style)
        # - false_positive_rate: hard deny only (exclude confirm+availability failures)
        "benign_non_allow_rate": (ben_non_allow / len(benign)) if benign else 0.0,
        "benign_non_allow_rate_ci95": list(wilson_ci(ben_non_allow, len(benign))),
        "benign_confirm_rate": (ben_confirm / len(benign)) if benign else 0.0,
        "benign_confirm_rate_ci95": list(wilson_ci(ben_confirm, len(benign))),
        "false_positive_rate": (ben_hard_deny / len(benign)) if benign else 0.0,
        "false_positive_rate_ci95": list(wilson_ci(ben_hard_deny, len(benign))),
        "availability_fail_rate": (ben_error / len(benign)) if benign else 0.0,
        "availability_fail_rate_ci95": list(wilson_ci(ben_error, len(benign))),
        "benign_outcome_counts": {
            "ALLOW": int(allow),
            "CONFIRM": int(ben_confirm),
            "HARD_DENY": int(ben_hard_deny),
            "ERROR": int(ben_error),
        },
        "latency_p50_ms": float(p50),
        "latency_p95_ms": float(p95),
    }


def _breakdown(rows: list[dict[str, Any]], case_meta: dict[str, CaseMeta]) -> dict[str, Any]:
    out: dict[str, Any] = {"by_channel": {}, "by_vertical": {}, "by_attack_family": {}, "reasons_attack": {}, "reasons_benign": {}}

    def key_case(r: dict[str, Any]) -> CaseMeta | None:
        return case_meta.get(str(r.get("case_id") or ""))

    # Per-channel rates.
    for ch in sorted({str(r.get("channel") or "") for r in rows}):
        rs = [r for r in rows if str(r.get("channel") or "") == ch]
        out["by_channel"][ch] = _summarize_rows(rs)

    # By-vertical and by-family (attack only).
    attacks = [r for r in rows if str(r.get("kind") or "") == "attack"]
    by_v: dict[str, list[dict[str, Any]]] = {}
    by_f: dict[str, list[dict[str, Any]]] = {}
    for r in attacks:
        m = key_case(r)
        if not m:
            continue
        if m.vertical:
            by_v.setdefault(m.vertical, []).append(r)
        if m.attack_family:
            by_f.setdefault(m.attack_family, []).append(r)
    for v, rs in sorted(by_v.items()):
        out["by_vertical"][v] = _summarize_rows(rs)
    for f, rs in sorted(by_f.items()):
        out["by_attack_family"][f] = _summarize_rows(rs)

    # Reason code distributions (useful for failure modes).
    def top_reasons(sub: list[dict[str, Any]], k: int = 20) -> list[tuple[str, int]]:
        cnt: dict[str, int] = {}
        for r in sub:
            rc = str(r.get("reason_code") or "")
            cnt[rc] = cnt.get(rc, 0) + 1
        return sorted(cnt.items(), key=lambda kv: (-kv[1], kv[0]))[:k]

    out["reasons_attack"] = top_reasons([r for r in rows if str(r.get("kind") or "") == "attack"])
    out["reasons_benign"] = top_reasons([r for r in rows if str(r.get("kind") or "") == "benign"])
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default="artifact_out_compare_noprompt/fair_full_report.json", help="Path to fair_full_report.json")
    ap.add_argument("--out", default="artifact_out_compare_noprompt/stats/fair_full_stats.json", help="Output JSON path")
    args = ap.parse_args()

    report_path = Path(str(args.report)).expanduser().resolve()
    rep = _load_json(report_path)
    out_root = report_path.parent

    manifest_path = Path(str(rep.get("cases_manifest_path") or "")).expanduser()
    if not manifest_path.exists():
        raise FileNotFoundError(f"cases_manifest_path missing: {manifest_path}")
    case_meta = _load_case_meta(manifest_path)

    # Load MIRAGE per-case rows (CSV).
    mirage_csv = out_root / "fair_mirage" / "agentleak_eval" / "agentleak_eval_rows.csv"
    mirage_rows_all = _read_mirage_rows(mirage_csv) if mirage_csv.exists() else []

    systems = rep.get("systems") if isinstance(rep.get("systems"), dict) else {}
    sys_rows: dict[str, list[dict[str, Any]]] = {}

    # MIRAGE modes from CSV.
    for name in ("mirage_full", "policy_only", "sandbox_only", "single_server_policy"):
        rs = [r for r in mirage_rows_all if str(r.get("mode") or "") == name]
        if rs:
            sys_rows[name] = rs

    # Native and defense baselines from their summaries (path carried in fair_full_report.json).
    if isinstance(systems, dict):
        for name, sysd in systems.items():
            if name in {"mirage_full", "policy_only", "sandbox_only", "single_server_policy"}:
                continue
            if not isinstance(sysd, dict):
                continue
            sp = str(sysd.get("source_path") or "")
            if not sp:
                continue
            p = Path(sp).expanduser()
            if not p.exists():
                continue
            d = _load_json(p)
            rows = d.get("rows") if isinstance(d.get("rows"), list) else []
            rs2 = [r for r in rows if isinstance(r, dict)]
            if rs2:
                rs2 = _annotate_native_runtime_errors(rs2, summary_path=p)
                sys_rows[str(name)] = rs2

    summaries: dict[str, Any] = {}
    breakdowns: dict[str, Any] = {}
    for name, rows in sys_rows.items():
        summaries[name] = _summarize_rows(rows)
        breakdowns[name] = _breakdown(rows, case_meta)

    # Significance tests vs mirage_full (attack leak + benign allow).
    tests: dict[str, Any] = {}
    ref = summaries.get("mirage_full") if isinstance(summaries.get("mirage_full"), dict) else None
    if isinstance(ref, dict):
        for name, sm in summaries.items():
            if name == "mirage_full" or not isinstance(sm, dict):
                continue
            # attack leak: (leak, no-leak)
            rrows = sys_rows.get("mirage_full") or []
            trows = sys_rows.get(name) or []
            leak_r = sum(1 for r in rrows if str(r.get("kind") or "") == "attack" and bool(r.get("leaked")))
            atk_r = sum(1 for r in rrows if str(r.get("kind") or "") == "attack")
            leak_t = sum(1 for r in trows if str(r.get("kind") or "") == "attack" and bool(r.get("leaked")))
            atk_t = sum(1 for r in trows if str(r.get("kind") or "") == "attack")
            # benign allow: (allow, deny)
            allow_r = sum(1 for r in rrows if str(r.get("kind") or "") == "benign" and bool(r.get("allowed")))
            ben_r = sum(1 for r in rrows if str(r.get("kind") or "") == "benign")
            allow_t = sum(1 for r in trows if str(r.get("kind") or "") == "benign" and bool(r.get("allowed")))
            ben_t = sum(1 for r in trows if str(r.get("kind") or "") == "benign")
            hard_r = sum(1 for r in rrows if str(r.get("kind") or "") == "benign" and _classify_benign(r) == "HARD_DENY")
            hard_t = sum(1 for r in trows if str(r.get("kind") or "") == "benign" and _classify_benign(r) == "HARD_DENY")
            non_allow_r = ben_r - allow_r
            non_allow_t = ben_t - allow_t

            p_attack = fisher_exact_two_sided(leak_r, max(0, atk_r - leak_r), leak_t, max(0, atk_t - leak_t)) if (atk_r and atk_t) else 1.0
            p_benign = fisher_exact_two_sided(allow_r, max(0, ben_r - allow_r), allow_t, max(0, ben_t - allow_t)) if (ben_r and ben_t) else 1.0
            p_hard = fisher_exact_two_sided(hard_r, max(0, ben_r - hard_r), hard_t, max(0, ben_t - hard_t)) if (ben_r and ben_t) else 1.0
            p_non_allow = (
                fisher_exact_two_sided(non_allow_r, max(0, ben_r - non_allow_r), non_allow_t, max(0, ben_t - non_allow_t))
                if (ben_r and ben_t)
                else 1.0
            )
            tests[name] = {
                "attack_leak_fisher_p_two_sided": float(p_attack),
                "benign_allow_fisher_p_two_sided": float(p_benign),
                "benign_hard_deny_fisher_p_two_sided": float(p_hard),
                "benign_non_allow_fisher_p_two_sided": float(p_non_allow),
                "counts": {
                    "mirage_full": {
                        "attack_leaks": leak_r,
                        "attack_n": atk_r,
                        "benign_allows": allow_r,
                        "benign_non_allow": non_allow_r,
                        "benign_hard_deny": hard_r,
                        "benign_n": ben_r,
                    },
                    "other": {
                        "system": name,
                        "attack_leaks": leak_t,
                        "attack_n": atk_t,
                        "benign_allows": allow_t,
                        "benign_non_allow": non_allow_t,
                        "benign_hard_deny": hard_t,
                        "benign_n": ben_t,
                    },
                },
            }

    out = {
        "status": "OK",
        "report_path": str(report_path),
        "cases_manifest_path": str(manifest_path),
        "systems_present": sorted(sys_rows.keys()),
        "summaries": summaries,
        "breakdowns": breakdowns,
        "significance_vs_mirage_full": tests,
    }
    out_path = Path(str(args.out)).expanduser().resolve()
    _write_json(out_path, out)
    print(str(out_path))


if __name__ == "__main__":
    main()
