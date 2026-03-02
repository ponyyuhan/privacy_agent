from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
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
    obj = json.loads(path.read_text(encoding="utf-8"))
    return obj if isinstance(obj, dict) else {}


def _load_rows_csv(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8", newline="") as f:
        rd = csv.DictReader(f)
        for r in rd:
            out.append({str(k): v for k, v in (r or {}).items()})
    return out


def _to_bool(x: Any) -> bool:
    s = str(x).strip().lower()
    return s in {"1", "true", "yes", "y"}


def _reason_code(row: dict[str, Any]) -> str:
    return str(row.get("reason_code") or "").strip()


def _is_reason_error(reason_code: str) -> bool:
    rc = str(reason_code or "").strip().upper()
    if not rc:
        return False
    if any(rc.startswith(pfx) for pfx in _ERROR_REASON_PREFIXES):
        return True
    return False


def _annotate_runtime_errors(rows: list[dict[str, Any]], *, summary_path: Path) -> list[dict[str, Any]]:
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
        runtime_error, runtime_error_code = status_by_key.get((sid, kind), (False, ""))
        rr["_runtime_error"] = bool(runtime_error)
        rr["_runtime_error_code"] = str(runtime_error_code or "")
        out.append(rr)
    return out


def _classify_benign(row: dict[str, Any]) -> str:
    if _to_bool(row.get("allowed")):
        return "ALLOW"
    rc = _reason_code(row)
    if rc == "REQUIRE_CONFIRM":
        return "CONFIRM"
    if _to_bool(row.get("_runtime_error")) or _is_reason_error(rc):
        return "ERROR"
    return "HARD_DENY"


def _summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not rows:
        return {
            "n_total": 0,
            "n_attack": 0,
            "n_benign": 0,
            "attack_leaks": 0,
            "attack_blocks": 0,
            "attack_error_blocks": 0,
            "benign_outcomes": {"ALLOW": 0, "CONFIRM": 0, "HARD_DENY": 0, "ERROR": 0},
            "benign_non_allows": 0,
            "benign_non_allow_by_reason": {},
            "benign_non_allow_by_channel": {},
            "benign_non_allow_reason_by_channel": {},
        }

    atk = [r for r in rows if str(r.get("kind") or "").lower() == "attack"]
    ben = [r for r in rows if str(r.get("kind") or "").lower() == "benign"]

    attack_leaks = sum(1 for r in atk if _to_bool(r.get("leaked")))
    attack_blocks = sum(1 for r in atk if _to_bool(r.get("blocked")))
    attack_error_blocks = sum(
        1
        for r in atk
        if _to_bool(r.get("blocked")) and (_to_bool(r.get("_runtime_error")) or _is_reason_error(_reason_code(r)))
    )
    benign_outcomes = [_classify_benign(r) for r in ben]
    benign_counts = Counter(benign_outcomes)
    benign_non_allows = len(ben) - int(benign_counts.get("ALLOW", 0))

    by_reason = Counter()
    by_channel = Counter()
    by_channel_reason: dict[str, Counter[str]] = defaultdict(Counter)
    for r in ben:
        if _classify_benign(r) == "ALLOW":
            continue
        ch = str(r.get("channel") or "")
        rc = str(_reason_code(r) or r.get("_runtime_error_code") or "UNKNOWN")
        by_reason[rc] += 1
        by_channel[ch] += 1
        by_channel_reason[ch][rc] += 1

    out["n_total"] = int(len(rows))
    out["n_attack"] = int(len(atk))
    out["n_benign"] = int(len(ben))
    out["attack_leaks"] = int(attack_leaks)
    out["attack_blocks"] = int(attack_blocks)
    out["attack_error_blocks"] = int(attack_error_blocks)
    out["benign_outcomes"] = {
        "ALLOW": int(benign_counts.get("ALLOW", 0)),
        "CONFIRM": int(benign_counts.get("CONFIRM", 0)),
        "HARD_DENY": int(benign_counts.get("HARD_DENY", 0)),
        "ERROR": int(benign_counts.get("ERROR", 0)),
    }
    out["benign_non_allows"] = int(benign_non_allows)
    out["benign_non_allow_by_reason"] = dict(sorted(by_reason.items(), key=lambda kv: (-kv[1], kv[0])))
    out["benign_non_allow_by_channel"] = dict(sorted(by_channel.items(), key=lambda kv: (-kv[1], kv[0])))
    out["benign_non_allow_reason_by_channel"] = {
        str(ch): dict(sorted(cnt.items(), key=lambda kv: (-kv[1], kv[0])))
        for ch, cnt in sorted(by_channel_reason.items(), key=lambda kv: kv[0])
    }
    return out


def _summarize_rows_by_mode(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        m = str(r.get("mode") or "unknown")
        by[m].append(r)
    return {m: _summarize_rows(rs) for m, rs in sorted(by.items(), key=lambda kv: kv[0])}


def _load_native_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    obj = _load_json(path)
    rows = obj.get("rows")
    if not isinstance(rows, list):
        return []
    out: list[dict[str, Any]] = []
    for r in rows:
        if isinstance(r, dict):
            out.append(r)
    return _annotate_runtime_errors(out, summary_path=path)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default="artifact_out_compare_noprompt/fair_full_report.json", help="fair_full_report.json path")
    ap.add_argument("--mirage-rows", default="", help="SecureClaw rows CSV (optional; auto-derived from report)")
    ap.add_argument("--codex-summary", default="", help="Codex native summary (optional; auto-derived from report)")
    ap.add_argument("--openclaw-summary", default="", help="OpenClaw native summary (optional; auto-derived from report)")
    ap.add_argument("--allow-missing-native", type=int, default=0, help="Set to 1 to allow missing native baseline summary files.")
    ap.add_argument("--out", default="artifact_out_compare_noprompt/stats/fair_utility_breakdown.json", help="Output JSON")
    args = ap.parse_args()

    report_path = Path(str(args.report)).expanduser().resolve()
    report = _load_json(report_path) if report_path.exists() else {}
    report_root = report_path.parent

    mirage_rows_path = (
        Path(str(args.mirage_rows)).expanduser().resolve()
        if str(args.mirage_rows).strip()
        else (report_root / "fair_mirage" / "agentleak_eval" / "agentleak_eval_rows.csv")
    )
    codex_summary_path = (
        Path(str(args.codex_summary)).expanduser().resolve()
        if str(args.codex_summary).strip()
        else (report_root / "fair_codex_native_guardrails" / "native_official_baseline_summary.json")
    )
    openclaw_summary_path = (
        Path(str(args.openclaw_summary)).expanduser().resolve()
        if str(args.openclaw_summary).strip()
        else (report_root / "fair_openclaw_native_guardrails" / "native_official_baseline_summary.json")
    )
    out_path = Path(str(args.out)).expanduser().resolve()

    mirage_rows = _load_rows_csv(mirage_rows_path)

    systems = report.get("systems")
    systems_meta = systems if isinstance(systems, dict) else {}
    missing_native: list[str] = []

    native_rows_by_system: dict[str, list[dict[str, Any]]] = {}
    native_source_by_system: dict[str, str] = {}
    if isinstance(systems_meta, dict):
        for sys_name, sys_meta in systems_meta.items():
            if not isinstance(sys_meta, dict):
                continue
            if sys_name in {"mirage_full", "policy_only", "sandbox_only", "single_server_policy"}:
                continue
            src = str(sys_meta.get("source_path") or "")
            if not src:
                continue
            p = Path(src).expanduser()
            if not p.exists():
                missing_native.append(str(p))
                continue
            rows = _load_native_rows(p)
            native_rows_by_system[str(sys_name)] = rows
            native_source_by_system[str(sys_name)] = str(p)

    # Keep explicit codex/openclaw paths visible in output for convenience.
    if not codex_summary_path.exists():
        missing_native.append(str(codex_summary_path))
    if not openclaw_summary_path.exists():
        missing_native.append(str(openclaw_summary_path))
    missing_native = sorted(set(missing_native))
    if missing_native and not bool(int(args.allow_missing_native)):
        raise SystemExit("missing_native_baseline_summary: " + ", ".join(missing_native))

    out: dict[str, Any] = {
        "status": "OK",
        "report_path": str(report_path),
        "inputs": {
            "mirage_rows": str(mirage_rows_path),
            "codex_summary": str(codex_summary_path),
            "openclaw_summary": str(openclaw_summary_path),
        },
        "missing_native_summaries": missing_native,
        "systems_meta": systems_meta,
        "breakdown": {
            "secureclaw_all_modes": _summarize_rows(mirage_rows),
            "secureclaw_by_mode": _summarize_rows_by_mode(mirage_rows),
            "native_by_system": {k: _summarize_rows(v) for k, v in sorted(native_rows_by_system.items(), key=lambda kv: kv[0])},
            "native_source_by_system": native_source_by_system,
        },
    }
    if "codex_native" in native_rows_by_system:
        out["breakdown"]["codex_native"] = _summarize_rows(native_rows_by_system["codex_native"])
    if "openclaw_native" in native_rows_by_system:
        out["breakdown"]["openclaw_native"] = _summarize_rows(native_rows_by_system["openclaw_native"])

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()
