from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


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


def _summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not rows:
        return {
            "n_total": 0,
            "n_attack": 0,
            "n_benign": 0,
            "attack_leaks": 0,
            "attack_blocks": 0,
            "benign_allows": 0,
            "benign_denies": 0,
            "benign_deny_by_reason": {},
            "benign_deny_by_channel": {},
            "benign_deny_reason_by_channel": {},
        }

    atk = [r for r in rows if str(r.get("kind") or "").lower() == "attack"]
    ben = [r for r in rows if str(r.get("kind") or "").lower() == "benign"]

    attack_leaks = sum(1 for r in atk if _to_bool(r.get("leaked")))
    attack_blocks = sum(1 for r in atk if _to_bool(r.get("blocked")))
    benign_allows = sum(1 for r in ben if _to_bool(r.get("allowed")))
    benign_denies = len(ben) - benign_allows

    by_reason = Counter()
    by_channel = Counter()
    by_channel_reason: dict[str, Counter[str]] = defaultdict(Counter)
    for r in ben:
        if _to_bool(r.get("allowed")):
            continue
        ch = str(r.get("channel") or "")
        rc = str(r.get("reason_code") or "UNKNOWN")
        by_reason[rc] += 1
        by_channel[ch] += 1
        by_channel_reason[ch][rc] += 1

    out["n_total"] = int(len(rows))
    out["n_attack"] = int(len(atk))
    out["n_benign"] = int(len(ben))
    out["attack_leaks"] = int(attack_leaks)
    out["attack_blocks"] = int(attack_blocks)
    out["benign_allows"] = int(benign_allows)
    out["benign_denies"] = int(benign_denies)
    out["benign_deny_by_reason"] = dict(sorted(by_reason.items(), key=lambda kv: (-kv[1], kv[0])))
    out["benign_deny_by_channel"] = dict(sorted(by_channel.items(), key=lambda kv: (-kv[1], kv[0])))
    out["benign_deny_reason_by_channel"] = {
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
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default="artifact_out_compare/fair_full_report.json", help="fair_full_report.json path")
    ap.add_argument("--mirage-rows", default="artifact_out_compare/fair_mirage/agentleak_eval/agentleak_eval_rows.csv", help="SecureClaw rows CSV")
    ap.add_argument("--codex-summary", default="artifact_out_compare/fair_codex_native_guardrails/native_official_baseline_summary.json", help="Codex native summary")
    ap.add_argument("--openclaw-summary", default="artifact_out_compare/fair_openclaw_native_guardrails/native_official_baseline_summary.json", help="OpenClaw native summary")
    ap.add_argument("--allow-missing-native", type=int, default=0, help="Set to 1 to allow missing native baseline summary files.")
    ap.add_argument("--out", default="artifact_out_compare/stats/fair_utility_breakdown.json", help="Output JSON")
    args = ap.parse_args()

    report_path = Path(str(args.report)).expanduser().resolve()
    mirage_rows_path = Path(str(args.mirage_rows)).expanduser().resolve()
    codex_summary_path = Path(str(args.codex_summary)).expanduser().resolve()
    openclaw_summary_path = Path(str(args.openclaw_summary)).expanduser().resolve()
    out_path = Path(str(args.out)).expanduser().resolve()

    report = _load_json(report_path) if report_path.exists() else {}
    mirage_rows = _load_rows_csv(mirage_rows_path)
    missing_native: list[str] = []
    if not codex_summary_path.exists():
        missing_native.append(str(codex_summary_path))
    if not openclaw_summary_path.exists():
        missing_native.append(str(openclaw_summary_path))
    if missing_native and not bool(int(args.allow_missing_native)):
        raise SystemExit("missing_native_baseline_summary: " + ", ".join(missing_native))

    codex_rows = _load_native_rows(codex_summary_path)
    openclaw_rows = _load_native_rows(openclaw_summary_path)

    systems = report.get("systems")
    systems_meta = systems if isinstance(systems, dict) else {}

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
            "codex_native": _summarize_rows(codex_rows),
            "openclaw_native": _summarize_rows(openclaw_rows),
        },
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()
