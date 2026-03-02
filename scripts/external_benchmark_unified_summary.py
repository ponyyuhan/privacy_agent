#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_float(n: int, d: int) -> float | None:
    if d <= 0:
        return None
    return n / d


def _load_json(path: Path) -> dict[str, Any] | list[Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _norm_path(path: Path) -> str:
    try:
        return str(path.expanduser().resolve())
    except Exception:
        return str(path)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except Exception:
        return False


IPIGUARD_USER_TASK_NUM: dict[str, int] = {
    "banking": 16,
    "slack": 21,
    "travel": 20,
    "workspace": 40,
}

IPIGUARD_INJECTION_TASK_NUM: dict[str, int] = {
    "banking": 9,
    "slack": 5,
    "travel": 7,
    "workspace": 6,
}


def _ipiguard_expected_rows(mode: str, suite: str) -> int:
    users = int(IPIGUARD_USER_TASK_NUM.get(suite, 0))
    if users <= 0:
        return 0
    if mode == "under_attack":
        return users * int(IPIGUARD_INJECTION_TASK_NUM.get(suite, 0))
    return users


def agentdojo_summary(model_dir: Path, benchmark_version: str) -> dict[str, Any]:
    progress_script = Path("scripts/agentdojo_progress.py")
    if not progress_script.exists():
        return {
            "status": "missing_progress_script",
            "model_dir": _norm_path(model_dir),
            "benchmark_version": benchmark_version,
        }

    import subprocess

    try:
        proc = subprocess.run(
            [
                os.environ.get("PYTHON", "python"),
                str(progress_script),
                "--model-dir",
                str(model_dir),
                "--benchmark-version",
                benchmark_version,
            ],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": "third_party/agentdojo/src"},
        )
        obj = json.loads(proc.stdout)
        ws = obj.get("suites", {}).get("workspace", {})
        complete = ws.get("missing") == 0
        return {
            "status": "ok",
            "complete": complete,
            "raw": obj,
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "model_dir": _norm_path(model_dir),
            "benchmark_version": benchmark_version,
        }


def _to_int(v: Any) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return 0


def summarize_asb_csv(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"path": _norm_path(path), "status": "missing"}

    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        rows.extend(reader)

    n = len(rows)
    if n == 0:
        return {"path": _norm_path(path), "status": "empty", "rows": 0}

    attack = sum(_to_int(r.get("Attack Successful", 0)) for r in rows)
    utility = sum(_to_int(r.get("Original Task Successful", 0)) for r in rows)
    refuse = sum(_to_int(r.get("Refuse Result", 0)) for r in rows)
    aggressive = sum(_to_int(r.get("Aggressive", 0)) for r in rows)

    return {
        "path": _norm_path(path),
        "status": "ok",
        "rows": n,
        "attack_success_count": attack,
        "attack_success_rate": _safe_float(attack, n),
        "utility_success_count": utility,
        "utility_success_rate": _safe_float(utility, n),
        "refuse_count": refuse,
        "refuse_rate": _safe_float(refuse, n),
        "aggressive_count": aggressive,
        "aggressive_rate": _safe_float(aggressive, n),
    }


def asb_summary(asb_dir: Path, run_tag: str, allow_latest_fallback: bool) -> dict[str, Any]:
    attacks = ["naive", "escape_characters", "fake_completion"]
    files: list[dict[str, Any]] = []
    run_tag = str(run_tag or "").strip()
    for atk in attacks:
        if run_tag:
            exact = asb_dir / f"{atk}-all_lowmem_{run_tag}.csv"
            if exact.exists():
                files.append(
                    {
                        "attack_type": atk,
                        "selection_mode": "run_tag_exact",
                        "requested_run_tag": run_tag,
                        **summarize_asb_csv(exact),
                    }
                )
            else:
                recent = sorted(
                    asb_dir.glob(f"{atk}-all_lowmem_*.csv"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                files.append(
                    {
                        "attack_type": atk,
                        "status": "missing_for_run_tag",
                        "requested_run_tag": run_tag,
                        "expected_path": _norm_path(exact),
                        "recent_candidates": [_norm_path(p) for p in recent[:5]],
                    }
                )
            continue

        if allow_latest_fallback:
            candidates = sorted(
                asb_dir.glob(f"{atk}-all_lowmem_*.csv"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if candidates:
                files.append(
                    {
                        "attack_type": atk,
                        "selection_mode": "latest_fallback",
                        **summarize_asb_csv(candidates[0]),
                    }
                )
            else:
                files.append({"attack_type": atk, "status": "missing"})
        else:
            files.append(
                {
                    "attack_type": atk,
                    "status": "run_tag_required",
                    "hint": "pass --asb-run-tag <RUN_TAG> or set --allow-asb-latest-fallback 1",
                }
            )
    return {
        "status": "ok",
        "dir": _norm_path(asb_dir),
        "requested_run_tag": run_tag,
        "allow_latest_fallback": bool(allow_latest_fallback),
        "files": files,
    }


def _collect_json_files(base: Path, pattern: str) -> list[Path]:
    return sorted(base.glob(pattern))


def _summarize_bool_json_files(paths: list[Path]) -> dict[str, Any]:
    total = 0
    utility_true = 0
    security_true = 0
    parse_errors = 0
    for p in paths:
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
            total += 1
            if bool(obj.get("utility")):
                utility_true += 1
            if bool(obj.get("security")):
                security_true += 1
        except Exception:
            parse_errors += 1
    return {
        "total": total,
        "utility_success_count": utility_true,
        "utility_success_rate": _safe_float(utility_true, total),
        "security_true_count": security_true,
        "security_true_rate": _safe_float(security_true, total),
        "parse_errors": parse_errors,
    }


def drift_summary(drift_runs_dir: Path, attack_name: str) -> dict[str, Any]:
    if not drift_runs_dir.exists():
        return {"status": "missing", "dir": _norm_path(drift_runs_dir)}

    suites = [d.name for d in sorted(drift_runs_dir.iterdir()) if d.is_dir()]
    suites_out: dict[str, Any] = {}

    for suite in suites:
        suite_dir = drift_runs_dir / suite
        benign_paths = _collect_json_files(suite_dir, "user_task_*/none/none.json")
        attack_paths = _collect_json_files(
            suite_dir, f"user_task_*/{attack_name}/injection_task_*.json"
        )

        benign_stat = _summarize_bool_json_files(benign_paths)
        attack_stat = _summarize_bool_json_files(attack_paths)

        suites_out[suite] = {
            "benign": {
                "files": len(benign_paths),
                "utility_success_count": benign_stat["utility_success_count"],
                "utility_success_rate": benign_stat["utility_success_rate"],
                "parse_errors": benign_stat["parse_errors"],
            },
            "under_attack": {
                "files": len(attack_paths),
                "attack_success_count": attack_stat["security_true_count"],
                "attack_success_rate": attack_stat["security_true_rate"],
                "utility_success_count": attack_stat["utility_success_count"],
                "utility_success_rate": attack_stat["utility_success_rate"],
                "parse_errors": attack_stat["parse_errors"],
            },
        }

    return {
        "status": "ok",
        "dir": _norm_path(drift_runs_dir),
        "attack_name": attack_name,
        "suites": suites_out,
    }


def parse_multi_json_stream(text: str) -> list[dict[str, Any]]:
    objs: list[dict[str, Any]] = []
    dec = json.JSONDecoder()
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        try:
            obj, j = dec.raw_decode(text, i)
            if isinstance(obj, dict):
                objs.append(obj)
            i = j
        except json.JSONDecodeError:
            i += 1
            continue
    return objs


def summarize_ipiguard_file(path: Path, mode: str, suite: str) -> dict[str, Any]:
    if not path.exists():
        return {"status": "missing", "path": _norm_path(path)}

    txt = path.read_text(encoding="utf-8", errors="replace")
    objs = parse_multi_json_stream(txt)
    if not objs:
        return {"status": "empty_or_unparseable", "path": _norm_path(path)}

    if mode == "under_attack":
        tasks = [
            o
            for o in objs
            if "user_task_id" in o and "injection_task_id" in o and o.get("injection_task_id") is not None
        ]
    else:
        tasks = [
            o
            for o in objs
            if "user_task_id" in o and ("injection_task_id" not in o or o.get("injection_task_id") is None)
        ]

    dedup: dict[tuple[str, str], dict[str, Any]] = {}
    for o in tasks:
        uid = str(o.get("user_task_id"))
        iid = (
            str(o.get("injection_task_id"))
            if mode == "under_attack"
            else ""
        )
        dedup[(uid, iid)] = o
    dedup_tasks = list(dedup.values())

    raw_total = len(tasks)
    total = len(dedup_tasks)
    duplicate_rows = max(0, raw_total - total)
    utility_true = sum(_to_int(o.get("utility", 0)) for o in dedup_tasks)
    security_true = sum(_to_int(o.get("security", 0)) for o in dedup_tasks)
    expected_rows = _ipiguard_expected_rows(mode, suite)

    suite_summaries = [o for o in objs if "Suite" in o and "ASR" in o and "Utility" in o]
    overall_summaries = [o for o in objs if "ASR" in o and "Utility" in o and "Suite" not in o]

    return {
        "status": "ok",
        "path": _norm_path(path),
        "raw_task_rows": raw_total,
        "task_rows": total,
        "duplicate_task_rows": duplicate_rows,
        "expected_task_rows": expected_rows,
        "rows_match_expected": bool(expected_rows > 0 and total == expected_rows),
        "utility_success_count": utility_true,
        "utility_success_rate": _safe_float(utility_true, total),
        "security_true_count": security_true,
        "security_true_rate": _safe_float(security_true, total),
        "reported_suite_summaries": suite_summaries,
        "reported_overall_summaries": overall_summaries,
    }


def ipiguard_summary(ipiguard_root: Path) -> dict[str, Any]:
    if not ipiguard_root.exists():
        return {"status": "missing", "dir": _norm_path(ipiguard_root)}

    suites = ["banking", "slack", "travel", "workspace"]
    modes = ["benign", "under_attack"]

    out: dict[str, Any] = {}
    for mode in modes:
        out[mode] = {}
        for suite in suites:
            path = ipiguard_root / mode / suite / "results.jsonl"
            out[mode][suite] = summarize_ipiguard_file(path, mode, suite)

    return {
        "status": "ok",
        "dir": _norm_path(ipiguard_root),
        "suites": out,
    }


def render_md(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# External Benchmark Unified Summary")
    lines.append("")
    lines.append(f"- generated_at_utc: `{report.get('generated_at_utc')}`")

    ad = report.get("agentdojo", {})
    lines.append("")
    lines.append("## AgentDojo")
    if ad.get("status") == "ok":
        ws = ad.get("raw", {}).get("suites", {}).get("workspace", {})
        lines.append(
            f"- workspace: present={ws.get('present')} missing={ws.get('missing')} expected={ws.get('expected')}"
        )
        lines.append(f"- complete: `{ad.get('complete')}`")
    else:
        lines.append(f"- status: `{ad.get('status')}`")

    lines.append("")
    lines.append("## ASB")
    asb = report.get("asb", {})
    if asb.get("requested_run_tag"):
        lines.append(f"- requested_run_tag: `{asb.get('requested_run_tag')}`")
    lines.append(f"- allow_latest_fallback: `{asb.get('allow_latest_fallback')}`")
    for f in asb.get("files", []):
        atk = f.get("attack_type")
        if f.get("status") == "ok":
            lines.append(
                f"- {atk}: rows={f.get('rows')} asr={f.get('attack_success_rate')} utility={f.get('utility_success_rate')} selection={f.get('selection_mode')}"
            )
        else:
            lines.append(f"- {atk}: status={f.get('status')} selection={f.get('selection_mode')}")

    lines.append("")
    lines.append("## DRIFT")
    drift = report.get("drift", {})
    suites = drift.get("suites", {})
    if suites:
        for suite, s in suites.items():
            b = s.get("benign", {})
            a = s.get("under_attack", {})
            lines.append(
                f"- {suite}: benign_files={b.get('files')} benign_utility={b.get('utility_success_rate')} attack_files={a.get('files')} attack_asr={a.get('attack_success_rate')} attack_utility={a.get('utility_success_rate')}"
            )
    else:
        lines.append(f"- status: {drift.get('status')}")

    lines.append("")
    lines.append("## IPIGuard")
    ipi = report.get("ipiguard", {})
    suites2 = ipi.get("suites", {})
    if suites2:
        for mode in ["benign", "under_attack"]:
            lines.append(f"- mode={mode}")
            for suite, s in suites2.get(mode, {}).items():
                lines.append(
                    f"  - {suite}: status={s.get('status')} rows={s.get('task_rows')}/{s.get('expected_task_rows')} dup={s.get('duplicate_task_rows')} asr={s.get('security_true_rate')} utility_rate={s.get('utility_success_rate')}"
                )
    else:
        lines.append(f"- status: {ipi.get('status')}")

    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--agentdojo-model-dir",
        default="third_party/agentdojo/runs/gpt-4o-mini-2024-07-18",
    )
    ap.add_argument("--agentdojo-benchmark-version", default="v1.2.2")
    ap.add_argument(
        "--asb-dir",
        default="third_party/ASB/logs/direct_prompt_injection/gpt-4o-mini/no_memory",
    )
    ap.add_argument(
        "--asb-run-tag",
        default="",
        help="ASB RUN_TAG to enforce exact file selection (<attack>-all_lowmem_<RUN_TAG>.csv).",
    )
    ap.add_argument(
        "--allow-asb-latest-fallback",
        type=int,
        default=0,
        help="Set to 1 to allow latest-by-mtime fallback when --asb-run-tag is not provided.",
    )
    ap.add_argument(
        "--drift-runs-dir",
        default="third_party/DRIFT/runs/gpt-4o-mini-2024-07-18",
    )
    ap.add_argument("--drift-attack-name", default="important_instructions")
    ap.add_argument(
        "--ipiguard-root",
        default="artifact_out_external_runtime/external_runs/latest/ipiguard",
        help="Path to ipiguard output root containing benign/under_attack subdirs",
    )
    ap.add_argument(
        "--output-json",
        default="artifact_out_external_runtime/external_benchmark_unified_report.json",
    )
    ap.add_argument(
        "--output-md",
        default="artifact_out_external_runtime/external_benchmark_unified_report.md",
    )
    ap.add_argument(
        "--external-run-tag",
        default="",
        help="External run tag used to materialize this report.",
    )
    ap.add_argument(
        "--external-out-root",
        default="",
        help="Expected run-isolated root (typically artifact_out_external_runtime/external_runs/<RUN_TAG>).",
    )
    ap.add_argument(
        "--enforce-run-scope",
        type=int,
        default=0,
        help="Set to 1 to require drift/ipiguard paths to be under --external-out-root.",
    )
    return ap.parse_args()


def main() -> None:
    args = parse_args()

    out = {
        "generated_at_utc": _now_iso(),
        "scope": {
            "external_run_tag": str(args.external_run_tag or ""),
            "external_out_root": _norm_path(Path(args.external_out_root)) if str(args.external_out_root).strip() else "",
            "enforce_run_scope": bool(int(args.enforce_run_scope)),
        },
        "agentdojo": agentdojo_summary(
            Path(args.agentdojo_model_dir), args.agentdojo_benchmark_version
        ),
        "asb": asb_summary(
            Path(args.asb_dir),
            run_tag=str(args.asb_run_tag),
            allow_latest_fallback=bool(int(args.allow_asb_latest_fallback)),
        ),
        "drift": drift_summary(Path(args.drift_runs_dir), args.drift_attack_name),
        "ipiguard": ipiguard_summary(Path(args.ipiguard_root)),
    }

    out_root_raw = str(args.external_out_root or "").strip()
    if out_root_raw:
        out_root = Path(out_root_raw).expanduser().resolve()
        drift_dir = Path(str((out.get("drift") or {}).get("dir") or "")).expanduser().resolve()
        ipi_dir = Path(str((out.get("ipiguard") or {}).get("dir") or "")).expanduser().resolve()
        path_checks = {
            "drift_in_scope": _is_within(drift_dir, out_root) if str((out.get("drift") or {}).get("dir") or "") else False,
            "ipiguard_in_scope": _is_within(ipi_dir, out_root) if str((out.get("ipiguard") or {}).get("dir") or "") else False,
        }
        (out.get("scope") or {})["path_checks"] = path_checks
        if bool(int(args.enforce_run_scope)):
            if not path_checks["drift_in_scope"]:
                raise SystemExit("drift_dir_outside_external_out_root")
            if not path_checks["ipiguard_in_scope"]:
                raise SystemExit("ipiguard_dir_outside_external_out_root")

    output_json = Path(args.output_json)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    output_md = Path(args.output_md)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(render_md(out), encoding="utf-8")

    print(json.dumps({"output_json": str(output_json), "output_md": str(output_md)}, indent=2))


if __name__ == "__main__":
    main()
