#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class SuiteStats:
    suite: str
    files: int
    asr_success: int
    usr_success: int
    done: bool
    log_exists: bool

    @property
    def asr_rate(self) -> float:
        return (self.asr_success / self.files) if self.files else 0.0

    @property
    def usr_rate(self) -> float:
        return (self.usr_success / self.files) if self.files else 0.0


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def collect_suite_stats(run_root: Path, model: str, suite: str) -> SuiteStats:
    log_path = run_root / "logs" / f"drift_attack_{suite}.log"
    log_text = _safe_read_text(log_path) if log_path.exists() else ""
    # Avoid trailing word-boundary after "!" (non-word), which can miss valid lines.
    done = bool(re.search(rf"\b{re.escape(suite)}\s+Done!", log_text))

    all_files: list[Path] = []
    root = (
        run_root
        / "drift_workspace"
        / "runs"
        / model
        / suite
    )
    if root.exists():
        all_files = sorted(root.glob("user_task_*/important_instructions/injection_task_*.json"))

    asr_success = 0
    usr_success = 0
    for fp in all_files:
        try:
            obj = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if bool(obj.get("security")):
            asr_success += 1
        if bool(obj.get("utility")):
            usr_success += 1

    return SuiteStats(
        suite=suite,
        files=len(all_files),
        asr_success=asr_success,
        usr_success=usr_success,
        done=done,
        log_exists=log_path.exists(),
    )


def collect_log_errors(run_root: Path, suite: str) -> dict[str, int]:
    log_path = run_root / "logs" / f"drift_attack_{suite}.log"
    txt = _safe_read_text(log_path)
    soft_reformat = txt.count("Function Call Tags Not Found. Requesting strict reformat once.")
    hard_tag_miss = txt.count("Function Call Tags Not Found.") - soft_reformat
    if hard_tag_miss < 0:
        hard_tag_miss = 0
    return {
        "CALL_ERROR": txt.count("[CALL ERROR]"),
        "Function_Call_Tags_Not_Found": hard_tag_miss,
        "Function_Call_Tags_Reformat_Request": soft_reformat,
        "Node_Checklist_Json_Format_Invalid": txt.count("Node Checklist Json Format Invalid"),
        "APITimeoutError": txt.count("APITimeoutError"),
        "Retrying_chat_completions": txt.count("Retrying request to /chat/completions"),
    }


def to_markdown(
    tag: str,
    generated_at: str,
    suites: dict[str, SuiteStats],
    errors: dict[str, dict[str, int]],
    notes: list[str],
) -> str:
    lines = [
        f"# DRIFT Post Audit ({tag})",
        f"Generated: {generated_at}",
        "",
        "## Attack Suite Summary",
    ]
    for name, s in suites.items():
        lines.append(
            f"- {name}: done={s.done}, ASR={s.asr_success}/{s.files} ({s.asr_rate:.3f}), "
            f"USR={s.usr_success}/{s.files} ({s.usr_rate:.3f}), files={s.files}"
        )

    lines += ["", "## Error Counters"]
    for name, e in errors.items():
        lines.append(
            "- "
            + name
            + ": "
            + ", ".join(
                f"{k}={v}"
                for k, v in [
                    ("CALL_ERROR", e["CALL_ERROR"]),
                    ("TAG_MISS", e["Function_Call_Tags_Not_Found"]),
                    ("TAG_REFORMAT", e["Function_Call_Tags_Reformat_Request"]),
                    ("NODE_JSON_INVALID", e["Node_Checklist_Json_Format_Invalid"]),
                    ("TIMEOUT", e["APITimeoutError"]),
                    ("RETRY", e["Retrying_chat_completions"]),
                ]
            )
        )

    lines += ["", "## Notes"]
    if notes:
        lines.extend([f"- {n}" for n in notes])
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit DRIFT attack run outputs and logs.")
    ap.add_argument("--run-root", required=True, help="Path to external run root")
    ap.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    ap.add_argument("--suites", default="banking,slack,travel,workspace")
    ap.add_argument("--out-json", default=None)
    ap.add_argument("--out-md", default=None)
    args = ap.parse_args()

    run_root = Path(args.run_root).expanduser().resolve()
    tag = run_root.name
    suites = [s.strip() for s in str(args.suites).split(",") if s.strip()]
    generated_at = datetime.utcnow().replace(microsecond=0).isoformat()

    suite_stats: dict[str, SuiteStats] = {}
    errors: dict[str, dict[str, int]] = {}
    notes: list[str] = []

    for suite in suites:
        s = collect_suite_stats(run_root=run_root, model=args.model, suite=suite)
        suite_stats[suite] = s
        errors[suite] = collect_log_errors(run_root=run_root, suite=suite)
        if s.files > 0 and s.usr_success == 0:
            notes.append(f"{suite}:zero_utility_so_far")
        if s.files > 0 and s.asr_success == 0:
            notes.append(f"{suite}:zero_asr_so_far")
        if not s.done:
            notes.append(f"{suite}:not_done")

    result: dict[str, Any] = {
        "tag": tag,
        "generated_at": generated_at,
        "run_root": str(run_root),
        "model": args.model,
        "suites": {
            name: {
                "done": s.done,
                "log_exists": s.log_exists,
                "asr": {"success": s.asr_success, "total": s.files, "rate": s.asr_rate},
                "usr": {"success": s.usr_success, "total": s.files, "rate": s.usr_rate},
                "files": s.files,
            }
            for name, s in suite_stats.items()
        },
        "errors": errors,
        "notes": notes,
    }

    out_json = Path(args.out_json) if args.out_json else run_root / "drift_post_audit.json"
    out_md = Path(args.out_md) if args.out_md else run_root / "drift_post_audit.md"
    out_json.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    out_md.write_text(
        to_markdown(
            tag=tag,
            generated_at=generated_at,
            suites=suite_stats,
            errors=errors,
            notes=notes,
        ),
        encoding="utf-8",
    )

    print(str(out_json))
    print(str(out_md))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
