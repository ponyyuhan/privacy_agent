from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from json import JSONDecoder
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
IPIGUARD_SRC = REPO_ROOT / "third_party" / "ipiguard" / "agentdojo" / "src"
if str(IPIGUARD_SRC) not in sys.path:
    sys.path.insert(0, str(IPIGUARD_SRC))

from agentdojo.task_suite.load_suites import get_suite  # type: ignore


def compute_expected_rows(benchmark_version: str, suites: list[str]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for suite_name in suites:
        suite = get_suite(str(benchmark_version), suite_name)
        benign = int(len(suite.user_tasks))
        under_attack = 0
        if hasattr(suite, "get_injections_for_user_task"):
            for ut in suite.user_tasks.values():
                under_attack += int(len(suite.get_injections_for_user_task(ut)))
        else:
            injections = getattr(suite, "injection_tasks", {}) or {}
            under_attack = benign * int(len(injections))
        out[suite_name] = {"benign": benign, "under_attack": under_attack}
    return out


def iter_json_objects(path: Path):
    txt = path.read_text(encoding="utf-8", errors="replace")
    dec = JSONDecoder()
    i = 0
    n = len(txt)
    while i < n:
        while i < n and txt[i].isspace():
            i += 1
        if i >= n:
            break
        try:
            obj, j = dec.raw_decode(txt, i)
            i = j
            yield obj
        except json.JSONDecodeError:
            i += 1


def suite_status(results_path: Path, mode: str, expected: int) -> dict:
    out = {
        "path": str(results_path),
        "rows": 0,
        "expected_rows": int(expected),
        "summary": False,
        "asr": None,
        "utility": None,
        "complete": False,
    }
    if not results_path.exists():
        return out

    seen: set[tuple[int, int | None]] = set()
    for obj in iter_json_objects(results_path):
        if not isinstance(obj, dict):
            continue
        if "Suite" in obj and "ASR" in obj:
            out["summary"] = True
            out["asr"] = obj.get("ASR")
            out["utility"] = obj.get("Utility")
            continue
        if "user_task_id" not in obj:
            continue
        try:
            uid = int(obj.get("user_task_id"))
        except Exception:
            continue
        if mode == "under_attack":
            iid = obj.get("injection_task_id")
            try:
                iid = int(iid)
            except Exception:
                continue
            seen.add((uid, iid))
        else:
            seen.add((uid, None))
    out["rows"] = len(seen)
    out["complete"] = bool(out["summary"] and out["rows"] >= int(expected))
    return out


def render_md(doc: dict) -> str:
    lines = [
        "# SecureClaw AgentDojo Live Status",
        f"- updated: {doc['updated_at']}",
        f"- run_root: {doc['run_root']}",
        f"- current_suite: {doc.get('current_suite') or ''}",
        f"- pid: {doc.get('pid') or ''}",
        f"- alive: {doc.get('alive')}",
        "",
    ]
    for suite, rec in doc["suites"].items():
        lines.append(f"## {suite}")
        for mode in ("benign", "under_attack"):
            mr = rec[mode]
            lines.append(
                f"- {mode}: {mr['rows']}/{mr['expected_rows']}, summary={mr['summary']}, "
                f"utility={mr['utility']}, asr={mr['asr']}, complete={mr['complete']}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Write live status for SecureClaw AgentDojo run.")
    ap.add_argument("--run-root", required=True)
    ap.add_argument("--benchmark-version", default="v1.1.2")
    ap.add_argument("--current-suite", default="")
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--output-json", required=True)
    ap.add_argument("--output-md", required=True)
    args = ap.parse_args()

    run_root = Path(str(args.run_root)).expanduser().resolve()
    suites = ["banking", "slack", "travel", "workspace"]
    expected = compute_expected_rows(str(args.benchmark_version), suites)
    alive = bool(args.pid and os.path.exists(f"/proc/{args.pid}") if sys.platform.startswith("linux") else False)
    if not sys.platform.startswith("linux") and args.pid:
        try:
            os.kill(int(args.pid), 0)
            alive = True
        except Exception:
            alive = False

    doc = {
        "updated_at": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "run_root": str(run_root),
        "current_suite": str(args.current_suite or ""),
        "pid": int(args.pid or 0),
        "alive": alive,
        "suites": {},
    }
    for suite in suites:
        doc["suites"][suite] = {
            "benign": suite_status(run_root / "secureclaw" / "benign" / suite / "results.jsonl", "benign", expected[suite]["benign"]),
            "under_attack": suite_status(run_root / "secureclaw" / "under_attack" / suite / "results.jsonl", "under_attack", expected[suite]["under_attack"]),
        }

    out_json = Path(str(args.output_json)).expanduser().resolve()
    out_md = Path(str(args.output_md)).expanduser().resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    out_md.write_text(render_md(doc), encoding="utf-8")


if __name__ == "__main__":
    main()
