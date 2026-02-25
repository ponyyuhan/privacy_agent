#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir", required=True, help="Path to runs/<model-value> directory.")
    ap.add_argument("--benchmark-version", default="v1.2.2")
    args = ap.parse_args()

    model_dir = Path(args.model_dir).expanduser().resolve()
    if not model_dir.exists():
        raise SystemExit(f"missing model_dir: {model_dir}")

    # Import AgentDojo lazily so this script can run outside the repo as well.
    from agentdojo.task_suite.load_suites import get_suites

    suites = get_suites(str(args.benchmark_version))
    out: dict[str, Any] = {"benchmark_version": str(args.benchmark_version), "model_dir": str(model_dir), "suites": {}}

    for suite_name, suite in suites.items():
        suite_dir = model_dir / suite_name
        user_ids = sorted(suite.user_tasks.keys())
        inj_ids = sorted(suite.injection_tasks.keys())

        expected = len(user_ids) * len(inj_ids) + len(user_ids) + len(inj_ids)
        missing = 0
        present = 0
        utility_vals: list[bool] = []
        security_vals: list[bool] = []

        for iid in inj_ids:
            p = suite_dir / iid / "none" / "none.json"
            if p.exists():
                present += 1
                d = _load_json(p)
                if isinstance(d.get("utility"), bool):
                    utility_vals.append(bool(d["utility"]))
                if isinstance(d.get("security"), bool):
                    security_vals.append(bool(d["security"]))
            else:
                missing += 1

        for uid in user_ids:
            p_none = suite_dir / uid / "none" / "none.json"
            if p_none.exists():
                present += 1
                d = _load_json(p_none)
                if isinstance(d.get("utility"), bool):
                    utility_vals.append(bool(d["utility"]))
                if isinstance(d.get("security"), bool):
                    security_vals.append(bool(d["security"]))
            else:
                missing += 1

            for iid in inj_ids:
                p = suite_dir / uid / "important_instructions" / f"{iid}.json"
                if p.exists():
                    present += 1
                    d = _load_json(p)
                    if isinstance(d.get("utility"), bool):
                        utility_vals.append(bool(d["utility"]))
                    if isinstance(d.get("security"), bool):
                        security_vals.append(bool(d["security"]))
                else:
                    missing += 1

        utility_rate = (sum(utility_vals) / len(utility_vals)) if utility_vals else None
        security_rate = (sum(security_vals) / len(security_vals)) if security_vals else None

        out["suites"][suite_name] = {
            "expected": expected,
            "present": present,
            "missing": missing,
            "utility_rate": utility_rate,
            "security_rate": security_rate,
            "attack_success_rate_est": (1.0 - security_rate) if security_rate is not None else None,
        }

    print(json.dumps(out, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
