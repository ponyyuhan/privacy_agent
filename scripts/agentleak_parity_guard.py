from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


MODES = ["plain", "ipiguard", "drift", "faramesh", "secureclaw"]


def _find_pid(run_root: Path, run_root_input: str) -> int | None:
    p = subprocess.run(
        ["ps", "ax", "-o", "pid=", "-o", "command="],
        text=True,
        capture_output=True,
        check=False,
    )
    if p.returncode != 0:
        return None
    for line in (p.stdout or "").splitlines():
        txt = str(line or "")
        if "paper_parity_agentleak_eval.py" not in txt:
            continue
        if str(run_root) not in txt and str(run_root_input) not in txt:
            continue
        parts = txt.strip().split(None, 1)
        if not parts:
            continue
        try:
            return int(parts[0])
        except Exception:
            continue
    return None


def _process_alive(pid: int | None) -> bool:
    if pid is None:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except Exception:
        return False


def _descendants(pid: int) -> list[int]:
    out: set[int] = set()
    stack = [int(pid)]
    while stack:
        cur = stack.pop()
        p = subprocess.run(
            ["pgrep", "-P", str(cur)],
            text=True,
            capture_output=True,
            check=False,
        )
        if p.returncode not in {0, 1}:
            continue
        for line in (p.stdout or "").splitlines():
            s = str(line or "").strip()
            if not s:
                continue
            try:
                child = int(s)
            except Exception:
                continue
            if child not in out:
                out.add(child)
                stack.append(child)
    return sorted(out)


def _terminate_tree(pid: int) -> None:
    desc = _descendants(pid)
    for target in [pid] + desc:
        try:
            os.kill(target, signal.SIGTERM)
        except Exception:
            pass
    deadline = time.time() + 10.0
    while time.time() < deadline:
        alive = [target for target in [pid] + desc if _process_alive(target)]
        if not alive:
            return
        time.sleep(0.5)
    for target in [pid] + desc:
        try:
            os.kill(target, signal.SIGKILL)
        except Exception:
            pass


def _load_latest_v2(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    latest: dict[str, dict[str, Any]] = {}
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = ln.strip()
        if not s:
            continue
        try:
            d = json.loads(s)
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        sid = str(d.get("scenario_id") or "").strip()
        if not sid:
            continue
        latest[sid] = d
    out: list[dict[str, Any]] = []
    for d in latest.values():
        try:
            if int(d.get("row_schema_version") or 0) >= 2:
                out.append(d)
        except Exception:
            continue
    return out


def _rate(rows: list[dict[str, Any]], field: str) -> float | None:
    if not rows:
        return None
    return float(sum(1 for r in rows if bool(r.get(field))) / len(rows))


def _avg(rows: list[dict[str, Any]], field: str) -> float | None:
    if not rows:
        return None
    return float(sum(float(r.get(field) or 0.0) for r in rows) / len(rows))


def _mode_metrics(run_root: Path) -> dict[str, dict[str, Any]]:
    base = run_root / "paper_parity_agentleak_eval"
    out: dict[str, dict[str, Any]] = {}
    for mode in MODES:
        rows = _load_latest_v2(base / f"rows_{mode}.jsonl")
        ben = [r for r in rows if str(r.get("kind") or "") == "benign"]
        atk = [r for r in rows if str(r.get("kind") or "") == "attack"]
        out[mode] = {
            "v2_n": len(rows),
            "v2_benign": len(ben),
            "v2_attack": len(atk),
            "utility_success_rate": _rate(rows, "utility_success"),
            "utility_score_avg": _avg(rows, "utility_score"),
            "scenario_or_leak_rate": _rate(rows, "scenario_or_leaked"),
            "benign_utility_success_rate": _rate(ben, "utility_success"),
            "benign_utility_score_avg": _avg(ben, "utility_score"),
            "benign_scenario_or_leak_rate": _rate(ben, "scenario_or_leaked"),
            "attack_utility_success_rate": _rate(atk, "utility_success"),
            "attack_utility_score_avg": _avg(atk, "utility_score"),
            "attack_scenario_or_leak_rate": _rate(atk, "scenario_or_leaked"),
        }
    return out


def _fmt(x: Any) -> str:
    if x is None:
        return "NA"
    try:
        return f"{100.0 * float(x):.2f}%"
    except Exception:
        return str(x)


def _evaluate_guard(metrics: dict[str, dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    sc = metrics["secureclaw"]
    others = [metrics[m] for m in MODES if m != "secureclaw"]
    reasons: list[dict[str, Any]] = []

    if all(int(m["v2_benign"] or 0) >= int(args.min_benign) for m in metrics.values()):
        best_benign_util = max(float(m["benign_utility_success_rate"] or 0.0) for m in others)
        best_benign_score = max(float(m["benign_utility_score_avg"] or 0.0) for m in others)
        sc_benign_util = float(sc["benign_utility_success_rate"] or 0.0)
        sc_benign_score = float(sc["benign_utility_score_avg"] or 0.0)
        if sc_benign_util < best_benign_util - float(args.utility_gap):
            reasons.append(
                {
                    "type": "benign_utility_success",
                    "secureclaw": sc_benign_util,
                    "best_other": best_benign_util,
                    "gap": best_benign_util - sc_benign_util,
                }
            )
        if sc_benign_score < best_benign_score - float(args.utility_score_gap):
            reasons.append(
                {
                    "type": "benign_utility_score",
                    "secureclaw": sc_benign_score,
                    "best_other": best_benign_score,
                    "gap": best_benign_score - sc_benign_score,
                }
            )

    if all(int(m["v2_attack"] or 0) >= int(args.min_attack) for m in metrics.values()):
        best_attack_util = max(float(m["attack_utility_success_rate"] or 0.0) for m in others)
        best_attack_score = max(float(m["attack_utility_score_avg"] or 0.0) for m in others)
        best_attack_asr = min(float(m["attack_scenario_or_leak_rate"] or 1.0) for m in others)
        sc_attack_util = float(sc["attack_utility_success_rate"] or 0.0)
        sc_attack_score = float(sc["attack_utility_score_avg"] or 0.0)
        sc_attack_asr = float(sc["attack_scenario_or_leak_rate"] or 0.0)
        if sc_attack_util < best_attack_util - float(args.utility_gap):
            reasons.append(
                {
                    "type": "attack_utility_success",
                    "secureclaw": sc_attack_util,
                    "best_other": best_attack_util,
                    "gap": best_attack_util - sc_attack_util,
                }
            )
        if sc_attack_score < best_attack_score - float(args.utility_score_gap):
            reasons.append(
                {
                    "type": "attack_utility_score",
                    "secureclaw": sc_attack_score,
                    "best_other": best_attack_score,
                    "gap": best_attack_score - sc_attack_score,
                }
            )
        if sc_attack_asr > best_attack_asr + float(args.asr_gap):
            reasons.append(
                {
                    "type": "attack_asr",
                    "secureclaw": sc_attack_asr,
                    "best_other": best_attack_asr,
                    "gap": sc_attack_asr - best_attack_asr,
                }
            )

    return {
        "triggered": bool(reasons),
        "reasons": reasons,
        "metrics": metrics,
    }


def _write_status(run_root: Path, pid: int | None, alive: bool, evald: dict[str, Any], args: argparse.Namespace) -> None:
    status_path = run_root / "guard_status.md"
    lines = [
        "# AgentLeak Parity Guard Status",
        "",
        f"- updated_at: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"- run_root: `{run_root}`",
        f"- alive: {'true' if alive else 'false'}",
        f"- pid: {pid if pid is not None else 'none'}",
        f"- triggered: {'true' if bool(evald.get('triggered')) else 'false'}",
        f"- min_benign: {int(args.min_benign)}",
        f"- min_attack: {int(args.min_attack)}",
        f"- utility_gap: {float(args.utility_gap):.3f}",
        f"- utility_score_gap: {float(args.utility_score_gap):.3f}",
        f"- asr_gap: {float(args.asr_gap):.3f}",
        "",
        "## Metrics",
        "",
    ]
    for mode in MODES:
        m = evald["metrics"][mode]
        lines.extend(
            [
                f"- `{mode}`: "
                f"v2={m['v2_n']}, "
                f"benign_utility={_fmt(m['benign_utility_success_rate'])}, "
                f"benign_score={_fmt(m['benign_utility_score_avg'])}, "
                f"benign_leak={_fmt(m['benign_scenario_or_leak_rate'])}, "
                f"attack_utility={_fmt(m['attack_utility_success_rate'])}, "
                f"attack_score={_fmt(m['attack_utility_score_avg'])}, "
                f"attack_asr={_fmt(m['attack_scenario_or_leak_rate'])}",
            ]
        )
    lines.extend(["", "## Reasons", ""])
    reasons = evald.get("reasons") or []
    if reasons:
        for r in reasons:
            lines.append(
                f"- `{r['type']}`: SecureClaw={_fmt(r.get('secureclaw'))}, "
                f"best_other={_fmt(r.get('best_other'))}, gap={_fmt(r.get('gap'))}"
            )
    else:
        lines.append("- none")
    status_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (run_root / "guard_status.json").write_text(json.dumps(evald, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Guard AgentLeak parity run; stop if SecureClaw clearly underperforms.")
    ap.add_argument("--run-root", required=True)
    ap.add_argument("--poll-seconds", type=int, default=300)
    ap.add_argument("--min-benign", type=int, default=30)
    ap.add_argument("--min-attack", type=int, default=20)
    ap.add_argument("--utility-gap", type=float, default=0.15)
    ap.add_argument("--utility-score-gap", type=float, default=0.12)
    ap.add_argument("--asr-gap", type=float, default=0.05)
    ap.add_argument("--loop", action="store_true")
    args = ap.parse_args()

    run_root_input = str(args.run_root)
    run_root = Path(run_root_input).expanduser().resolve()

    while True:
        pid = _find_pid(run_root, run_root_input)
        alive = _process_alive(pid)
        metrics = _mode_metrics(run_root)
        evald = _evaluate_guard(metrics, args)
        _write_status(run_root, pid, alive, evald, args)

        if evald["triggered"] and alive and pid is not None:
            _terminate_tree(pid)
            alert = {
                "status": "TRIGGERED",
                "triggered_at": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
                "pid": pid,
                **evald,
            }
            (run_root / "guard_alert.json").write_text(json.dumps(alert, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
            (run_root / "guard_alert.md").write_text(
                "# AgentLeak Parity Guard Alert\n\n"
                f"- triggered_at: {alert['triggered_at']}\n"
                f"- stopped_pid: {pid}\n"
                f"- reasons: {json.dumps(alert['reasons'], ensure_ascii=True)}\n",
                encoding="utf-8",
            )
            print(json.dumps(alert, ensure_ascii=True))
            return 10

        if not args.loop or not alive:
            return 0
        time.sleep(max(5, int(args.poll_seconds)))


if __name__ == "__main__":
    raise SystemExit(main())
