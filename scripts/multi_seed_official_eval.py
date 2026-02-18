from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def _run(args: list[str], *, env: dict[str, str], cwd: Path, timeout_s: int = 7200) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, env=env, cwd=str(cwd), text=True, capture_output=True, timeout=int(timeout_s), check=False)


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def _extract(m: dict[str, Any]) -> dict[str, Any]:
    return {
        "n_total": int(m.get("n_total", 0)),
        "n_attack": int(m.get("n_attack", 0)),
        "n_benign": int(m.get("n_benign", 0)),
        "attack_leak_rate": float(m.get("attack_leak_rate", 0.0)),
        "attack_block_rate": float(m.get("attack_block_rate", 0.0)),
        "benign_allow_rate": float(m.get("benign_allow_rate", 0.0)),
        "latency_p50_ms": float(m.get("latency_p50_ms", 0.0)),
        "latency_p95_ms": float(m.get("latency_p95_ms", 0.0)),
        "ops_s": float(m.get("ops_s", 0.0)),
    }


def _mean_ci95(xs: list[float]) -> list[float]:
    # Simple t-based CI for across-seed means; used only as a robustness check.
    import math
    import statistics

    n = len(xs)
    if n <= 1:
        m = float(xs[0]) if xs else 0.0
        return [m, m, m]
    m = float(statistics.mean(xs))
    s = float(statistics.stdev(xs))
    se = s / math.sqrt(n)
    # Conservative 1.96 normal approximation (t_{n-1} close for n>=5).
    lo = m - 1.96 * se
    hi = m + 1.96 * se
    return [float(m), float(lo), float(hi)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="artifact_out_compare/multi_seed_official", help="Output root directory.")
    ap.add_argument("--seeds", default="7,11,13,17,19", help="Comma-separated list of seeds.")
    ap.add_argument("--policy-backend", default=os.getenv("POLICY_BACKEND", "rust"), choices=["rust", "python"])
    ap.add_argument("--timeout-s", type=int, default=7200)
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    out_root = Path(str(args.out)).expanduser().resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    seeds = [int(x.strip()) for x in str(args.seeds).split(",") if x.strip()]

    per_seed: dict[str, Any] = {}
    for seed in seeds:
        od = out_root / f"seed_{seed}"
        od.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(repo_root)
        env["OUT_DIR"] = str(od)
        env["AGENTLEAK_CASESET"] = "official"
        env["MIRAGE_SEED"] = str(seed)
        # Take all available official cases in each channel for the given seed.
        env["AGENTLEAK_ATTACKS_PER_CHANNEL"] = str(int(os.getenv("AGENTLEAK_ATTACKS_PER_CHANNEL", "100000")))
        env["AGENTLEAK_BENIGNS_PER_CHANNEL"] = str(int(os.getenv("AGENTLEAK_BENIGNS_PER_CHANNEL", "100000")))
        env["POLICY_BACKEND"] = str(args.policy_backend)
        env.setdefault("MIRAGE_USE_UDS", "1")
        env.setdefault("PIR_BINARY_TRANSPORT", "1")

        t0 = time.perf_counter()
        p = _run([sys.executable, str(repo_root / "scripts" / "agentleak_channel_eval.py")], env=env, cwd=repo_root, timeout_s=int(args.timeout_s))
        wall_s = time.perf_counter() - t0
        summ_path = od / "agentleak_eval" / "agentleak_channel_summary.json"
        if p.returncode != 0 or not summ_path.exists():
            per_seed[str(seed)] = {"status": "ERROR", "rc": int(p.returncode), "wall_s": float(wall_s), "stderr": (p.stderr or "")[:2000]}
            continue
        d = _load_json(summ_path)
        modes = d.get("modes") if isinstance(d.get("modes"), dict) else {}
        per_seed[str(seed)] = {"status": "OK", "wall_s": float(wall_s), "summary_path": str(summ_path), "modes": {k: _extract(v) for k, v in modes.items() if isinstance(v, dict)}}

    # Aggregate across seeds (robustness): mean +/- CI95 for key rates.
    agg: dict[str, Any] = {}
    for mode in ("mirage_full", "policy_only", "sandbox_only", "single_server_policy"):
        xs_leak: list[float] = []
        xs_allow: list[float] = []
        xs_ops: list[float] = []
        for seed in seeds:
            sd = per_seed.get(str(seed)) if isinstance(per_seed.get(str(seed)), dict) else None
            if not isinstance(sd, dict) or str(sd.get("status")) != "OK":
                continue
            md = (sd.get("modes") or {}).get(mode) if isinstance(sd.get("modes"), dict) else None
            if not isinstance(md, dict):
                continue
            xs_leak.append(float(md.get("attack_leak_rate", 0.0)))
            xs_allow.append(float(md.get("benign_allow_rate", 0.0)))
            xs_ops.append(float(md.get("ops_s", 0.0)))
        agg[mode] = {
            "attack_leak_rate_mean_ci95": _mean_ci95(xs_leak),
            "benign_allow_rate_mean_ci95": _mean_ci95(xs_allow),
            "ops_s_mean_ci95": _mean_ci95(xs_ops),
            "n_seeds_ok": int(len(xs_ops)),
        }

    out = {"status": "OK", "seeds": seeds, "per_seed": per_seed, "aggregate": agg}
    out_path = out_root / "multi_seed_official_summary.json"
    _write_json(out_path, out)
    print(str(out_path))


if __name__ == "__main__":
    main()

