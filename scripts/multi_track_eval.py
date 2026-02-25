from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def _run(args: list[str], *, cwd: Path, env: dict[str, str] | None = None, timeout_s: int = 7200) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(cwd),
        env=env,
        text=True,
        capture_output=True,
        timeout=int(timeout_s),
        check=False,
    )


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def _system_slice(rep: dict[str, Any], key: str) -> dict[str, Any]:
    s = ((rep.get("systems") or {}).get(key) or {}) if isinstance(rep.get("systems"), dict) else {}
    out: dict[str, Any] = {"system": key}
    for k in ("attack_leak_rate", "attack_block_rate", "benign_allow_rate", "latency_p50_ms", "latency_p95_ms", "n_attack", "n_benign"):
        if k in s:
            out[k] = s.get(k)
    if "status" in s:
        out["status"] = s.get("status")
    if "source_path" in s:
        out["source_path"] = s.get("source_path")
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="artifact_out_compare_noprompt")
    ap.add_argument("--force-refresh-fair", type=int, default=0, help="Set 1 to rerun fair_full_compare.")
    ap.add_argument("--run-protocol-tests", type=int, default=1)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    out_dir = Path(str(args.out_dir)).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    fair_report = out_dir / "fair_full_report.json"
    if int(args.force_refresh_fair) == 1 or not fair_report.exists():
        env = os.environ.copy()
        env["OUT_DIR"] = str(out_dir)
        env.setdefault("FAIR_FULL_REUSE_SECURECLAW", "1")
        env.setdefault("FAIR_FULL_REUSE_NATIVE", "1")
        p = _run([sys.executable, str(repo_root / "scripts" / "fair_full_compare.py")], cwd=repo_root, env=env, timeout_s=24 * 3600)
        if p.returncode != 0:
            raise SystemExit(f"fair_full_compare_failed:\n{p.stderr[:2000]}")
    if not fair_report.exists():
        raise SystemExit(f"missing_fair_full_report: {fair_report}")

    rep = _load_json(fair_report)

    # Keep the original main comparison and extend with defense baselines.
    main_systems = ["mirage_full", "codex_native", "openclaw_native"]
    defense_systems = ["codex_drift", "codex_ipiguard", "codex_agentarmor"]

    privacy_track = {
        "name": "privacy_leakage_track",
        "benchmarks": ["AgentLeak", "MAGPIE", "TOP-Bench"],
        "local_primary_eval": str(fair_report),
        "systems": [_system_slice(rep, k) for k in (main_systems + defense_systems)],
    }

    injection_track = {
        "name": "injection_robustness_track",
        "benchmarks": ["AgentDojo", "ASB", "WASP", "VPI-Bench"],
        "local_proxy_eval": str(fair_report),
        "systems": [_system_slice(rep, k) for k in (main_systems + defense_systems)],
    }

    protocol_track: dict[str, Any] = {
        "name": "protocol_implementation_track",
        "focus": ["MCP attack surface", "A2A delegated authority surface"],
        "pytest": {},
        "multi_agent_federated_eval": {},
    }
    if int(args.run_protocol_tests) == 1:
        test_targets = [
            "tests/test_mcp_gateway.py",
            "tests/test_delegation_and_dual_principal.py",
            "tests/test_federated_auth.py",
            "tests/test_security_games.py",
        ]
        existing = [t for t in test_targets if (repo_root / t).exists()]
        if existing:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(repo_root)
            p = _run(["pytest", "-q", *existing], cwd=repo_root, env=env, timeout_s=7200)
            protocol_track["pytest"] = {
                "status": "OK" if p.returncode == 0 else "ERROR",
                "returncode": int(p.returncode),
                "targets": existing,
                "stdout_tail": (p.stdout or "")[-2000:],
                "stderr_tail": (p.stderr or "")[-2000:],
            }
        else:
            protocol_track["pytest"] = {"status": "SKIPPED", "reason": "no_protocol_tests_found"}

        env2 = os.environ.copy()
        env2["PYTHONPATH"] = str(repo_root)
        env2["OUT_DIR"] = str(out_dir)
        mf = _run([sys.executable, str(repo_root / "scripts" / "multi_agent_federated_eval.py")], cwd=repo_root, env=env2, timeout_s=7200)
        mf_path = out_dir / "multi_agent_federated_eval.json"
        protocol_track["multi_agent_federated_eval"] = {
            "status": "OK" if mf.returncode == 0 and mf_path.exists() else "ERROR",
            "returncode": int(mf.returncode),
            "output_path": str(mf_path),
            "stdout_tail": (mf.stdout or "")[-2000:],
            "stderr_tail": (mf.stderr or "")[-2000:],
        }
    else:
        protocol_track["pytest"] = {"status": "SKIPPED", "reason": "run_protocol_tests=0"}
        protocol_track["multi_agent_federated_eval"] = {"status": "SKIPPED", "reason": "run_protocol_tests=0"}

    out = {
        "status": "OK",
        "out_dir": str(out_dir),
        "fair_full_report_path": str(fair_report),
        "tracks": {
            "privacy_leakage": privacy_track,
            "injection_robustness": injection_track,
            "protocol_implementation": protocol_track,
        },
    }
    out_path = Path(str(args.out)).expanduser().resolve() if str(args.out).strip() else (out_dir / "multi_track_eval.json")
    _write_json(out_path, out)
    print(str(out_path))


if __name__ == "__main__":
    main()
