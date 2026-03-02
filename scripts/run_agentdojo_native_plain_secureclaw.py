from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
IPIGUARD_DIR = REPO_ROOT / "third_party" / "ipiguard"

SUITES = ("banking", "slack", "travel", "workspace")
EXPECTED = {
    "banking": {"benign": 16, "under_attack": 16 * 9},
    "slack": {"benign": 21, "under_attack": 21 * 5},
    "travel": {"benign": 20, "under_attack": 20 * 7},
    "workspace": {"benign": 40, "under_attack": 40 * 6},
}


@dataclass(frozen=True)
class ResumeInfo:
    has_summary: bool
    unique_rows: int
    next_uid: int
    next_iid: int


def _pick_port() -> int:
    s = socket.socket()
    s.bind(("", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def _wait_http_ok(url: str, tries: int = 160) -> None:
    import requests

    for _ in range(int(tries)):
        try:
            r = requests.get(url, timeout=0.5)
            if int(r.status_code) == 200:
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"health check failed: {url}")


def _iter_json_objects(path: Path):
    txt = path.read_text(encoding="utf-8", errors="replace")
    dec = json.JSONDecoder()
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


def _resume_info(mode: str, results_path: Path) -> ResumeInfo:
    if not results_path.exists():
        return ResumeInfo(False, 0, 0, 0)

    has_summary = False
    seen: set[tuple[int, int | None]] = set()
    max_uid = -1
    max_iid = -1
    for obj in _iter_json_objects(results_path):
        if not isinstance(obj, dict):
            continue
        if "Suite" in obj and "ASR" in obj:
            has_summary = True
        if mode == "under_attack":
            if "user_task_id" in obj and obj.get("injection_task_id") is not None:
                try:
                    uid = int(obj.get("user_task_id", -1))
                    iid = int(obj.get("injection_task_id", -1))
                except Exception:
                    continue
                seen.add((uid, iid))
                if uid > max_uid or (uid == max_uid and iid > max_iid):
                    max_uid, max_iid = uid, iid
        else:
            if "user_task_id" in obj and ("injection_task_id" not in obj or obj.get("injection_task_id") is None):
                try:
                    uid = int(obj.get("user_task_id", -1))
                except Exception:
                    continue
                seen.add((uid, None))
                if uid > max_uid:
                    max_uid = uid

    rows = len(seen)
    if rows <= 0:
        return ResumeInfo(has_summary, 0, 0, 0)
    if mode == "under_attack":
        return ResumeInfo(has_summary, rows, max_uid, max_iid + 1)
    return ResumeInfo(has_summary, rows, max_uid + 1, 0)


class SecureClawInfra:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.procs: list[subprocess.Popen[str]] = []
        self.env_patch: dict[str, str] = {}

    def __enter__(self):
        self.run_dir.mkdir(parents=True, exist_ok=True)
        p0 = _pick_port()
        p1 = _pick_port()
        ex = _pick_port()

        base_env = os.environ.copy()
        base_env["PYTHONPATH"] = str(REPO_ROOT)
        base_env["POLICY0_URL"] = f"http://127.0.0.1:{p0}"
        base_env["POLICY1_URL"] = f"http://127.0.0.1:{p1}"
        base_env["EXECUTOR_URL"] = f"http://127.0.0.1:{ex}"
        base_env["POLICY0_MAC_KEY"] = base_env.get("POLICY0_MAC_KEY", secrets.token_hex(32))
        base_env["POLICY1_MAC_KEY"] = base_env.get("POLICY1_MAC_KEY", secrets.token_hex(32))
        base_env["SIGNED_PIR"] = "1"
        base_env["MIRAGE_POLICY_BYPASS"] = "0"
        base_env["SINGLE_SERVER_POLICY"] = "0"
        base_env["MIRAGE_ENFORCE_FINAL_OUTPUT_GATE"] = "0"
        base_env["USE_POLICY_BUNDLE"] = base_env.get("USE_POLICY_BUNDLE", "1")
        base_env["DLP_MODE"] = base_env.get("DLP_MODE", "fourgram")
        base_env["MIRAGE_SESSION_ID"] = base_env.get("MIRAGE_SESSION_ID", "agentdojo-secureclaw")
        base_env["SECURECLAW_SHADOW_RECIPIENT"] = base_env.get("SECURECLAW_SHADOW_RECIPIENT", "alice@example.com")
        base_env["SECURECLAW_SHADOW_DOMAIN"] = base_env.get("SECURECLAW_SHADOW_DOMAIN", "example.com")

        subprocess.run(
            [sys.executable, "-m", "policy_server.build_dbs"],
            check=True,
            cwd=str(REPO_ROOT),
            env=base_env,
        )

        env0 = base_env.copy()
        env0["SERVER_ID"] = "0"
        env0["PORT"] = str(p0)
        env0["POLICY_MAC_KEY"] = env0["POLICY0_MAC_KEY"]
        p0_proc = subprocess.Popen([sys.executable, "-m", "policy_server.server"], cwd=str(REPO_ROOT), env=env0, text=True)
        self.procs.append(p0_proc)

        env1 = base_env.copy()
        env1["SERVER_ID"] = "1"
        env1["PORT"] = str(p1)
        env1["POLICY_MAC_KEY"] = env1["POLICY1_MAC_KEY"]
        p1_proc = subprocess.Popen([sys.executable, "-m", "policy_server.server"], cwd=str(REPO_ROOT), env=env1, text=True)
        self.procs.append(p1_proc)

        envx = base_env.copy()
        envx["EXECUTOR_PORT"] = str(ex)
        ex_proc = subprocess.Popen([sys.executable, "-m", "executor_server.server"], cwd=str(REPO_ROOT), env=envx, text=True)
        self.procs.append(ex_proc)

        _wait_http_ok(f"http://127.0.0.1:{p0}/health")
        _wait_http_ok(f"http://127.0.0.1:{p1}/health")
        _wait_http_ok(f"http://127.0.0.1:{ex}/health")

        self.env_patch = {
            "POLICY0_URL": f"http://127.0.0.1:{p0}",
            "POLICY1_URL": f"http://127.0.0.1:{p1}",
            "EXECUTOR_URL": f"http://127.0.0.1:{ex}",
            "POLICY0_MAC_KEY": str(base_env["POLICY0_MAC_KEY"]),
            "POLICY1_MAC_KEY": str(base_env["POLICY1_MAC_KEY"]),
            "SIGNED_PIR": "1",
            "MIRAGE_POLICY_BYPASS": "0",
            "SINGLE_SERVER_POLICY": "0",
            "MIRAGE_ENFORCE_FINAL_OUTPUT_GATE": "0",
            "USE_POLICY_BUNDLE": str(base_env["USE_POLICY_BUNDLE"]),
            "DLP_MODE": str(base_env["DLP_MODE"]),
            "MIRAGE_SESSION_ID": str(base_env["MIRAGE_SESSION_ID"]),
            "SECURECLAW_SHADOW_RECIPIENT": str(base_env["SECURECLAW_SHADOW_RECIPIENT"]),
            "SECURECLAW_SHADOW_DOMAIN": str(base_env["SECURECLAW_SHADOW_DOMAIN"]),
        }
        return self

    def __exit__(self, exc_type, exc, tb):
        for p in self.procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in self.procs:
            try:
                p.wait(timeout=2)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass


def _run_one(
    *,
    mode: str,
    suite: str,
    defense: str,
    model: str,
    benchmark_version: str,
    out_dir: Path,
    logs_dir: Path,
    env_extra: dict[str, str],
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "results.jsonl"

    exp = int(EXPECTED[suite][mode])
    ri = _resume_info(mode, results_path)
    if ri.has_summary and ri.unique_rows >= exp and exp > 0:
        return {"status": "SKIP_COMPLETE", "rows": ri.unique_rows, "expected_rows": exp}

    log_path = logs_dir / f"{defense}_{mode}_{suite}.log"
    cmd = [
        sys.executable,
        "run/eval.py",
        "--benchmark_version",
        str(benchmark_version),
        "--suite_name",
        str(suite),
        "--agent_model",
        str(model),
        "--attack_name",
        "important_instructions",
        "--defense_name",
        str(defense),
        "--output_dir",
        str(out_dir),
        "--mode",
        str(mode),
        "--uid",
        str(ri.next_uid),
        "--iid",
        str(ri.next_iid),
    ]
    env = os.environ.copy()
    env.update(env_extra)
    env["PYTHONPATH"] = f"{IPIGUARD_DIR}:{IPIGUARD_DIR / 'agentdojo' / 'src'}:{env.get('PYTHONPATH','')}"

    with log_path.open("a", encoding="utf-8") as lf:
        lf.write(
            f"\n[launch] defense={defense} mode={mode} suite={suite} resume_uid={ri.next_uid} resume_iid={ri.next_iid} rows={ri.unique_rows}/{exp}\n"
        )
        lf.flush()
        p = subprocess.run(
            cmd,
            cwd=str(IPIGUARD_DIR),
            env=env,
            stdout=lf,
            stderr=lf,
            text=True,
            check=False,
        )

    ri2 = _resume_info(mode, results_path)
    return {
        "status": "OK" if int(p.returncode) == 0 else "ERROR",
        "rc": int(p.returncode),
        "rows": int(ri2.unique_rows),
        "expected_rows": int(exp),
        "has_summary": bool(ri2.has_summary),
        "log": str(log_path),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Run AgentDojo native plain/secureclaw baselines with resume.")
    ap.add_argument("--out-root", required=True)
    ap.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    ap.add_argument("--benchmark-version", default="v1.1.2")
    ap.add_argument("--suites", default="banking,slack,travel,workspace")
    ap.add_argument("--modes", default="benign,under_attack")
    ap.add_argument("--run-plain", type=int, default=1)
    ap.add_argument("--run-secureclaw", type=int, default=1)
    args = ap.parse_args()

    out_root = Path(str(args.out_root)).expanduser().resolve()
    logs_dir = out_root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    suites = [s.strip() for s in str(args.suites).split(",") if s.strip()]
    modes = [m.strip() for m in str(args.modes).split(",") if m.strip()]

    report: dict[str, Any] = {
        "status": "RUNNING",
        "benchmark": "AgentDojo-v1.1.2-native",
        "model": str(args.model),
        "benchmark_version": str(args.benchmark_version),
        "out_root": str(out_root),
        "plain": {},
        "secureclaw": {},
    }

    plain_root = out_root / "plain"
    secure_root = out_root / "secureclaw"

    env_base = {
        "OPENAI_API_KEY": str(os.getenv("OPENAI_API_KEY", "")),
        "OPENAI_BASE_URL": str(os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")),
        "PYTHONUNBUFFERED": "1",
    }

    if int(args.run_plain):
        for mode in modes:
            for suite in suites:
                key = f"{mode}/{suite}"
                rec = _run_one(
                    mode=mode,
                    suite=suite,
                    defense="None",
                    model=str(args.model),
                    benchmark_version=str(args.benchmark_version),
                    out_dir=plain_root / mode / suite,
                    logs_dir=logs_dir,
                    env_extra=env_base,
                )
                report["plain"][key] = rec
                (out_root / "agentdojo_native_plain_secureclaw_report.json").write_text(
                    json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
                )

    if int(args.run_secureclaw):
        with SecureClawInfra(run_dir=secure_root / "infra") as infra:
            env_sc = dict(env_base)
            env_sc.update(infra.env_patch)
            for mode in modes:
                for suite in suites:
                    key = f"{mode}/{suite}"
                    rec = _run_one(
                        mode=mode,
                        suite=suite,
                        defense="secureclaw",
                        model=str(args.model),
                        benchmark_version=str(args.benchmark_version),
                        out_dir=secure_root / mode / suite,
                        logs_dir=logs_dir,
                        env_extra=env_sc,
                    )
                    report["secureclaw"][key] = rec
                    (out_root / "agentdojo_native_plain_secureclaw_report.json").write_text(
                        json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
                    )

    report["status"] = "OK"
    out_path = out_root / "agentdojo_native_plain_secureclaw_report.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()
