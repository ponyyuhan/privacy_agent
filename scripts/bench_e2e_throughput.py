from __future__ import annotations

import os
import secrets
import socket
import statistics
import subprocess
import sys
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

from gateway.fss_pir import PirClient
from gateway.guardrails import ObliviousGuardrails
from gateway.handles import HandleStore
from gateway.executors.msgexec import MsgExec


def pick_port() -> int:
    s = socket.socket()
    s.bind(("", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def wait_http_ok(url: str, tries: int = 80) -> None:
    for _ in range(tries):
        try:
            r = requests.get(url, timeout=0.5)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"health check failed: {url}")


def _percentile(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    xs2 = sorted(xs)
    k = int(round((p / 100.0) * (len(xs2) - 1)))
    k = max(0, min(len(xs2) - 1, k))
    return float(xs2[k])


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    out_dir = Path(os.getenv("OUT_DIR", str(repo_root / "artifact_out")))
    out_dir.mkdir(parents=True, exist_ok=True)

    iters = int(os.getenv("BENCH_ITERS", "50"))
    conc = int(os.getenv("BENCH_CONCURRENCY", "8"))
    if iters < 10:
        iters = 10
    if conc < 1:
        conc = 1
    if conc > 64:
        conc = 64

    # Ports / URLs
    p0_port = int(os.getenv("P0_PORT", str(pick_port())))
    p1_port = int(os.getenv("P1_PORT", str(pick_port())))
    ex_port = int(os.getenv("EX_PORT", str(pick_port())))
    policy0_url = os.getenv("POLICY0_URL", f"http://127.0.0.1:{p0_port}")
    policy1_url = os.getenv("POLICY1_URL", f"http://127.0.0.1:{p1_port}")
    executor_url = os.getenv("EXECUTOR_URL", f"http://127.0.0.1:{ex_port}")

    dlp_mode = os.getenv("DLP_MODE", "fourgram").strip().lower()
    use_bundle = bool(int(os.getenv("USE_POLICY_BUNDLE", "0")))
    shape_all = bool(int(os.getenv("SHAPE_ALL_INTENTS", "0")))

    # Fresh keys per run
    policy0_mac_key = os.getenv("POLICY0_MAC_KEY", secrets.token_hex(32))
    policy1_mac_key = os.getenv("POLICY1_MAC_KEY", secrets.token_hex(32))

    env_common = os.environ.copy()
    env_common["PYTHONPATH"] = str(repo_root)
    env_common["POLICY0_URL"] = policy0_url
    env_common["POLICY1_URL"] = policy1_url
    env_common["EXECUTOR_URL"] = executor_url
    env_common["SIGNED_PIR"] = "1"
    env_common["DLP_MODE"] = dlp_mode
    env_common["USE_POLICY_BUNDLE"] = "1" if use_bundle else "0"
    env_common["SHAPE_ALL_INTENTS"] = "1" if shape_all else "0"
    env_common["POLICY0_MAC_KEY"] = policy0_mac_key
    env_common["POLICY1_MAC_KEY"] = policy1_mac_key

    # Apply the same knobs to the current process so in-process gateway objects
    # use the exact same configuration as the spawned services.
    os.environ["POLICY0_URL"] = policy0_url
    os.environ["POLICY1_URL"] = policy1_url
    os.environ["EXECUTOR_URL"] = executor_url
    os.environ["SIGNED_PIR"] = "1"
    os.environ["DLP_MODE"] = dlp_mode
    os.environ["USE_POLICY_BUNDLE"] = "1" if use_bundle else "0"
    os.environ["SHAPE_ALL_INTENTS"] = "1" if shape_all else "0"

    # Build DBs (enable bundle build if requested)
    if use_bundle:
        env_common["POLICY_BUNDLE_ENABLE"] = "1"
    subprocess.run([sys.executable, "-m", "policy_server.build_dbs"], check=True, env=env_common)

    procs: list[subprocess.Popen[str]] = []
    try:
        backend = (os.getenv("POLICY_BACKEND") or "python").strip().lower()
        rust_bin = repo_root / "policy_server_rust" / "target" / "release" / "mirage_policy_server"
        if backend == "rust" and not rust_bin.exists():
            subprocess.run(["cargo", "build", "--release"], check=True, cwd=str(repo_root / "policy_server_rust"))

        # Start policy servers
        env0 = env_common.copy()
        env0["SERVER_ID"] = "0"
        env0["PORT"] = str(p0_port)
        env0["POLICY_MAC_KEY"] = policy0_mac_key
        if backend == "rust":
            env0["DATA_DIR"] = str(repo_root / "policy_server" / "data")
            p0 = subprocess.Popen([str(rust_bin)], env=env0, text=True)
        else:
            p0 = subprocess.Popen([sys.executable, "-m", "policy_server.server"], env=env0, text=True)
        procs.append(p0)

        env1 = env_common.copy()
        env1["SERVER_ID"] = "1"
        env1["PORT"] = str(p1_port)
        env1["POLICY_MAC_KEY"] = policy1_mac_key
        if backend == "rust":
            env1["DATA_DIR"] = str(repo_root / "policy_server" / "data")
            p1 = subprocess.Popen([str(rust_bin)], env=env1, text=True)
        else:
            p1 = subprocess.Popen([sys.executable, "-m", "policy_server.server"], env=env1, text=True)
        procs.append(p1)

        # Start executor
        envx = env_common.copy()
        envx["EXECUTOR_PORT"] = str(ex_port)
        ex = subprocess.Popen([sys.executable, "-m", "executor_server.server"], env=envx, text=True)
        procs.append(ex)

        wait_http_ok(f"{policy0_url}/health")
        wait_http_ok(f"{policy1_url}/health")
        wait_http_ok(f"{executor_url}/health")

        # Gateway objects (in-process). These still do network calls to policy servers + executor.
        handles = HandleStore()
        pir = PirClient(policy0_url=policy0_url, policy1_url=policy1_url, domain_size=int(os.getenv("FSS_DOMAIN_SIZE", "4096")))
        guardrails = ObliviousGuardrails(pir=pir, handles=handles, domain_size=pir.domain_size, max_tokens=int(os.getenv("MAX_TOKENS_PER_MESSAGE", "32")))
        msg = MsgExec(handles, guardrails)

        recipient = "alice@example.com"
        text = "Hello Alice, here is the weekly update. Nothing sensitive."

        def one(i: int) -> float:
            t0 = time.perf_counter()
            obs = msg.send_message(
                {
                    "channel": "email",
                    "recipient": recipient,
                    "text": text,
                    "artifacts": [],
                },
                session="bench",
                caller="bench",
            )
            if obs.get("status") != "OK":
                raise RuntimeError(f"unexpected deny: {obs}")
            return time.perf_counter() - t0

        # Warmup
        for _ in range(min(5, iters)):
            _ = one(-1)

        lat_s: list[float] = []
        t_start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=conc) as tp:
            futs = [tp.submit(one, i) for i in range(iters)]
            for f in as_completed(futs):
                lat_s.append(float(f.result()))
        t_end = time.perf_counter()

        total = t_end - t_start
        avg_ms = statistics.mean(lat_s) * 1000.0
        p50_ms = _percentile(lat_s, 50) * 1000.0
        p95_ms = _percentile(lat_s, 95) * 1000.0
        thr = (iters / total) if total > 0 else 0.0

        row = {
            "iters": iters,
            "concurrency": conc,
            "dlp_mode": dlp_mode,
            "policy_backend": backend,
            "use_bundle": int(use_bundle),
            "shape_all_intents": int(shape_all),
            "avg_ms": round(avg_ms, 3),
            "p50_ms": round(p50_ms, 3),
            "p95_ms": round(p95_ms, 3),
            "throughput_ops_s": round(thr, 3),
        }

        out_path = out_dir / "bench_e2e.json"
        out_path.write_text(json.dumps(row, indent=2, sort_keys=True) + "\n")
        print(str(out_path))
    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=2)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass


if __name__ == "__main__":
    main()
