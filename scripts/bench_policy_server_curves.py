from __future__ import annotations

import base64
import json
import os
import random
import secrets
import shutil
import socket
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests

from fss.dpf import gen_dpf_keys


def pick_port() -> int:
    s = socket.socket()
    s.bind(("", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def wait_http_ok(url: str, tries: int = 120) -> None:
    for _ in range(tries):
        try:
            r = requests.get(url, timeout=0.5)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"health check failed: {url}")


def pct(xs: list[float], q: float) -> float:
    if not xs:
        return 0.0
    ys = sorted(xs)
    k = int(round((q / 100.0) * (len(ys) - 1)))
    k = max(0, min(len(ys) - 1, k))
    return float(ys[k])


def round_up(x: int, to: int) -> int:
    if to <= 0:
        return int(x)
    return int(((x + to - 1) // to) * to)


def build_payload(*, db: str, batch: int, domain_bits: int, seed: int) -> dict[str, Any]:
    rng = random.Random(seed)
    ds = 1 << int(domain_bits)
    keys: list[str] = []
    for _ in range(int(batch)):
        idx = rng.randrange(ds)
        k0, _k1 = gen_dpf_keys(alpha=idx, beta=1, domain_bits=domain_bits)
        keys.append(base64.b64encode(k0).decode("ascii"))
    return {"db": str(db), "dpf_keys_b64": keys}


def run_cfg(*, url: str, payload: dict[str, Any], logical_batch: int, requests_n: int, conc: int) -> dict[str, Any]:
    endpoint = f"{url}/pir/query_batch"

    # warmup
    for _ in range(3):
        r = requests.post(endpoint, json=payload, timeout=15)
        r.raise_for_status()

    lat: list[float] = []

    def one() -> float:
        t0 = time.perf_counter()
        r = requests.post(endpoint, json=payload, timeout=20)
        r.raise_for_status()
        out = r.json().get("ans_shares") or []
        if len(out) != len(payload.get("dpf_keys_b64") or []):
            raise RuntimeError("unexpected answer size")
        return time.perf_counter() - t0

    t_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max(1, int(conc))) as tp:
        futs = [tp.submit(one) for _ in range(int(requests_n))]
        for f in as_completed(futs):
            lat.append(float(f.result()))
    t_end = time.perf_counter()

    wall = max(1e-9, t_end - t_start)
    eff_batch = int(len(payload.get("dpf_keys_b64") or []))
    logical_keys = int(logical_batch) * int(requests_n)
    effective_keys = int(eff_batch) * int(requests_n)

    return {
        "requests": int(requests_n),
        "concurrency": int(conc),
        "logical_batch": int(logical_batch),
        "effective_batch": int(eff_batch),
        "latency_avg_ms": statistics.mean(lat) * 1000.0 if lat else 0.0,
        "latency_p50_ms": pct(lat, 50.0) * 1000.0,
        "latency_p95_ms": pct(lat, 95.0) * 1000.0,
        "throughput_reqs_s": float(requests_n) / wall,
        "throughput_logical_keys_s": float(logical_keys) / wall,
        "throughput_effective_keys_s": float(effective_keys) / wall,
    }


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    out_dir = Path(os.getenv("OUT_DIR", str(repo_root / "artifact_out")))
    out_dir.mkdir(parents=True, exist_ok=True)
    perf_dir = out_dir / "policy_perf"
    perf_dir.mkdir(parents=True, exist_ok=True)

    domain_size = int(os.getenv("FSS_DOMAIN_SIZE", "4096"))
    if domain_size <= 0 or (domain_size & (domain_size - 1)) != 0:
        domain_size = 4096
    domain_bits = int(domain_size.bit_length() - 1)

    req_n = int(os.getenv("POLICY_CURVE_REQUESTS", "80"))
    conc = int(os.getenv("POLICY_CURVE_CONCURRENCY", "8"))
    if req_n < 10:
        req_n = 10
    if conc < 1:
        conc = 1
    if conc > 64:
        conc = 64

    base_batches = [int(x) for x in (os.getenv("POLICY_CURVE_BASE_BATCHES", "1,8,32,64,128").split(",")) if x.strip()]
    if not base_batches:
        base_batches = [1, 8, 32, 64, 128]

    pad_tos = [int(x) for x in (os.getenv("POLICY_CURVE_PAD_TO", "0,32,128").split(",")) if x.strip()]
    if not pad_tos:
        pad_tos = [0, 32, 128]

    seed = int(os.getenv("MIRAGE_SEED", "7"))

    env_common = os.environ.copy()
    env_common["PYTHONPATH"] = str(repo_root)
    subprocess.run([sys.executable, "-m", "policy_server.build_dbs"], check=True, env=env_common)

    backends: list[str] = ["python"]
    rust_bin = repo_root / "policy_server_rust" / "target" / "release" / "mirage_policy_server"
    if shutil.which("cargo"):
        if not rust_bin.exists():
            subprocess.run(["cargo", "build", "--release"], check=True, cwd=str(repo_root / "policy_server_rust"))
        backends.append("rust")

    rows: list[dict[str, Any]] = []

    for backend in backends:
        port = pick_port()
        url = f"http://127.0.0.1:{port}"
        mac_key = secrets.token_hex(32)

        env = env_common.copy()
        env["SERVER_ID"] = "0"
        env["PORT"] = str(port)
        env["POLICY_MAC_KEY"] = mac_key

        if backend == "rust":
            env["DATA_DIR"] = str(repo_root / "policy_server" / "data")
            proc = subprocess.Popen([str(rust_bin)], env=env, text=True)
        else:
            proc = subprocess.Popen([sys.executable, "-m", "policy_server.server"], env=env, text=True)

        try:
            wait_http_ok(f"{url}/health")
            for b in base_batches:
                b = max(1, int(b))
                for p in pad_tos:
                    eff = round_up(b, int(p))
                    payload = build_payload(db="allow_recipients", batch=eff, domain_bits=domain_bits, seed=(seed + b * 131 + p * 17))
                    m = run_cfg(url=url, payload=payload, logical_batch=b, requests_n=req_n, conc=conc)
                    row = {
                        "backend": backend,
                        "domain_size": int(domain_size),
                        "pad_to": int(p),
                        **m,
                    }
                    rows.append(row)
        finally:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    out = {
        "status": "OK",
        "seed": seed,
        "domain_size": int(domain_size),
        "requests": int(req_n),
        "concurrency": int(conc),
        "rows": rows,
    }

    json_path = perf_dir / "policy_server_curves.json"
    csv_path = perf_dir / "policy_server_curves.csv"
    json_path.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    with csv_path.open("w", encoding="utf-8") as f:
        f.write(
            "backend,domain_size,pad_to,requests,concurrency,logical_batch,effective_batch,latency_avg_ms,latency_p50_ms,latency_p95_ms,throughput_reqs_s,throughput_logical_keys_s,throughput_effective_keys_s\n"
        )
        for r in rows:
            f.write(
                f"{r['backend']},{int(r['domain_size'])},{int(r['pad_to'])},{int(r['requests'])},{int(r['concurrency'])},{int(r['logical_batch'])},{int(r['effective_batch'])},"
                f"{float(r['latency_avg_ms']):.6f},{float(r['latency_p50_ms']):.6f},{float(r['latency_p95_ms']):.6f},"
                f"{float(r['throughput_reqs_s']):.6f},{float(r['throughput_logical_keys_s']):.6f},{float(r['throughput_effective_keys_s']):.6f}\n"
            )

    print(str(json_path))


if __name__ == "__main__":
    main()
