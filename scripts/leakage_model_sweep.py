from __future__ import annotations

import json
import math
import os
import random
import secrets
import shutil
import socket
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Allow running as `python scripts/...` without manually setting PYTHONPATH.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from gateway.egress_policy import EgressPolicyEngine
from gateway.fss_pir import MixedPirClient, PirClient, PirMixConfig
from gateway.handles import HandleStore
from gateway.tx_store import TxStore
from gateway.http_session import session_for


def pick_port() -> int:
    s = socket.socket()
    s.bind(("", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def wait_http_ok(url: str, tries: int = 120) -> None:
    for _ in range(int(tries)):
        try:
            r = session_for(url).get(url, timeout=0.5)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"health check failed: {url}")


def mutual_info_bits(labels: list[str], feats: list[tuple]) -> float:
    if not labels or not feats or len(labels) != len(feats):
        return 0.0
    n = len(labels)
    joint = Counter(zip(labels, feats))
    lc = Counter(labels)
    fc = Counter(feats)
    mi = 0.0
    for (lab, ft), c in joint.items():
        p = c / n
        pl = lc[lab] / n
        pf = fc[ft] / n
        if p <= 0.0 or pl <= 0.0 or pf <= 0.0:
            continue
        mi += p * math.log2(p / (pl * pf))
    return float(mi)


def map_accuracy(labels: list[str], feats: list[tuple], *, seed: int = 7, train_frac: float = 0.7) -> float:
    if not labels or not feats or len(labels) != len(feats):
        return 0.0
    n = len(labels)
    idxs = list(range(n))
    rng = random.Random(int(seed))
    rng.shuffle(idxs)
    split = int(max(1, min(n - 1, int(round(train_frac * n)))))
    train = idxs[:split]
    test = idxs[split:]

    feat_counts: dict[tuple, dict[str, int]] = {}
    lab_counts: dict[str, int] = {}
    for i in train:
        ft = feats[i]
        lab = labels[i]
        feat_counts.setdefault(ft, {})
        feat_counts[ft][lab] = int(feat_counts[ft].get(lab, 0)) + 1
        lab_counts[lab] = int(lab_counts.get(lab, 0)) + 1
    maj = sorted(lab_counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] if lab_counts else labels[0]

    feat_to_best: dict[tuple, str] = {}
    for ft, cnt in feat_counts.items():
        feat_to_best[ft] = sorted(cnt.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]

    ok = 0
    for i in test:
        pred = feat_to_best.get(feats[i], maj)
        if pred == labels[i]:
            ok += 1
    return float(ok) / float(len(test) or 1)


def _parse_transcript(path: Path, *, kind_prefix: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            ev = json.loads(ln)
        except Exception:
            continue
        if not isinstance(ev, dict):
            continue
        if int(ev.get("server_id", -1)) != 0:
            continue
        ep = str(ev.get("endpoint") or "")
        if not ep.startswith(kind_prefix):
            continue
        out.append(ev)
    return out


def _pir_feature(ev: dict[str, Any]) -> tuple:
    return (
        str(ev.get("endpoint") or ""),
        str(ev.get("db") or ""),
        int(ev.get("n_keys") or 0),
        int(ev.get("n_subreq") or 0),
        int(ev.get("keys_per_subreq") or 0),
        int(ev.get("domain_size") or 0),
        int(bool(ev.get("signed"))),
    )


def _mpc_feature(ev: dict[str, Any]) -> tuple:
    return (
        str(ev.get("endpoint") or ""),
        str(ev.get("program_id") or ""),
        int(ev.get("n_wires") or 0),
        int(ev.get("n_gates") or 0),
        int(ev.get("and_round") or -1),
        int(ev.get("n_items") or 0),
        int(bool(ev.get("multi"))),
    )


@dataclass(frozen=True)
class SweepCfg:
    name: str
    env: dict[str, str]


def _make_pir(*, policy0_url: str, policy1_url: str, domain_size: int) -> PirClient | MixedPirClient:
    base = PirClient(
        policy0_url=policy0_url,
        policy1_url=policy1_url,
        domain_size=int(domain_size),
        policy0_uds_path=(os.getenv("POLICY0_UDS_PATH") or "").strip() or None,
        policy1_uds_path=(os.getenv("POLICY1_UDS_PATH") or "").strip() or None,
    )
    if not bool(int(os.getenv("PIR_MIX_ENABLED", "0"))):
        return base
    try:
        meta = session_for(policy0_url).get(f"{policy0_url.rstrip('/')}/meta", timeout=1.5).json()
        b = (meta.get("bundle") or {}) if isinstance(meta, dict) else {}
        if not isinstance(b, dict) or not bool(b.get("enabled")):
            return base
        bundle_db = str(b.get("db") or os.getenv("POLICY_BUNDLE_DB", "policy_bundle"))
        bundle_ds = int(b.get("bundle_domain_size") or 0)
        if bundle_ds <= 0:
            return base
        max_tokens = int(os.getenv("MAX_TOKENS_PER_MESSAGE", "32"))
        max_domains = int(os.getenv("MAX_SKILL_DOMAINS", "8"))
        if max_domains < 1:
            max_domains = 1
        if max_domains > 64:
            max_domains = 64
        fixed_n_keys = 2 + (2 * max_tokens) + max_domains
        mix = PirMixConfig(
            enabled=True,
            interval_ms=int(os.getenv("PIR_MIX_INTERVAL_MS", "20")),
            pad_to=int(os.getenv("PIR_MIX_PAD_TO", "1")),
            fixed_n_keys=int(fixed_n_keys),
            db_name=bundle_db,
            domain_size=bundle_ds,
            timeout_s=int(os.getenv("PIR_MIX_TIMEOUT_S", "10")),
            cover_traffic=bool(int(os.getenv("PIR_COVER_TRAFFIC", "0"))),
            lanes=int(os.getenv("PIR_MIX_LANES", "1")),
            max_inflight=int(os.getenv("PIR_MIX_MAX_INFLIGHT", "1")),
            schedule_mode=str(os.getenv("PIR_MIX_SCHEDULE", "eager")),
        )
        return MixedPirClient(base, mix=mix)
    except Exception:
        return base


class TempEnv:
    def __init__(self, overrides: dict[str, str]):
        self._overrides = dict(overrides)
        self._old: dict[str, str | None] = {}

    def __enter__(self):
        for k, v in self._overrides.items():
            self._old[k] = os.getenv(k)
            os.environ[k] = str(v)
        return self

    def __exit__(self, exc_type, exc, tb):  # noqa: ANN001
        for k, old in self._old.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


def _run_label_workload(*, label: str, n: int, eng: EgressPolicyEngine, session_id: str) -> None:
    caller = "leakage-sweep"
    for i in range(int(n)):
        if label == "send":
            txt = ("hello " * (1 + (i % 7))).strip()
            _ = eng.preview(
                intent_id="CheckMessagePolicy",
                inputs={"channel": "email", "recipient": "alice@example.com", "text": txt, "domain": "", "artifacts": []},
                constraints={},
                session=session_id,
                caller=caller,
            )
            continue
        if label == "fetch":
            _ = eng.preview(
                intent_id="CheckFetchPolicy",
                inputs={"resource_id": f"r{i}", "domain": "api.github.com", "recipient": "", "text": ""},
                constraints={},
                session=session_id,
                caller=caller,
            )
            continue
        if label == "webhook":
            body = "{\"k\":\"" + ("x" * (10 + (i % 13))) + "\"}"
            _ = eng.preview(
                intent_id="CheckWebhookPolicy",
                inputs={"domain": "example.com", "path": "/hook", "text": body, "recipient": "", "artifacts": []},
                constraints={},
                session=session_id,
                caller=caller,
            )
            continue
        raise ValueError(f"unknown label: {label}")


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    out_dir = Path(os.getenv("OUT_DIR", str(repo_root / "artifact_out_compare" / "leakage_sweep"))).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    seed = int(os.getenv("MIRAGE_SEED", "7"))
    n_per_label = int(os.getenv("LEAKAGE_SWEEP_N_PER_LABEL", "64"))
    if n_per_label < 16:
        n_per_label = 16
    if n_per_label > 512:
        n_per_label = 512

    # Policy servers
    p0 = int(os.getenv("P0_PORT", str(pick_port())))
    p1 = int(os.getenv("P1_PORT", str(pick_port())))
    policy0_url = os.getenv("POLICY0_URL", f"http://127.0.0.1:{p0}")
    policy1_url = os.getenv("POLICY1_URL", f"http://127.0.0.1:{p1}")

    # Build DBs (ensure bundle exists so the sweep can enable USE_POLICY_BUNDLE).
    env_common = os.environ.copy()
    env_common["PYTHONPATH"] = str(repo_root)
    env_common["POLICY0_URL"] = policy0_url
    env_common["POLICY1_URL"] = policy1_url
    env_common["SIGNED_PIR"] = "1"
    env_common["POLICY_BUNDLE_ENABLE"] = "1"
    subprocess.run([sys.executable, "-m", "policy_server.build_dbs"], check=True, env=env_common, cwd=str(repo_root))

    procs: list[subprocess.Popen[str]] = []
    try:
        # Start Rust policy servers (required for UDS + higher throughput).
        rust_bin = repo_root / "policy_server_rust" / "target" / "release" / "mirage_policy_server"
        if not rust_bin.exists():
            subprocess.run(["cargo", "build", "--release"], check=True, cwd=str(repo_root / "policy_server_rust"))

        use_uds = bool(int(os.getenv("MIRAGE_USE_UDS", "1"))) and (os.name == "posix")
        uds0 = ""
        uds1 = ""
        if use_uds:
            uds_base = Path(os.getenv("MIRAGE_UDS_DIR", "/tmp/mirage_uds")).expanduser()
            uds_dir = uds_base / f"leakage_{os.getpid()}_{seed}"
            uds_dir.mkdir(parents=True, exist_ok=True)
            uds0_path = uds_dir / f"p0_{p0}.sock"
            uds1_path = uds_dir / f"p1_{p1}.sock"
            for p in (uds0_path, uds1_path):
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass
                except Exception:
                    pass
            uds0 = str(uds0_path)
            uds1 = str(uds1_path)
        if uds0 and uds1:
            os.environ["POLICY0_UDS_PATH"] = uds0
            os.environ["POLICY1_UDS_PATH"] = uds1

        env0 = env_common.copy()
        env0["SERVER_ID"] = "0"
        env0["PORT"] = str(p0)
        env0["DATA_DIR"] = str(repo_root / "policy_server" / "data")
        env0["POLICY_MAC_KEY"] = env0.get("POLICY_MAC_KEY", secrets.token_hex(32))
        if uds0:
            env0["POLICY_UDS_PATH"] = uds0
        procs.append(subprocess.Popen([str(rust_bin)], env=env0, text=True, cwd=str(repo_root)))

        env1 = env_common.copy()
        env1["SERVER_ID"] = "1"
        env1["PORT"] = str(p1)
        env1["DATA_DIR"] = str(repo_root / "policy_server" / "data")
        env1["POLICY_MAC_KEY"] = env1.get("POLICY_MAC_KEY", secrets.token_hex(32))
        if uds1:
            env1["POLICY_UDS_PATH"] = uds1
        procs.append(subprocess.Popen([str(rust_bin)], env=env1, text=True, cwd=str(repo_root)))

        wait_http_ok(f"{policy0_url}/health")
        wait_http_ok(f"{policy1_url}/health")

        # Sweep configs. Keep the grid small but informative; users can extend via env overrides.
        sweep: list[SweepCfg] = [
            SweepCfg(
                name="unshaped",
                env={
                    # Unshaped baseline must disable unified mode so PIR/MPC structure
                    # (endpoint/DB choice, batch sizes) can differ across intents.
                    "UNIFIED_POLICY": "0",
                    "USE_POLICY_BUNDLE": "0",
                    "PAD_TOKEN_BATCH": "0",
                    "PIR_MIX_ENABLED": "0",
                    "PIR_COVER_TRAFFIC": "0",
                    "MPC_MIX_ENABLED": "0",
                },
            ),
            SweepCfg(
                name="shaped_pad1_cover0",
                env={
                    "UNIFIED_POLICY": "1",
                    "USE_POLICY_BUNDLE": "1",
                    "PAD_TOKEN_BATCH": "1",
                    "PIR_MIX_ENABLED": "1",
                    "PIR_MIX_PAD_TO": "1",
                    "PIR_COVER_TRAFFIC": "0",
                    "PIR_MIX_INTERVAL_MS": "20",
                    "PIR_MIX_SCHEDULE": "eager",
                    "MPC_MIX_ENABLED": "1",
                    "MPC_MIX_PAD_TO": "1",
                    "MPC_COVER_TRAFFIC": "0",
                    "MPC_MIX_INTERVAL_MS": "20",
                    "MPC_MIX_SCHEDULE": "eager",
                },
            ),
            SweepCfg(
                name="shaped_pad4_cover0",
                env={
                    "UNIFIED_POLICY": "1",
                    "USE_POLICY_BUNDLE": "1",
                    "PAD_TOKEN_BATCH": "1",
                    "PIR_MIX_ENABLED": "1",
                    "PIR_MIX_PAD_TO": "4",
                    "PIR_COVER_TRAFFIC": "0",
                    "PIR_MIX_INTERVAL_MS": "20",
                    "PIR_MIX_SCHEDULE": "eager",
                    "MPC_MIX_ENABLED": "1",
                    "MPC_MIX_PAD_TO": "4",
                    "MPC_COVER_TRAFFIC": "0",
                    "MPC_MIX_INTERVAL_MS": "20",
                    "MPC_MIX_SCHEDULE": "eager",
                },
            ),
            SweepCfg(
                name="shaped_pad4_cover1",
                env={
                    "UNIFIED_POLICY": "1",
                    "USE_POLICY_BUNDLE": "1",
                    "PAD_TOKEN_BATCH": "1",
                    "PIR_MIX_ENABLED": "1",
                    "PIR_MIX_PAD_TO": "4",
                    "PIR_COVER_TRAFFIC": "1",
                    "PIR_MIX_INTERVAL_MS": "20",
                    "PIR_MIX_SCHEDULE": "eager",
                    "MPC_MIX_ENABLED": "1",
                    "MPC_MIX_PAD_TO": "4",
                    "MPC_COVER_TRAFFIC": "1",
                    "MPC_MIX_INTERVAL_MS": "20",
                    "MPC_MIX_SCHEDULE": "eager",
                },
            ),
        ]

        results: dict[str, Any] = {"status": "OK", "seed": seed, "n_per_label": n_per_label, "configs": []}
        labels = ["send", "fetch", "webhook"]
        for cfg in sweep:
            pir_labels: list[str] = []
            pir_feats: list[tuple] = []
            mpc_labels: list[str] = []
            mpc_feats: list[tuple] = []
            per_label_counts: dict[str, Any] = {}
            for lab in labels:
                tpath = out_dir / f"transcript_{cfg.name}_{lab}.jsonl"
                try:
                    tpath.unlink()
                except Exception:
                    pass
                env_over = dict(cfg.env)
                env_over["MIRAGE_TRANSCRIPT_PATH"] = str(tpath)
                session_id = f"sweep-{cfg.name}-{lab}-{secrets.token_hex(3)}"
                with TempEnv(env_over):
                    pir = _make_pir(policy0_url=policy0_url, policy1_url=policy1_url, domain_size=int(os.getenv("FSS_DOMAIN_SIZE", "4096")))
                    hs = HandleStore()
                    txs = TxStore()
                    eng = EgressPolicyEngine(pir=pir, handles=hs, tx_store=txs, domain_size=int(os.getenv("FSS_DOMAIN_SIZE", "4096")), max_tokens=int(os.getenv("MAX_TOKENS_PER_MESSAGE", "32")))
                    _run_label_workload(label=lab, n=n_per_label, eng=eng, session_id=session_id)
                    # Stop background mixers so cover traffic does not bleed into the next label.
                    try:
                        if isinstance(pir, MixedPirClient):
                            pir.close()
                    except Exception:
                        pass
                    try:
                        if getattr(eng, "_unified", None) is not None and getattr(getattr(eng, "_unified"), "_mpc_mixed", None) is not None:
                            getattr(getattr(eng, "_unified"), "_mpc_mixed").close()  # type: ignore[call-arg]
                    except Exception:
                        pass

                pir_evs = _parse_transcript(tpath, kind_prefix="/pir/")
                mpc_evs = _parse_transcript(tpath, kind_prefix="/mpc/")
                per_label_counts[lab] = {"pir_events": len(pir_evs), "mpc_events": len(mpc_evs)}
                for ev in pir_evs:
                    pir_labels.append(lab)
                    pir_feats.append(_pir_feature(ev))
                for ev in mpc_evs:
                    mpc_labels.append(lab)
                    mpc_feats.append(_mpc_feature(ev))

            # Compute distinguishability.
            pir_mi = mutual_info_bits(pir_labels, pir_feats)
            mpc_mi = mutual_info_bits(mpc_labels, mpc_feats)
            pir_acc = map_accuracy(pir_labels, pir_feats, seed=seed)
            mpc_acc = map_accuracy(mpc_labels, mpc_feats, seed=seed)
            cfg_row = {
                "name": cfg.name,
                "env": cfg.env,
                "per_label_counts": per_label_counts,
                "pir": {
                    "n_obs": len(pir_labels),
                    "n_unique_features": len(set(pir_feats)),
                    "mi_bits": float(pir_mi),
                    "map_acc": float(pir_acc),
                    "chance_acc": 1.0 / float(len(labels)),
                },
                "mpc": {
                    "n_obs": len(mpc_labels),
                    "n_unique_features": len(set(mpc_feats)),
                    "mi_bits": float(mpc_mi),
                    "map_acc": float(mpc_acc),
                    "chance_acc": 1.0 / float(len(labels)),
                },
            }
            results["configs"].append(cfg_row)

        out_path = out_dir / "leakage_model_sweep.json"
        out_path.write_text(json.dumps(results, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
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
