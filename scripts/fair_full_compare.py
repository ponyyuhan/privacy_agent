from __future__ import annotations

import importlib.util
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any


def _pick_port() -> int:
    s = socket.socket()
    s.bind(("", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def _run(args: list[str], *, env: dict[str, str] | None = None, cwd: Path | None = None, timeout_s: int = 3600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        env=env,
        cwd=str(cwd) if cwd else None,
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


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=True) + "\n")


def _load_agentleak_module(repo_root: Path):
    p = repo_root / "scripts" / "agentleak_channel_eval.py"
    spec = importlib.util.spec_from_file_location("_agentleak_channel_eval", p)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed_to_load_agentleak_module")
    mod = importlib.util.module_from_spec(spec)
    # dataclasses/type-checking expects the module to be present in sys.modules.
    sys.modules[str(spec.name)] = mod
    spec.loader.exec_module(mod)  # type: ignore[misc]
    return mod


def _extract_system_metrics(ms: dict[str, Any]) -> dict[str, Any]:
    # Normalize the fields requested by the user.
    out: dict[str, Any] = {
        "n_total": int(ms.get("n_total", 0)),
        "n_attack": int(ms.get("n_attack", 0)),
        "n_benign": int(ms.get("n_benign", 0)),
        "attack_block_rate": float(ms.get("attack_block_rate", 0.0)),
        "attack_leak_rate": float(ms.get("attack_leak_rate", 0.0)),
        "benign_allow_rate": float(ms.get("benign_allow_rate", 0.0)),
        "latency_p50_ms": float(ms.get("latency_p50_ms", 0.0)),
        "latency_p95_ms": float(ms.get("latency_p95_ms", 0.0)),
        "ops_s": float(ms.get("ops_s", 0.0)),
    }
    per = ms.get("per_channel")
    if isinstance(per, dict):
        out["per_channel"] = per
    return out


def _openclaw_run_script_once(
    *,
    repo_root: Path,
    out_dir: Path,
    cases_manifest: Path,
    model: str,
) -> tuple[str, dict[str, Any]]:
    """
    Run the plain-runtime baseline under OpenClaw once (one agent turn) by asking
    it to execute the deterministic Python harness.
    """
    oc_bin = repo_root / "integrations" / "openclaw_runner" / "node_modules" / ".bin" / "openclaw"
    if not oc_bin.exists():
        return "SKIPPED", {"reason": "openclaw_not_installed", "bin": str(oc_bin)}

    state_dir = out_dir / "openclaw_state"
    state_dir.mkdir(parents=True, exist_ok=True)

    # Ensure provider plugin is configured and Codex OAuth is imported.
    env = os.environ.copy()
    env["OPENCLAW_STATE_DIR"] = str(state_dir)
    setup = _run(["bash", str(repo_root / "scripts" / "setup_openclaw_state.sh")], env=env, cwd=repo_root, timeout_s=600)
    if setup.returncode != 0:
        return "ERROR", {"reason": "openclaw_state_setup_failed", "stderr": setup.stderr[:2000]}

    imp = _run([sys.executable, str(repo_root / "scripts" / "import_codex_oauth_to_openclaw.py")], env=env, cwd=repo_root, timeout_s=120)
    if imp.returncode != 0:
        return "ERROR", {"reason": "openclaw_oauth_import_failed", "stderr": imp.stderr[:2000]}

    port = _pick_port()
    token = secrets.token_hex(16)
    cfg_path = out_dir / "openclaw.native.config.json"
    baseline_out = out_dir / "openclaw_native"
    baseline_out.mkdir(parents=True, exist_ok=True)

    provider_ext = repo_root / "integrations" / "openclaw_runner" / "extensions" / "openai-codex-auth"
    cfg = {
        "gateway": {
            "mode": "local",
            "port": int(port),
            "bind": "loopback",
            "auth": {"mode": "token", "token": token},
        },
        # Ensure the OpenAI-Codex OAuth provider plugin is available.
        "plugins": {
            "enabled": True,
            "load": {"paths": [str(provider_ext)]},
            "entries": {"openai-codex-auth": {"enabled": True}},
        },
        "tools": {"profile": "coding"},
        "agents": {
            "defaults": {
                "workspace": str(repo_root),
                "model": {"primary": str(model)},
            }
        },
    }
    _write_json(cfg_path, cfg)

    env["OPENCLAW_CONFIG_PATH"] = str(cfg_path)

    log_path = out_dir / "openclaw_gateway.log"
    gw = subprocess.Popen(
        [
            str(oc_bin),
            "gateway",
            "run",
            "--force",
            "--port",
            str(port),
            "--bind",
            "loopback",
            "--auth",
            "token",
            "--token",
            token,
        ],
        env=env,
        text=True,
        stdout=log_path.open("w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
        cwd=str(repo_root),
    )
    try:
        ok = False
        for _ in range(200):
            h = _run([str(oc_bin), "gateway", "health", "--timeout", "250"], env=env, cwd=repo_root, timeout_s=20)
            if h.returncode == 0:
                ok = True
                break
            time.sleep(0.1)
        if not ok:
            lg = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
            return "ERROR", {"reason": "openclaw_gateway_not_ready", "log_tail": lg[-2000:]}

        # Ask the agent to run the deterministic harness.
        out_path = baseline_out / "plain_runtime_summary.json"
        prompt = (
            "Artifact baseline runner. Execute exactly this command, then print ONLY the path it prints:\n\n"
            f"python scripts/plain_runtime_agentleak_eval.py --cases {cases_manifest} --out {baseline_out}\n"
        )
        res = _run(
            [str(oc_bin), "agent", "--session-id", f"fair-openclaw-{secrets.token_hex(4)}", "--message", prompt, "--json"],
            env=env,
            cwd=repo_root,
            timeout_s=3600,
        )
        if res.returncode != 0:
            return "ERROR", {"reason": "openclaw_agent_failed", "stderr": res.stderr[:2000], "stdout": res.stdout[:2000]}
        if not out_path.exists():
            return "ERROR", {"reason": "openclaw_did_not_produce_output", "stdout": res.stdout[:2000]}
        return "OK", {"summary_path": str(out_path), "agent_stdout_json": res.stdout[:2000]}
    finally:
        try:
            gw.terminate()
        except Exception:
            pass
        try:
            gw.wait(timeout=2)
        except Exception:
            try:
                gw.kill()
            except Exception:
                pass


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    # Make repo-root imports (agent/, gateway/, etc.) work when invoked as a script.
    # `python scripts/fair_full_compare.py` sets sys.path[0]=scripts/, not repo root.
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    out_root = Path(os.getenv("OUT_DIR", str(repo_root / "artifact_out_compare"))).expanduser().resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    seed = int(os.getenv("MIRAGE_SEED", "7"))
    n_attack = int(os.getenv("AGENTLEAK_ATTACKS_PER_CHANNEL", "100000"))
    n_benign = int(os.getenv("AGENTLEAK_BENIGNS_PER_CHANNEL", "100000"))
    dataset_path = Path(
        os.getenv(
            "AGENTLEAK_DATASET_PATH",
            str(repo_root / "third_party" / "agentleak_official" / "agentleak_data" / "datasets" / "scenarios_full_1000.jsonl"),
        )
    ).expanduser()
    reuse_secureclaw = bool(int(os.getenv("FAIR_FULL_REUSE_SECURECLAW", "1")))

    mod = _load_agentleak_module(repo_root)
    cases, case_meta = mod.build_cases_official(  # type: ignore[attr-defined]
        seed=seed,
        n_attack_per_channel=n_attack,
        n_benign_per_channel=n_benign,
        dataset_path=dataset_path,
    )
    manifest_rows: list[dict[str, Any]] = []
    for c in cases:
        try:
            d = asdict(c)  # dataclass from agentleak_channel_eval
        except Exception:
            d = {"case_id": getattr(c, "case_id", ""), "channel": getattr(c, "channel", ""), "kind": getattr(c, "kind", ""), "payload": getattr(c, "payload", {})}
        manifest_rows.append({"case_id": str(d.get("case_id") or ""), "channel": str(d.get("channel") or ""), "kind": str(d.get("kind") or ""), "payload": d.get("payload") if isinstance(d.get("payload"), dict) else {}})

    cases_manifest = out_root / "fair_cases.jsonl"
    _write_jsonl(cases_manifest, manifest_rows)
    _write_json(out_root / "fair_case_meta.json", {"seed": seed, "case_meta": case_meta})

    # 1) SecureClaw four modes (same official cases via manifest).
    mirage_out = out_root / "fair_mirage"
    mirage_summary_path = mirage_out / "agentleak_eval" / "agentleak_channel_summary.json"
    if not (reuse_secureclaw and mirage_summary_path.exists()):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(repo_root)
        env["OUT_DIR"] = str(mirage_out)
        env["POLICY_BACKEND"] = str(os.getenv("POLICY_BACKEND", "rust"))
        env["AGENTLEAK_CASESET"] = "official"
        env["MIRAGE_SEED"] = str(seed)
        env["AGENTLEAK_ATTACKS_PER_CHANNEL"] = str(n_attack)
        env["AGENTLEAK_BENIGNS_PER_CHANNEL"] = str(n_benign)
        env["AGENTLEAK_CASES_MANIFEST_PATH"] = str(cases_manifest)
        # Prefer high-perf local settings unless explicitly disabled.
        env.setdefault("MIRAGE_USE_UDS", "1")
        env.setdefault("PIR_BINARY_TRANSPORT", "1")
        p = _run([sys.executable, str(repo_root / "scripts" / "agentleak_channel_eval.py")], env=env, cwd=repo_root, timeout_s=7200)
        if p.returncode != 0:
            raise SystemExit(f"secureclaw_eval_failed:\n{p.stderr[:2000]}")
    if not mirage_summary_path.exists():
        raise SystemExit("secureclaw_eval_missing_summary")
    mirage_summary = _load_json(mirage_summary_path)

    systems: dict[str, Any] = {}
    modes = mirage_summary.get("modes") if isinstance(mirage_summary.get("modes"), dict) else {}
    for name in ("mirage_full", "policy_only", "sandbox_only", "single_server_policy"):
        ms = modes.get(name) if isinstance(modes, dict) else None
        if isinstance(ms, dict):
            systems[name] = _extract_system_metrics(ms)

    # 2) Native runtime baselines (non-compromised): Codex and OpenClaw "guardrails-only" runs.
    # These baselines execute the official cases against real CLIs, without the deterministic
    # "compromised runtime" harness that intentionally leaks secrets.
    native_script = repo_root / "scripts" / "native_official_baseline_eval.py"
    max_groups = int(os.getenv("NATIVE_BASELINE_MAX_GROUPS", "0") or 0)
    max_groups_arg = ["--max-groups", str(max_groups)] if max_groups > 0 else []
    reuse_native = bool(int(os.getenv("FAIR_FULL_REUSE_NATIVE", "0")))

    codex_out = out_root / "fair_codex_native_guardrails"
    codex_out.mkdir(parents=True, exist_ok=True)
    codex_summary_path = codex_out / "native_official_baseline_summary.json"
    if reuse_native and codex_summary_path.exists():
        cd = _load_json(codex_summary_path)
        sm = (cd.get("summary") or {}) if isinstance(cd, dict) else {}
        systems["codex_native"] = {"status": "OK", **_extract_system_metrics(sm), "source_path": str(codex_summary_path), "reused_existing": True}
        if isinstance(sm, dict):
            for k in ("model_call_count", "model_ops_s", "model_latency_p50_ms", "model_latency_p95_ms"):
                if k in sm:
                    systems["codex_native"][k] = sm.get(k)
    else:
        codex_env = os.environ.copy()
        codex_env.setdefault("NATIVE_BASELINE_RETRY_BAD", "0")
        codex = _run(
            [
                sys.executable,
                str(native_script),
                "--cases",
                str(cases_manifest),
                "--out",
                str(codex_out),
                "--runtime",
                "codex",
                *max_groups_arg,
            ],
            env=codex_env,
            cwd=repo_root,
            timeout_s=24 * 3600,
        )
        if codex.returncode != 0 or not codex_summary_path.exists():
            systems["codex_native"] = {"status": "ERROR", "rc": int(codex.returncode), "stderr": codex.stderr[:2000], "stdout": codex.stdout[:2000]}
        else:
            cd = _load_json(codex_summary_path)
            sm = (cd.get("summary") or {}) if isinstance(cd, dict) else {}
            systems["codex_native"] = {"status": "OK", **_extract_system_metrics(sm), "source_path": str(codex_summary_path), "reused_existing": False}
            # Preserve call-level metrics for transparency (LLM inference dominates).
            if isinstance(sm, dict):
                for k in ("model_call_count", "model_ops_s", "model_latency_p50_ms", "model_latency_p95_ms"):
                    if k in sm:
                        systems["codex_native"][k] = sm.get(k)

    openclaw_out = out_root / "fair_openclaw_native_guardrails"
    openclaw_out.mkdir(parents=True, exist_ok=True)
    oc_summary_path = openclaw_out / "native_official_baseline_summary.json"
    if reuse_native and oc_summary_path.exists():
        od = _load_json(oc_summary_path)
        sm2 = (od.get("summary") or {}) if isinstance(od, dict) else {}
        systems["openclaw_native"] = {"status": "OK", **_extract_system_metrics(sm2), "source_path": str(oc_summary_path), "reused_existing": True}
        if isinstance(sm2, dict):
            for k in ("model_call_count", "model_ops_s", "model_latency_p50_ms", "model_latency_p95_ms"):
                if k in sm2:
                    systems["openclaw_native"][k] = sm2.get(k)
    else:
        oc_env = os.environ.copy()
        oc_env.setdefault("NATIVE_BASELINE_RETRY_BAD", "1")
        oc = _run(
            [
                sys.executable,
                str(native_script),
                "--cases",
                str(cases_manifest),
                "--out",
                str(openclaw_out),
                "--runtime",
                "openclaw",
                *max_groups_arg,
            ],
            env=oc_env,
            cwd=repo_root,
            timeout_s=24 * 3600,
        )
        if oc.returncode != 0 or not oc_summary_path.exists():
            systems["openclaw_native"] = {"status": "ERROR", "rc": int(oc.returncode), "stderr": oc.stderr[:2000], "stdout": oc.stdout[:2000]}
        else:
            od = _load_json(oc_summary_path)
            sm2 = (od.get("summary") or {}) if isinstance(od, dict) else {}
            systems["openclaw_native"] = {"status": "OK", **_extract_system_metrics(sm2), "source_path": str(oc_summary_path), "reused_existing": False}
            if isinstance(sm2, dict):
                for k in ("model_call_count", "model_ops_s", "model_latency_p50_ms", "model_latency_p95_ms"):
                    if k in sm2:
                        systems["openclaw_native"][k] = sm2.get(k)

    out = {
        "status": "OK",
        "seed": seed,
        "cases_manifest_path": str(cases_manifest),
        "case_meta": case_meta,
        "baseline_set": {
            "secureclaw_modes": ["mirage_full", "policy_only", "sandbox_only", "single_server_policy"],
            "native_baselines": ["codex_native", "openclaw_native"],
        },
        "systems": systems,
    }
    out_path = out_root / "fair_full_report.json"
    _write_json(out_path, out)
    print(str(out_path))


if __name__ == "__main__":
    main()
