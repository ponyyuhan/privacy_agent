from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _safe_rate_percent(x: Any) -> float:
    try:
        return float(x) / 100.0
    except Exception:
        return 0.0


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    out_dir = Path(os.getenv("OUT_DIR", str(repo_root / "artifact_out_compare")))
    out_dir.mkdir(parents=True, exist_ok=True)

    mirage_path = Path(
        os.getenv(
            "MIRAGE_SUMMARY_PATH",
            str(repo_root / "artifact_out_full_official_v3" / "agentleak_eval" / "agentleak_channel_summary.json"),
        )
    )
    native_path = Path(
        os.getenv(
            "NATIVE_BASELINE_PATH",
            str(repo_root / "artifact_out_tmp" / "native_smoke2" / "native_baselines" / "native_guardrail_eval.json"),
        )
    )
    model_stats_path = Path(
        os.getenv(
            "OFFICIAL_MODEL_STATS_PATH",
            str(repo_root / "third_party" / "agentleak_official" / "benchmarks" / "ieee_repro" / "results" / "model_stats.json"),
        )
    )

    out: dict[str, Any] = {"status": "OK", "sources": {}, "baselines": {}}

    # MIRAGE-side same-harness ablations (official full dataset mapping + same seed/metrics).
    if mirage_path.exists():
        ms = _load_json(mirage_path)
        modes = ms.get("modes") if isinstance(ms.get("modes"), dict) else {}
        out["sources"]["mirage_official_full"] = str(mirage_path)
        out["baselines"]["mirage_harness_modes"] = {}
        for name in ("mirage_full", "policy_only", "sandbox_only", "single_server_policy"):
            m = modes.get(name) if isinstance(modes, dict) else None
            if not isinstance(m, dict):
                continue
            out["baselines"]["mirage_harness_modes"][name] = {
                "attack_block_rate": float(m.get("attack_block_rate", 0.0)),
                "attack_leak_rate": float(m.get("attack_leak_rate", 0.0)),
                "benign_allow_rate": float(m.get("benign_allow_rate", 0.0)),
                "n_attack": int(m.get("n_attack", 0)),
                "n_benign": int(m.get("n_benign", 0)),
            }

    # Native runtime smoke baselines (Codex/Claude/OpenClaw runtime behavior).
    if native_path.exists():
        ns = _load_json(native_path)
        rows = ns.get("rows") if isinstance(ns.get("rows"), list) else []
        out["sources"]["native_runtime_baselines"] = str(native_path)
        out["baselines"]["native_runtime"] = {}
        for r in rows:
            if not isinstance(r, dict):
                continue
            runtime = str(r.get("runtime") or "")
            if not runtime:
                continue
            out["baselines"]["native_runtime"][runtime] = {
                "status": str(r.get("status") or ""),
                "attack_block_rate": float(r.get("attack_block_rate", 0.0)),
                "benign_allow_rate": float(r.get("benign_allow_rate", 0.0)),
                "attack_secret_leaked": bool(r.get("attack_secret_leaked")),
            }

    # Official AgentLeak paper-model stats (same official benchmark family; model-level).
    if model_stats_path.exists():
        md = _load_json(model_stats_path)
        out["sources"]["official_model_stats"] = str(model_stats_path)
        out["baselines"]["official_models"] = {}
        for model_name, v in md.items():
            if not isinstance(v, dict):
                continue
            out["baselines"]["official_models"][str(model_name)] = {
                "n": int(v.get("n", 0)),
                "attack_leak_rate_C1": _safe_rate_percent(v.get("C1", 0.0)),
                "attack_leak_rate_C2": _safe_rate_percent(v.get("C2", 0.0)),
                "attack_leak_rate_C5": _safe_rate_percent(v.get("C5", 0.0)),
            }

    out_path = out_dir / "strong_baseline_report.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()

