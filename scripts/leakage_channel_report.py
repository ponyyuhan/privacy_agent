from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    return obj if isinstance(obj, dict) else {}


def _get_mode(summary: dict[str, Any], mode: str) -> dict[str, Any]:
    modes = summary.get("modes")
    if not isinstance(modes, dict):
        return {}
    md = modes.get(mode)
    return md if isinstance(md, dict) else {}


def _channel_metrics(md: dict[str, Any]) -> dict[str, dict[str, Any]]:
    per = md.get("per_channel")
    if not isinstance(per, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for ch, v in per.items():
        if not isinstance(v, dict):
            continue
        out[str(ch)] = {
            "n_attack": int(v.get("n_attack") or 0),
            "n_benign": int(v.get("n_benign") or 0),
            "attack_block_rate": float(v.get("attack_block_rate") or 0.0),
            "attack_leak_rate": float(v.get("attack_leak_rate") or 0.0),
            "benign_allow_rate": float(v.get("benign_allow_rate") or 0.0),
        }
    return out


def _pick_existing(repo_root: Path, rels: list[str]) -> Path | None:
    for r in rels:
        p = repo_root / r
        if p.exists():
            return p
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="artifact_out_compare/leakage_channel_report.json", help="Output report path")
    ap.add_argument("--mode", default="mirage_full", help="Mode to report")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    out_path = Path(str(args.out)).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    mode = str(args.mode)

    official_path = _pick_existing(
        repo_root,
        [
            "artifact_out_compare/fair_mirage/agentleak_eval/agentleak_channel_summary.json",
            "artifact_out/agentleak_eval/agentleak_channel_summary.json",
        ],
    )
    synth_path = _pick_existing(
        repo_root,
        [
            "artifact_out_compare/leakage_sys_synth_v2/agentleak_eval/agentleak_channel_summary.json",
            "artifact_out_compare/leakage_sys_synth/agentleak_eval/agentleak_channel_summary.json",
        ],
    )
    sweep_path = _pick_existing(
        repo_root,
        [
            "artifact_out_compare/leakage_sweep/leakage_model_sweep.json",
            "artifact_out/leakage_sweep/leakage_model_sweep.json",
        ],
    )

    if official_path is None or synth_path is None or sweep_path is None:
        raise SystemExit("missing required leakage inputs")

    official = _load_json(official_path)
    synth = _load_json(synth_path)
    sweep = _load_json(sweep_path)

    off_mode = _get_mode(official, mode)
    syn_mode = _get_mode(synth, mode)
    off_ch = _channel_metrics(off_mode)
    syn_ch = _channel_metrics(syn_mode)

    channels: dict[str, Any] = {}
    for ch in [f"C{i}" for i in range(1, 8)]:
        if ch in off_ch:
            channels[ch] = {"source": "official", **off_ch[ch]}
        elif ch in syn_ch:
            channels[ch] = {"source": "synthetic", **syn_ch[ch]}
        else:
            channels[ch] = {
                "source": "missing",
                "n_attack": 0,
                "n_benign": 0,
                "attack_block_rate": 0.0,
                "attack_leak_rate": 0.0,
                "benign_allow_rate": 0.0,
            }

    # Distinguishability section from leakage sweep.
    cfgs = sweep.get("configs") if isinstance(sweep.get("configs"), list) else []
    distinguishability: dict[str, Any] = {}
    for c in cfgs:
        if not isinstance(c, dict):
            continue
        name = str(c.get("name") or "unknown")
        pir = c.get("pir") if isinstance(c.get("pir"), dict) else {}
        mpc = c.get("mpc") if isinstance(c.get("mpc"), dict) else {}
        distinguishability[name] = {
            "pir_mi_bits": float(pir.get("mi_bits") or 0.0),
            "pir_map_acc": float(pir.get("map_acc") or 0.0),
            "pir_chance_acc": float(pir.get("chance_acc") or 0.0),
            "mpc_mi_bits": float(mpc.get("mi_bits") or 0.0),
            "mpc_map_acc": float(mpc.get("map_acc") or 0.0),
            "mpc_chance_acc": float(mpc.get("chance_acc") or 0.0),
        }

    # Residual leakage upper-bound checklist tracked in docs.
    residual_contract = {
        "allowed_residual_terms": [
            "coarse_scheduler_timing_buckets",
            "confirm_path_invocation_bit_when_conditional",
            "request_hash_commitment_visibility_in_mpc_init",
        ],
        "out_of_scope_terms": [
            "kernel_scheduler_side_channels",
            "microarchitectural_cache_channels",
        ],
    }

    out = {
        "status": "OK",
        "mode": mode,
        "inputs": {
            "official_summary": str(official_path),
            "synthetic_summary": str(synth_path),
            "leakage_sweep": str(sweep_path),
        },
        "channels": channels,
        "distinguishability": distinguishability,
        "residual_contract": residual_contract,
    }

    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()

