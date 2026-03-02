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
    for k in (
        "attack_leak_rate",
        "attack_block_rate",
        "benign_allow_rate",
        "benign_confirm_rate",
        "false_positive_rate",
        "availability_fail_rate",
        "availability_case_success_rate",
        "latency_p50_ms",
        "latency_p95_ms",
        "n_attack",
        "n_benign",
    ):
        if k in s:
            out[k] = s.get(k)
    if "status" in s:
        out["status"] = s.get("status")
    if "source_path" in s:
        out["source_path"] = s.get("source_path")
    return out


def _pick_external_report(
    *,
    repo_root: Path,
    arg_path: str,
    external_run_tag: str,
) -> tuple[Path | None, str]:
    candidates: list[tuple[Path, str]] = []
    if str(arg_path).strip():
        candidates.append((Path(str(arg_path)).expanduser().resolve(), "arg:--external-report"))

    env_path = str(os.getenv("EXTERNAL_UNIFIED_REPORT_PATH", "")).strip()
    if env_path:
        candidates.append((Path(env_path).expanduser().resolve(), "env:EXTERNAL_UNIFIED_REPORT_PATH"))

    run_tag = str(external_run_tag or "").strip() or str(os.getenv("EXTERNAL_RUN_TAG", "")).strip()
    if run_tag:
        candidates.append(
            (
                (repo_root / "artifact_out_external_runtime" / "external_runs" / run_tag / "external_benchmark_unified_report.json").resolve(),
                f"run_tag:{run_tag}",
            )
        )

    for p, src in candidates:
        if p.exists():
            return p, src
    return None, "not_found"


def _extract_asb_run_tag(asb: dict[str, Any]) -> str:
    tag = str(asb.get("requested_run_tag") or "").strip()
    if tag:
        return tag
    # Backward-compatible parse from selected file path suffix.
    files = asb.get("files") if isinstance(asb.get("files"), list) else []
    for f in files:
        if not isinstance(f, dict):
            continue
        p = str(f.get("path") or "")
        stem = Path(p).name
        if "-all_lowmem_" in stem and stem.endswith(".csv"):
            try:
                return stem.split("-all_lowmem_", 1)[1].rsplit(".csv", 1)[0]
            except Exception:
                continue
    return ""


def _extract_external_run_tag_from_path(path: Path) -> str:
    parts = list(path.parts)
    for i, p in enumerate(parts):
        if p == "external_runs" and i + 1 < len(parts):
            return str(parts[i + 1])
    return ""


def _resolve_optional_path(raw: Any) -> Path | None:
    s = str(raw or "").strip()
    if not s:
        return None
    return Path(s).expanduser().resolve()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except Exception:
        return False


def _validate_external_real_run_report(
    doc: dict[str, Any],
    *,
    expected_asb_run_tag: str,
    expected_external_run_tag: str,
    report_path: Path | None,
) -> tuple[bool, list[str], dict[str, Any]]:
    reasons: list[str] = []
    snapshot: dict[str, Any] = {}

    ad = doc.get("agentdojo") if isinstance(doc.get("agentdojo"), dict) else {}
    asb = doc.get("asb") if isinstance(doc.get("asb"), dict) else {}
    drift = doc.get("drift") if isinstance(doc.get("drift"), dict) else {}
    ipi = doc.get("ipiguard") if isinstance(doc.get("ipiguard"), dict) else {}
    report_tag = _extract_external_run_tag_from_path(report_path) if report_path is not None else ""
    run_root = report_path.parent.resolve() if report_path is not None else None

    snapshot["report_path"] = str(report_path) if report_path is not None else ""
    snapshot["report_external_run_tag"] = report_tag
    snapshot["expected_external_run_tag"] = str(expected_external_run_tag or "")
    if expected_external_run_tag:
        if not report_tag:
            reasons.append("external_run_tag_missing_in_report_path")
        elif report_tag != expected_external_run_tag:
            reasons.append(f"external_run_tag_mismatch:{report_tag}!={expected_external_run_tag}")

    ad_complete = bool(ad.get("complete"))
    snapshot["agentdojo_complete"] = ad_complete

    asb_files = asb.get("files") if isinstance(asb.get("files"), list) else []
    asb_run_tag = _extract_asb_run_tag(asb)
    snapshot["asb_run_tag"] = asb_run_tag
    snapshot["asb_files"] = []
    if len(asb_files) < 3:
        reasons.append("asb_files_incomplete")
    for f in asb_files:
        if not isinstance(f, dict):
            reasons.append("asb_file_entry_invalid")
            continue
        status = str(f.get("status") or "")
        selection = str(f.get("selection_mode") or "")
        atk = str(f.get("attack_type") or "")
        snapshot["asb_files"].append(
            {
                "attack_type": atk,
                "status": status,
                "selection_mode": selection,
                "rows": int(f.get("rows") or 0),
                "attack_success_rate": f.get("attack_success_rate"),
                "utility_success_rate": f.get("utility_success_rate"),
            }
        )
        if status != "ok":
            reasons.append(f"asb_not_ok:{atk}:{status}")
        if expected_asb_run_tag and selection != "run_tag_exact":
            reasons.append(f"asb_selection_not_run_tag_exact:{atk}:{selection or 'missing'}")
        elif selection and selection != "run_tag_exact":
            reasons.append(f"asb_selection_not_run_tag_exact:{atk}:{selection}")

    if expected_asb_run_tag:
        if asb_run_tag != expected_asb_run_tag:
            reasons.append(f"asb_run_tag_mismatch:{asb_run_tag}!={expected_asb_run_tag}")
    elif not asb_run_tag:
        reasons.append("asb_run_tag_missing")

    drift_suites = drift.get("suites") if isinstance(drift.get("suites"), dict) else {}
    snapshot["drift_suite_count"] = int(len(drift_suites))
    snapshot["drift_suites"] = {}
    drift_rows = 0
    drift_status = str(drift.get("status") or "")
    expected_suites = ("banking", "slack", "travel", "workspace")
    drift_dir = _resolve_optional_path(drift.get("dir"))
    snapshot["drift_dir"] = str(drift_dir) if drift_dir is not None else str(drift.get("dir") or "")
    if run_root is not None and drift_dir is not None and not _is_within(drift_dir, run_root):
        reasons.append("drift_dir_not_under_external_run_root")
    if drift_status == "ok" and drift_suites:
        for name, s in drift_suites.items():
            if not isinstance(s, dict):
                continue
            b = s.get("benign") if isinstance(s.get("benign"), dict) else {}
            a = s.get("under_attack") if isinstance(s.get("under_attack"), dict) else {}
            bf = int(b.get("files") or 0)
            af = int(a.get("files") or 0)
            drift_rows += bf + af
            snapshot["drift_suites"][str(name)] = {"benign_files": bf, "attack_files": af}
    if drift_status != "ok":
        reasons.append(f"drift_status_not_ok:{drift_status or 'missing'}")
    for suite in expected_suites:
        s = drift_suites.get(suite) if isinstance(drift_suites.get(suite), dict) else {}
        b = s.get("benign") if isinstance(s.get("benign"), dict) else {}
        a = s.get("under_attack") if isinstance(s.get("under_attack"), dict) else {}
        bf = int(b.get("files") or 0)
        af = int(a.get("files") or 0)
        if not s:
            reasons.append(f"drift_suite_missing:{suite}")
            continue
        if bf <= 0:
            reasons.append(f"drift_benign_missing:{suite}")
        if af <= 0:
            reasons.append(f"drift_attack_missing:{suite}")
    snapshot["drift_total_files"] = int(drift_rows)

    ipi_suites = ipi.get("suites") if isinstance(ipi.get("suites"), dict) else {}
    snapshot["ipiguard_modes"] = sorted(list(ipi_suites.keys())) if isinstance(ipi_suites, dict) else []
    snapshot["ipiguard_suites"] = {}
    ipi_rows = 0
    ipi_status = str(ipi.get("status") or "")
    ipi_dir = _resolve_optional_path(ipi.get("dir"))
    snapshot["ipiguard_dir"] = str(ipi_dir) if ipi_dir is not None else str(ipi.get("dir") or "")
    if run_root is not None and ipi_dir is not None and not _is_within(ipi_dir, run_root):
        reasons.append("ipiguard_dir_not_under_external_run_root")
    if ipi_status == "ok" and ipi_suites:
        for mode in ("benign", "under_attack"):
            md = ipi_suites.get(mode) if isinstance(ipi_suites.get(mode), dict) else {}
            for suite_name, rec in md.items():
                if not isinstance(rec, dict):
                    continue
                rows = int(rec.get("task_rows") or 0)
                ipi_rows += rows
                snapshot["ipiguard_suites"][f"{mode}/{suite_name}"] = {"status": str(rec.get("status") or ""), "rows": rows}
    if ipi_status != "ok":
        reasons.append(f"ipiguard_status_not_ok:{ipi_status or 'missing'}")
    for mode in ("benign", "under_attack"):
        md = ipi_suites.get(mode) if isinstance(ipi_suites.get(mode), dict) else {}
        if not md:
            reasons.append(f"ipiguard_mode_missing:{mode}")
            continue
        for suite in expected_suites:
            rec = md.get(suite) if isinstance(md.get(suite), dict) else {}
            st = str(rec.get("status") or "")
            rows = int(rec.get("task_rows") or 0)
            if not rec:
                reasons.append(f"ipiguard_suite_missing:{mode}:{suite}")
                continue
            if st != "ok":
                reasons.append(f"ipiguard_status_not_ok:{mode}:{suite}:{st or 'missing'}")
            if rows <= 0:
                reasons.append(f"ipiguard_rows_missing:{mode}:{suite}")
    snapshot["ipiguard_total_rows"] = int(ipi_rows)

    if drift_rows <= 0:
        reasons.append("external_runtime_rows_missing:drift")
    if ipi_rows <= 0:
        reasons.append("external_runtime_rows_missing:ipiguard")

    return (len(reasons) == 0), reasons, snapshot


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="artifact_out_compare_noprompt")
    ap.add_argument("--force-refresh-fair", type=int, default=0, help="Set 1 to rerun fair_full_compare.")
    ap.add_argument("--run-protocol-tests", type=int, default=1)
    ap.add_argument(
        "--external-report",
        default="",
        help="Path to external_benchmark_unified_report.json from a real run (optional if discoverable).",
    )
    ap.add_argument(
        "--external-run-tag",
        default="",
        help="Expected external run tag; used to locate/validate external benchmark report.",
    )
    ap.add_argument(
        "--asb-run-tag",
        default="",
        help="Expected ASB run tag in the external benchmark report.",
    )
    ap.add_argument(
        "--require-external-real-run",
        type=int,
        default=1,
        help="Set 1 to require validated external benchmark real-run evidence.",
    )
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

    injection_track: dict[str, Any] = {
        "name": "injection_robustness_track",
        "benchmarks": ["AgentDojo", "ASB", "WASP", "VPI-Bench"],
        "local_proxy_eval": str(fair_report),
        "systems": [_system_slice(rep, k) for k in (main_systems + defense_systems)],
    }

    external_report_path, external_source = _pick_external_report(
        repo_root=repo_root,
        arg_path=str(args.external_report),
        external_run_tag=str(args.external_run_tag),
    )
    external_block: dict[str, Any] = {
        "status": "MISSING",
        "source": external_source,
    }
    if external_report_path and external_report_path.exists():
        ext_doc = _load_json(external_report_path)
        ext_ok, ext_reasons, ext_snapshot = _validate_external_real_run_report(
            ext_doc,
            expected_asb_run_tag=str(args.asb_run_tag or ""),
            expected_external_run_tag=str(args.external_run_tag or ""),
            report_path=external_report_path,
        )
        external_block = {
            "status": "OK" if ext_ok else "INVALID",
            "source": external_source,
            "path": str(external_report_path),
            "validation_reasons": ext_reasons,
            "snapshot": ext_snapshot,
            "report": ext_doc,
        }
    injection_track["external_real_run"] = external_block
    if int(args.require_external_real_run) == 1 and external_block.get("status") != "OK":
        raise SystemExit(
            "external_benchmark_real_run_required_but_not_valid: "
            + json.dumps({"status": external_block.get("status"), "source": external_block.get("source"), "reasons": external_block.get("validation_reasons", [])}, ensure_ascii=True)
        )

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
