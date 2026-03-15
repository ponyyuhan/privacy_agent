from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load module: {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


parity_mod = _load_module(REPO_ROOT / "scripts" / "paper_parity_agentleak_eval.py", "_paper_parity_merge_mod")
channel_mod = _load_module(REPO_ROOT / "scripts" / "agentleak_channel_eval.py", "_agentleak_channel_merge_mod")


def _concat_jsonl(srcs: list[Path], dst: Path) -> int:
    dst.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with dst.open("w", encoding="utf-8") as out:
        for src in srcs:
            if not src.exists():
                continue
            for line in src.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                out.write(line.rstrip() + "\n")
                total += 1
    return total


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def merge_parity(prefix: str, shards: int, merged_root: Path, modes: list[str]) -> None:
    run_dir = merged_root / "paper_parity_agentleak_eval"
    run_dir.mkdir(parents=True, exist_ok=True)
    template_report: dict[str, Any] | None = None
    summaries: dict[str, Any] = {}
    merged_from: list[str] = []
    for mode in modes:
        srcs: list[Path] = []
        for idx in range(int(shards)):
            shard_root = Path(f"{prefix}{idx}") / "paper_parity_agentleak_eval"
            shard_report = shard_root / "paper_parity_report.json"
            if template_report is None and shard_report.exists():
                template_report = _load_json(shard_report)
            if shard_root.exists():
                merged_from.append(str(shard_root))
            srcs.append(shard_root / f"rows_{mode}.jsonl")
        dst = run_dir / f"rows_{mode}.jsonl"
        _concat_jsonl(srcs, dst)
        rows = parity_mod._load_latest_rows(dst)
        summary = parity_mod._summarize(rows)
        summaries[mode] = summary
        (run_dir / f"summary_{mode}.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )
    report = dict(template_report or {})
    report["status"] = "OK"
    report["summaries"] = summaries
    report["run_dir"] = str(run_dir)
    report["merged_from_shards"] = sorted(set(merged_from))
    (run_dir / "paper_parity_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def merge_channel(prefix: str, shards: int, merged_root: Path, modes: list[str]) -> None:
    compare_dir = merged_root / "compare"
    compare_dir.mkdir(parents=True, exist_ok=True)
    template_report: dict[str, Any] | None = None
    merged_from: list[str] = []
    mode_reports: dict[str, Any] = {}
    manifest_written = False
    for idx in range(int(shards)):
        shard_root = Path(f"{prefix}{idx}")
        report_path = shard_root / "report.json"
        if template_report is None and report_path.exists():
            template_report = _load_json(report_path)
        shard_manifest = shard_root / "compare" / "cases_manifest.jsonl"
        if (not manifest_written) and shard_manifest.exists():
            shutil.copyfile(shard_manifest, compare_dir / "cases_manifest.jsonl")
            manifest_written = True
        if shard_root.exists():
            merged_from.append(str(shard_root))
    for mode in modes:
        srcs = [Path(f"{prefix}{idx}") / "compare" / mode / "rows.jsonl" for idx in range(int(shards))]
        mode_dir = compare_dir / mode
        mode_dir.mkdir(parents=True, exist_ok=True)
        rows_path = mode_dir / "rows.jsonl"
        _concat_jsonl(srcs, rows_path)
        rows = []
        for line in rows_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            rows.append(json.loads(line))
        summary = channel_mod.summarize(rows)
        summary_path = mode_dir / "summary.json"
        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        mode_reports[mode] = {
            "summary": summary,
            "rows_path": str(rows_path),
            "summary_path": str(summary_path),
        }
    report = dict(template_report or {})
    report["status"] = "OK"
    report["modes"] = mode_reports
    report["merged_from_shards"] = sorted(set(merged_from))
    report["cases_manifest"] = str(compare_dir / "cases_manifest.jsonl")
    (merged_root / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Merge sharded AgentLeak native baseline runs.")
    ap.add_argument("--kind", choices=["parity", "channel"], required=True)
    ap.add_argument("--prefix", required=True, help="Shard root prefix, e.g. path/to/run_shard")
    ap.add_argument("--shards", type=int, required=True)
    ap.add_argument("--merged-root", required=True)
    ap.add_argument("--modes", required=True, help="Comma list, e.g. ipiguard,drift")
    args = ap.parse_args()

    merged_root = Path(str(args.merged_root)).expanduser().resolve()
    modes = [x.strip().lower() for x in str(args.modes).split(",") if x.strip()]
    if str(args.kind) == "parity":
        merge_parity(args.prefix, int(args.shards), merged_root, modes)
    else:
        merge_channel(args.prefix, int(args.shards), merged_root, modes)


if __name__ == "__main__":
    main()
