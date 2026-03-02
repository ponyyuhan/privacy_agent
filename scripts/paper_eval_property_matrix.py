from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


PROPERTY_MAP: dict[str, list[str]] = {
    "prompt_injection": ["NBE"],
    "fetch_exfil_domain": ["NBE"],
    "webhook_exfil_domain": ["NBE"],
    "path_bypass": ["NBE", "SM"],
    "dlp_secret": ["SM", "PEI"],
    "skill_supply_chain": ["SCS"],
    "skill_install_marker": ["SCS"],
    "skill_base64_obf": ["SCS"],
    "command_injection": ["SCS"],  # interpreted as capsule/runtime-mediation boundary
}


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def _render_md(rows: list[dict[str, Any]]) -> str:
    out = [
        "# Property x AttackClass Matrix (paper_eval)",
        "",
        "| Category | Properties | n | blocked_rate | confirm_rate |",
        "|---|---|---:|---:|---:|",
    ]
    for r in rows:
        props = ",".join(r["properties"])
        out.append(
            f"| `{r['category']}` | `{props}` | {r['n']} | "
            f"{r['blocked_rate']:.4f} | {r['confirm_rate']:.4f} |"
        )
    out.append("")
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--paper-eval", default="artifact_out/paper_eval/paper_eval_summary.json")
    ap.add_argument("--mode", default="mirage_full")
    ap.add_argument("--out-json", default="artifact_out/paper_eval/property_matrix.json")
    ap.add_argument("--out-md", default="artifact_out/paper_eval/property_matrix.md")
    args = ap.parse_args()

    src_path = Path(str(args.paper_eval)).expanduser().resolve()
    data = _load_json(src_path)
    mode = str(args.mode)
    modes = data.get("modes") if isinstance(data.get("modes"), dict) else {}
    md = modes.get(mode) if isinstance(modes.get(mode), dict) else {}
    by_cat = md.get("by_category") if isinstance(md.get("by_category"), dict) else {}

    rows: list[dict[str, Any]] = []
    for cat, v in sorted(by_cat.items(), key=lambda kv: kv[0]):
        if not isinstance(v, dict):
            continue
        if str(cat).startswith("benign_"):
            continue
        props = PROPERTY_MAP.get(str(cat), ["UNMAPPED"])
        rows.append(
            {
                "category": str(cat),
                "properties": props,
                "n": int(v.get("n") or 0),
                "blocked_rate": float(v.get("blocked_rate") or 0.0),
                "confirm_rate": float(v.get("confirm_rate") or 0.0),
            }
        )

    prop_rollup: dict[str, dict[str, float]] = {}
    for p in sorted({p for r in rows for p in r["properties"]}):
        rs = [r for r in rows if p in r["properties"]]
        n = sum(int(r["n"]) for r in rs)
        if n <= 0:
            prop_rollup[p] = {"n": 0, "blocked_rate_weighted": 0.0, "confirm_rate_weighted": 0.0}
            continue
        blocked = sum(float(r["blocked_rate"]) * int(r["n"]) for r in rs) / float(n)
        confirm = sum(float(r["confirm_rate"]) * int(r["n"]) for r in rs) / float(n)
        prop_rollup[p] = {"n": int(n), "blocked_rate_weighted": float(blocked), "confirm_rate_weighted": float(confirm)}

    out = {
        "status": "OK",
        "input": str(src_path),
        "mode": mode,
        "rows": rows,
        "property_rollup": prop_rollup,
    }

    out_json = Path(str(args.out_json)).expanduser().resolve()
    out_md = Path(str(args.out_md)).expanduser().resolve()
    _write_json(out_json, out)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(_render_md(rows), encoding="utf-8")
    print(str(out_json))
    print(str(out_md))


if __name__ == "__main__":
    main()
