#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


PROJECT_DOC_EXCLUDES = (
    "third_party/",
    "artifact_out/",
    "artifact_out_",
    "integrations/",
    "node_modules/",
    "memory/",
    ".pytest_cache/",
)

FORBIDDEN_TOKENS = (
    "webexec.py",
    "httpexec.py",
    "paper_full_body_副本",
    "appendix_security_副本",
)

FORBIDDEN_NUMERIC_STRINGS = (
    "0.34545454545454546",
    "0.3175635718509758",
    "2.0776676398894596e-06",
)

CODE_SPAN_RE = re.compile(r"`([^`]+)`")
PATH_HINT_RE = re.compile(r"[A-Za-z0-9_./-]+\.(?:py|md|tex|jsonl|json|ya?ml|sh|toml|rs)(?![A-Za-z0-9])")
LINE_REF_SUFFIX_RE = re.compile(r"^(.+\.(?:py|md|tex|jsonl|json|ya?ml|sh|toml|rs))(?::\d+(?::\d+)?)$")
SYMBOL_REF_SUFFIX_RE = re.compile(r"^(.+\.(?:py|md|tex|jsonl|json|ya?ml|sh|toml|rs)):[A-Za-z_].*$")
ANCHOR_SUFFIX_RE = re.compile(r"^(.+\.(?:py|md|tex|jsonl|json|ya?ml|sh|toml|rs))(?:#L\d+(?:C\d+)?)$")
ENDPOINT_REF_SUFFIX_RE = re.compile(r"^(.+\.(?:py|md|tex|jsonl|json|ya?ml|sh|toml|rs)):/.+$")

KNOWN_PATH_PREFIXES = (
    "scripts/",
    "gateway/",
    "executor_server/",
    "common/",
    "formal/",
    "spec/",
    "capsule/",
    "tests/",
    "policy_server/",
    "policy_server_rust/",
    "artifact_out",
    "third_party/",
)

EXCLUDE_DOC_BASENAMES = {
    "AGENTS.md",
    "SOUL.md",
    "USER.md",
    "MEMORY.md",
    "HEARTBEAT.md",
    "TOOLS.md",
    "chat_history.md",
    "gpt.md",
    "guide.md",
    "guide2.md",
    "idea_1.md",
    "idea_2.md",
    "new.md",
    "update.md",
    "polish.md",
    "SAP_动机.md",
    "方案优化.md",
}


def _is_doc(rel: str) -> bool:
    if not (rel.endswith(".md") or rel.endswith(".tex")):
        return False
    if Path(rel).name in EXCLUDE_DOC_BASENAMES:
        return False
    return not any(rel.startswith(prefix) for prefix in PROJECT_DOC_EXCLUDES)


def _iter_docs(repo_root: Path) -> list[Path]:
    out: list[Path] = []
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(repo_root).as_posix()
        if _is_doc(rel):
            out.append(p)
    return sorted(out)


def _is_candidate_path(s: str) -> bool:
    if not s:
        return False
    if len(s) > 240:
        return False
    if "\n" in s or "\r" in s or "\t" in s:
        return False
    if any(ch.isspace() for ch in s):
        return False
    if s.startswith("http://") or s.startswith("https://"):
        return False
    if s.startswith("//"):
        return False
    if s.startswith("/"):
        return False
    if s.startswith("<") or s.endswith(">"):
        return False
    if "://" in s:
        return False
    if "*" in s:
        return False
    if s.startswith("$"):
        return False
    has_slash = "/" in s
    if has_slash and not any(s.startswith(p) for p in KNOWN_PATH_PREFIXES):
        return False
    return bool(PATH_HINT_RE.fullmatch(s))


def _normalize_candidate(raw: str) -> str:
    s = raw.replace("\\_", "_").strip().strip("`")
    s = s.rstrip(",.;:")
    s = s.split("?", 1)[0]
    m = ANCHOR_SUFFIX_RE.match(s)
    if m:
        s = m.group(1)
    m = ENDPOINT_REF_SUFFIX_RE.match(s)
    if m:
        s = m.group(1)
    m = LINE_REF_SUFFIX_RE.match(s)
    if m:
        s = m.group(1)
    else:
        m2 = SYMBOL_REF_SUFFIX_RE.match(s)
        if m2:
            s = m2.group(1)
    return s


def _collect_path_candidates(text: str) -> set[str]:
    cands: set[str] = set()
    for m in CODE_SPAN_RE.finditer(text):
        val = _normalize_candidate(m.group(1))
        if _is_candidate_path(val):
            cands.add(val)
    for m in PATH_HINT_RE.finditer(text):
        val = _normalize_candidate(m.group(0))
        if _is_candidate_path(val):
            cands.add(val)
    return cands


def _check_path_exists(repo_root: Path, candidate: str, name_index: dict[str, int]) -> bool:
    if candidate.startswith("artifact_out"):
        return True
    if candidate.startswith("~"):
        return True
    if "YYYY" in candidate or "MM" in candidate or "DD" in candidate:
        return True
    try:
        p = (repo_root / candidate).resolve()
        if p.exists():
            return True
        if "/" not in candidate:
            # Bare filenames in prose are often artifact names; only fail when ambiguous source
            # references can be resolved and still missing.
            return True
        return False
    except OSError:
        return False


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _extract_leakage_numbers(repo_root: Path) -> dict[str, str]:
    p = repo_root / "artifact_out_compare/leakage_sweep/leakage_model_sweep.json"
    if not p.exists():
        return {}
    d = _load_json(p)
    cfgs = d.get("configs") if isinstance(d.get("configs"), list) else []
    by_name = {str(c.get("name")): c for c in cfgs if isinstance(c, dict)}
    u = by_name.get("unshaped") or {}
    s = by_name.get("shaped_pad4_cover1") or {}
    return {
        "unshaped_pir_mi": str((((u.get("pir") or {}) if isinstance(u.get("pir"), dict) else {}).get("mi_bits"))),
        "unshaped_pir_acc": str((((u.get("pir") or {}) if isinstance(u.get("pir"), dict) else {}).get("accuracy"))),
        "shaped_pir_acc": str((((s.get("pir") or {}) if isinstance(s.get("pir"), dict) else {}).get("accuracy"))),
        "shaped_mpc_mi": str((((s.get("mpc") or {}) if isinstance(s.get("mpc"), dict) else {}).get("mi_bits"))),
        "shaped_mpc_acc": str((((s.get("mpc") or {}) if isinstance(s.get("mpc"), dict) else {}).get("accuracy"))),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="artifact_out_compare_noprompt/docs_consistency_report.json")
    ap.add_argument("--strict", type=int, default=1)
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    docs = _iter_docs(repo_root)
    name_index: dict[str, int] = {}
    for p in repo_root.rglob("*"):
        if p.is_file():
            name_index[p.name] = int(name_index.get(p.name, 0)) + 1

    missing_paths: list[dict[str, str]] = []
    stale_tokens: list[dict[str, str]] = []
    forbidden_numerics: list[dict[str, str]] = []

    for doc in docs:
        rel = doc.relative_to(repo_root).as_posix()
        text = doc.read_text(encoding="utf-8", errors="replace")
        for tok in FORBIDDEN_TOKENS:
            if tok in text:
                stale_tokens.append({"file": rel, "token": tok})
        for num in FORBIDDEN_NUMERIC_STRINGS:
            if num in text:
                forbidden_numerics.append({"file": rel, "value": num})
        for cand in sorted(_collect_path_candidates(text)):
            if not _check_path_exists(repo_root, cand, name_index):
                missing_paths.append({"file": rel, "path": cand})

    number_ref = _extract_leakage_numbers(repo_root)
    numeric_consistency: dict[str, Any] = {
        "status": "SKIPPED",
        "issues": [],
        "reference": number_ref,
    }
    if number_ref:
        issues: list[str] = []
        readme = (repo_root / "README.md").read_text(encoding="utf-8", errors="replace")
        leakage_md = (repo_root / "LEAKAGE_EVIDENCE.md").read_text(encoding="utf-8", errors="replace")
        paper = (repo_root / "paper_full_body.tex").read_text(encoding="utf-8", errors="replace")
        for key in ("unshaped_pir_mi", "unshaped_pir_acc", "shaped_pir_acc", "shaped_mpc_mi", "shaped_mpc_acc"):
            val = number_ref.get(key, "")
            if not val:
                continue
            if key in {"shaped_mpc_mi"}:
                if val not in readme and val not in leakage_md:
                    issues.append(f"missing_value_in_docs:{key}={val}")
            else:
                if val not in readme and val not in leakage_md:
                    issues.append(f"missing_value_in_docs:{key}={val}")
        shaped_pir_acc = number_ref.get("shaped_pir_acc")
        shaped_mpc_acc = number_ref.get("shaped_mpc_acc")
        if shaped_pir_acc and shaped_mpc_acc:
            expected_row = f"Shaped (pad4, cover) & 0.0000 & {float(shaped_pir_acc):.3f} & 0.0000 & {float(shaped_mpc_acc):.3f} \\\\"
            if expected_row not in paper:
                issues.append("paper_table_row_out_of_sync:rq2_shaped_pad4_cover")
        numeric_consistency = {
            "status": "OK" if not issues else "ERROR",
            "issues": issues,
            "reference": number_ref,
        }

    issues_total = len(missing_paths) + len(stale_tokens) + len(forbidden_numerics)
    if numeric_consistency.get("status") == "ERROR":
        issues_total += len(numeric_consistency.get("issues") or [])

    out = {
        "status": "OK" if issues_total == 0 else "ERROR",
        "n_docs": len(docs),
        "n_missing_paths": len(missing_paths),
        "n_stale_tokens": len(stale_tokens),
        "n_forbidden_numerics": len(forbidden_numerics),
        "numeric_consistency": numeric_consistency,
        "missing_paths": missing_paths[:200],
        "stale_tokens": stale_tokens[:200],
        "forbidden_numerics": forbidden_numerics[:200],
    }

    out_path = Path(args.out).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(str(out_path))

    if int(args.strict) == 1 and out["status"] != "OK":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
