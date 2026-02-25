#!/usr/bin/env python3
"""Manage third-party overlay workflow without touching upstream branches.

Subcommands:
  - status: show branch/dirty/push-url status for all configured repos
  - lock-push: set origin push URL to DISABLED (fetch URL unchanged)
  - unlock-push: restore origin push URL from backup file
  - export: export local deltas into overlay patch files
  - apply: apply overlay patch files back into local third-party repos
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "third_party_overlays" / "manifest.json"
DEFAULT_PUSH_BACKUP = ROOT / "third_party_overlays" / "remotes" / "push_urls.json"
DEFAULT_PATCH_ROOT = ROOT / "third_party_overlays" / "patches"


def _run(
    cmd: List[str],
    *,
    cwd: Optional[Path] = None,
    check: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        check=False,
        text=text,
        capture_output=True,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )
    return proc


def _git(repo: Path, *args: str, check: bool = True) -> str:
    proc = _run(["git", "-C", str(repo), *args], check=check)
    return proc.stdout.strip()


def _git_ok(repo: Path, *args: str) -> bool:
    proc = _run(["git", "-C", str(repo), *args], check=False)
    return proc.returncode == 0


def _load_manifest(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    repos = data.get("repos", [])
    if not isinstance(repos, list):
        raise ValueError("manifest.json must contain a list field 'repos'")
    return repos


def _repo_path(item: Dict[str, Any]) -> Path:
    return ROOT / item["path"]


def _repo_exists(repo: Path) -> bool:
    return (repo / ".git").exists()


def _pick_repos(repos: List[Dict[str, Any]], names: List[str]) -> List[Dict[str, Any]]:
    if not names:
        return repos
    wanted = set(names)
    out = [r for r in repos if r["name"] in wanted]
    missing = sorted(wanted - {r["name"] for r in out})
    if missing:
        raise ValueError(f"unknown repos in --repo: {', '.join(missing)}")
    return out


def _repo_status(repo_item: Dict[str, Any]) -> Dict[str, Any]:
    repo = _repo_path(repo_item)
    result: Dict[str, Any] = {
        "name": repo_item["name"],
        "path": repo_item["path"],
        "kind": repo_item.get("kind", "nested_repo"),
        "exists": _repo_exists(repo),
    }
    if not result["exists"]:
        return result
    result["branch"] = _git(repo, "rev-parse", "--abbrev-ref", "HEAD", check=False) or "UNKNOWN"
    result["head"] = _git(repo, "rev-parse", "HEAD", check=False) or ""
    result["upstream"] = _git(
        repo, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}", check=False
    )
    result["dirty_count"] = len(
        [line for line in _git(repo, "status", "--porcelain", check=False).splitlines() if line.strip()]
    )
    result["origin_fetch_url"] = _git(repo, "remote", "get-url", "origin", check=False)
    push_url = _git(repo, "remote", "get-url", "--push", "origin", check=False)
    result["origin_push_url"] = push_url or result["origin_fetch_url"]
    result["push_locked"] = result["origin_push_url"] == "DISABLED"
    result["ahead_of_upstream"] = None
    if result["upstream"]:
        ahead = _git(repo, "rev-list", "--count", f"{result['upstream']}..HEAD", check=False)
        try:
            result["ahead_of_upstream"] = int(ahead)
        except ValueError:
            result["ahead_of_upstream"] = None
    return result


def cmd_status(args: argparse.Namespace) -> int:
    repos = _pick_repos(_load_manifest(Path(args.manifest)), args.repo)
    rows = [_repo_status(r) for r in repos]
    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(
                {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "repos": rows,
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
    for row in rows:
        if not row["exists"]:
            print(f"{row['name']:20s} MISSING ({row['path']})")
            continue
        print(
            f"{row['name']:20s} branch={row['branch']:12s} dirty={row['dirty_count']:4d} "
            f"locked={str(row['push_locked']):5s} upstream={row['upstream'] or '-'}"
        )
    return 0


def cmd_lock_push(args: argparse.Namespace) -> int:
    repos = _pick_repos(_load_manifest(Path(args.manifest)), args.repo)
    backup_path = Path(args.backup)
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    backup_rows: List[Dict[str, Any]] = []
    for item in repos:
        repo = _repo_path(item)
        if not _repo_exists(repo):
            print(f"[skip] missing repo: {item['path']}")
            continue
        fetch_url = _git(repo, "remote", "get-url", "origin", check=False)
        if not fetch_url:
            print(f"[skip] no origin remote: {item['path']}")
            continue
        push_url = _git(repo, "remote", "get-url", "--push", "origin", check=False) or fetch_url
        _git(repo, "remote", "set-url", "--push", "origin", "DISABLED")
        print(f"[lock] {item['name']}: push {push_url} -> DISABLED")
        backup_rows.append(
            {
                "name": item["name"],
                "path": item["path"],
                "origin_fetch_url": fetch_url,
                "origin_push_url": push_url,
            }
        )
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repos": backup_rows,
    }
    backup_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[ok] wrote backup: {backup_path}")
    return 0


def cmd_unlock_push(args: argparse.Namespace) -> int:
    backup_path = Path(args.backup)
    data = json.loads(backup_path.read_text(encoding="utf-8"))
    rows = data.get("repos", [])
    for row in rows:
        repo = ROOT / row["path"]
        if not _repo_exists(repo):
            print(f"[skip] missing repo: {row['path']}")
            continue
        push_url = row.get("origin_push_url") or row.get("origin_fetch_url")
        if not push_url:
            print(f"[skip] missing push url record: {row['path']}")
            continue
        _git(repo, "remote", "set-url", "--push", "origin", push_url)
        print(f"[unlock] {row['name']}: push -> {push_url}")
    return 0


def _patch_text(repo: Path, args: List[str]) -> str:
    return _run(["git", "-C", str(repo), *args], check=True).stdout


def _write_if_nonempty(path: Path, content: str) -> bool:
    if content.strip():
        path.write_text(content, encoding="utf-8")
        return True
    if path.exists():
        path.unlink()
    return False


def _best_base_ref(repo: Path) -> str:
    upstream = _git(repo, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}", check=False)
    if upstream:
        return upstream
    if _git_ok(repo, "rev-parse", "--verify", "origin/main"):
        return "origin/main"
    if _git_ok(repo, "rev-parse", "--verify", "origin/master"):
        return "origin/master"
    return ""


def cmd_export(args: argparse.Namespace) -> int:
    repos = _pick_repos(_load_manifest(Path(args.manifest)), args.repo)
    out_root = Path(args.out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    index_rows: List[Dict[str, Any]] = []
    for item in repos:
        repo = _repo_path(item)
        if not _repo_exists(repo):
            print(f"[skip] missing repo: {item['path']}")
            continue
        name = item["name"]
        export_dir = out_root / name
        export_dir.mkdir(parents=True, exist_ok=True)
        base_ref = args.base_ref or _best_base_ref(repo)
        head = _git(repo, "rev-parse", "HEAD", check=False)
        branch = _git(repo, "rev-parse", "--abbrev-ref", "HEAD", check=False)
        metadata: Dict[str, Any] = {
            "name": name,
            "path": item["path"],
            "kind": item.get("kind", "nested_repo"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "branch": branch,
            "head": head,
            "base_ref": base_ref,
            "commits_patch": None,
            "staged_patch": None,
            "working_patch": None,
            "untracked_files": [],
        }
        commits_text = ""
        if base_ref:
            ahead = _git(repo, "rev-list", "--count", f"{base_ref}..HEAD", check=False)
            try:
                ahead_count = int(ahead)
            except ValueError:
                ahead_count = 0
            metadata["ahead_of_base"] = ahead_count
            if ahead_count > 0:
                commits_text = _patch_text(repo, ["format-patch", "--stdout", f"{base_ref}..HEAD"])
        commits_path = export_dir / "commits.patch"
        if _write_if_nonempty(commits_path, commits_text):
            metadata["commits_patch"] = str(commits_path.relative_to(ROOT))

        staged_text = _patch_text(repo, ["diff", "--binary", "--cached"])
        staged_path = export_dir / "staged.patch"
        if _write_if_nonempty(staged_path, staged_text):
            metadata["staged_patch"] = str(staged_path.relative_to(ROOT))

        working_text = _patch_text(repo, ["diff", "--binary"])
        working_path = export_dir / "working.patch"
        if _write_if_nonempty(working_path, working_text):
            metadata["working_patch"] = str(working_path.relative_to(ROOT))

        untracked = _git(repo, "ls-files", "--others", "--exclude-standard", check=False).splitlines()
        metadata["untracked_files"] = [p for p in untracked if p.strip()]
        (export_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        index_rows.append(metadata)
        print(
            f"[export] {name}: commits={bool(metadata['commits_patch'])} "
            f"staged={bool(metadata['staged_patch'])} "
            f"working={bool(metadata['working_patch'])} "
            f"untracked={len(metadata['untracked_files'])}"
        )
    index_path = out_root / "index.json"
    index_path.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "repos": index_rows,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"[ok] wrote index: {index_path}")
    return 0


def _apply_file(repo: Path, cmd: List[str], patch_file: Path) -> None:
    _run(["git", "-C", str(repo), *cmd, str(patch_file)], check=True)


def cmd_apply(args: argparse.Namespace) -> int:
    repos = _pick_repos(_load_manifest(Path(args.manifest)), args.repo)
    patch_root = Path(args.patch_root)
    for item in repos:
        repo = _repo_path(item)
        if not _repo_exists(repo):
            print(f"[skip] missing repo: {item['path']}")
            continue
        overlay = patch_root / item["name"]
        if not overlay.exists():
            print(f"[skip] no overlay dir: {overlay}")
            continue
        commits = overlay / "commits.patch"
        staged = overlay / "staged.patch"
        working = overlay / "working.patch"
        if commits.exists() and commits.stat().st_size > 0:
            _apply_file(repo, ["am", "--3way", "--keep-cr", "--whitespace=nowarn"], commits)
            print(f"[apply] {item['name']}: applied commits.patch")
        if staged.exists() and staged.stat().st_size > 0:
            _apply_file(repo, ["apply", "--index", "--3way"], staged)
            print(f"[apply] {item['name']}: applied staged.patch")
        if working.exists() and working.stat().st_size > 0:
            _apply_file(repo, ["apply", "--3way"], working)
            print(f"[apply] {item['name']}: applied working.patch")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="path to third-party manifest json")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("status", help="show third-party repo status")
    ps.add_argument("--repo", action="append", default=[], help="repo name in manifest (repeatable)")
    ps.add_argument("--json-out", help="optional status json output path")
    ps.set_defaults(func=cmd_status)

    pl = sub.add_parser("lock-push", help="set all origin push URLs to DISABLED")
    pl.add_argument("--repo", action="append", default=[], help="repo name in manifest (repeatable)")
    pl.add_argument("--backup", default=str(DEFAULT_PUSH_BACKUP), help="backup file path")
    pl.set_defaults(func=cmd_lock_push)

    pu = sub.add_parser("unlock-push", help="restore origin push URLs from backup")
    pu.add_argument("--backup", default=str(DEFAULT_PUSH_BACKUP), help="backup file path")
    pu.set_defaults(func=cmd_unlock_push)

    pe = sub.add_parser("export", help="export overlay patches for local deltas")
    pe.add_argument("--repo", action="append", default=[], help="repo name in manifest (repeatable)")
    pe.add_argument("--out-root", default=str(DEFAULT_PATCH_ROOT), help="overlay patch output root")
    pe.add_argument("--base-ref", default="", help="override base ref for commits.patch (default upstream)")
    pe.set_defaults(func=cmd_export)

    pa = sub.add_parser("apply", help="apply overlay patches back to local third-party repos")
    pa.add_argument("--repo", action="append", default=[], help="repo name in manifest (repeatable)")
    pa.add_argument("--patch-root", default=str(DEFAULT_PATCH_ROOT), help="overlay patch root")
    pa.set_defaults(func=cmd_apply)
    return p


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except Exception as exc:  # pragma: no cover - CLI error boundary
        print(f"[error] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
