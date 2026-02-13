from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from pathlib import Path


def _cmd(args: list[str]) -> str:
    try:
        p = subprocess.run(args, text=True, capture_output=True, check=False)
        s = (p.stdout or p.stderr or "").strip()
        return s
    except Exception:
        return ""


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    out_dir = Path(os.getenv("OUT_DIR", str(repo_root / "artifact_out")))
    out_dir.mkdir(parents=True, exist_ok=True)

    m = {
        "status": "OK",
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": sys.version,
        },
        "repo": {
            "path": str(repo_root),
            "git_head": _cmd(["git", "rev-parse", "HEAD"]),
            "git_branch": _cmd(["git", "branch", "--show-current"]),
            "git_status_short": _cmd(["git", "status", "--short"]),
        },
        "tool_versions": {
            "rustc": _cmd(["rustc", "--version"]),
            "cargo": _cmd(["cargo", "--version"]),
            "codex": _cmd(["codex", "--version"]),
            "claude": _cmd(["claude", "--version"]),
            "openclaw_runner": _cmd([str(repo_root / "integrations" / "openclaw_runner" / "node_modules" / ".bin" / "openclaw"), "--version"]),
        },
        "seeds": {
            "MIRAGE_SEED": os.getenv("MIRAGE_SEED", "7"),
            "PYTHONHASHSEED": os.getenv("PYTHONHASHSEED", "0"),
        },
    }

    out_path = out_dir / "repro_manifest.json"
    out_path.write_text(json.dumps(m, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()
