import os
import re
from typing import Dict, Any
from pathlib import Path
from ..handles import HandleStore

DEMO_ROOT = Path(__file__).resolve().parents[1] / "demo_data"

SENSITIVE_PATH_MARKERS = [
    "/.ssh/",
    "/.config/",
    "/.aws/",
    "/.gnupg/",
    "/key",
    "/id_rsa",
    ".env",
]

SECRET_PATTERNS = [
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "AKIA",      # AWS access key prefix
    "xoxb-",     # Slack bot token prefix
]

class FSExec:
    def __init__(self, handles: HandleStore):
        self.handles = handles

    def _resolve_demo_path(self, path_spec: str) -> Path:
        # For safety, this demo maps some sensitive-looking paths into demo_data.
        if path_spec in ("~/.ssh/id_rsa", "/home/user/.ssh/id_rsa"):
            return DEMO_ROOT / "id_rsa_fake"
        if path_spec in ("~/.env", ".env"):
            return DEMO_ROOT / "env_fake"
        # Otherwise allow reading only inside demo_data
        p = (DEMO_ROOT / path_spec).resolve()
        if not str(p).startswith(str(DEMO_ROOT.resolve())):
            raise PermissionError("Path outside demo sandbox.")
        return p

    def read_file(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        path_spec = str(inputs.get("path_spec", ""))
        purpose = str(inputs.get("purpose", ""))

        try:
            p = self._resolve_demo_path(path_spec)
            data = p.read_text(errors="ignore")
        except Exception as e:
            return {
                "status": "DENY",
                "summary": "File read blocked or failed.",
                "data": {"error": str(e)},
                "artifacts": [],
                "reason_code": "READFILE_ERROR",
            }

        # Classify sensitivity
        lower = path_spec.lower()
        is_sensitive_path = any(m in lower for m in SENSITIVE_PATH_MARKERS)
        is_secret_content = any(sp in data for sp in SECRET_PATTERNS)

        if is_sensitive_path or is_secret_content:
            # Level 1: do NOT return plaintext. Return a HIGH handle.
            rec = self.handles.mint(
                label="CONFIDENTIAL_FILE",
                sensitivity="HIGH",
                value={"path": path_spec, "content": data},
                allowed_sinks=["UseCredential", "Declassify"],
                session=session,
                ttl_seconds=600,
                caller=caller,
                issuer_intent="ReadFile",
            )
            return {
                "status": "OK",
                "summary": "File classified as sensitive. Returning an opaque handle (no plaintext).",
                "data": {"path": path_spec, "note": "content withheld"},
                "artifacts": [{"handle": rec.handle, "label": rec.label, "sensitivity": rec.sensitivity}],
                "reason_code": "SENSITIVE_HANDLE_RETURNED",
            }

        # Non-sensitive: return a small preview only (still limit).
        preview = data[:200]
        return {
            "status": "OK",
            "summary": "File read allowed (public view only).",
            "data": {"path": path_spec, "preview": preview},
            "artifacts": [],
            "reason_code": "ALLOW",
        }

    def write_workspace_file(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        relpath = str(inputs.get("relpath", "output.txt"))
        content = str(inputs.get("content", ""))

        # Only allow writing into demo_data/workspace/
        ws = DEMO_ROOT / "workspace"
        ws.mkdir(exist_ok=True)
        p = (ws / relpath).resolve()
        if not str(p).startswith(str(ws.resolve())):
            return {
                "status": "DENY",
                "summary": "Write blocked: path outside workspace.",
                "data": {},
                "artifacts": [],
                "reason_code": "WORKSPACE_PATH_BLOCKED",
            }

        p.write_text(content)
        return {
            "status": "OK",
            "summary": "Workspace file written.",
            "data": {"path": str(p)},
            "artifacts": [],
            "reason_code": "ALLOW",
        }

    def list_workspace_files(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        _ = inputs
        _ = session
        _ = caller
        ws = DEMO_ROOT / "workspace"
        ws.mkdir(exist_ok=True)
        files = []
        for p in sorted(ws.glob("**/*")):
            if p.is_file():
                try:
                    rel = p.relative_to(ws).as_posix()
                except Exception:
                    rel = p.name
                files.append(rel)
        return {
            "status": "OK",
            "summary": "Workspace files listed.",
            "data": {"files": files},
            "artifacts": [],
            "reason_code": "ALLOW",
        }

    def read_workspace_file(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        _ = session
        _ = caller
        relpath = str(inputs.get("relpath", ""))
        if not relpath:
            return {"status": "DENY", "summary": "Missing relpath.", "data": {}, "artifacts": [], "reason_code": "BAD_ARGS"}
        ws = DEMO_ROOT / "workspace"
        ws.mkdir(exist_ok=True)
        p = (ws / relpath).resolve()
        if not str(p).startswith(str(ws.resolve())):
            return {"status": "DENY", "summary": "Read blocked: path outside workspace.", "data": {}, "artifacts": [], "reason_code": "WORKSPACE_PATH_BLOCKED"}
        try:
            data = p.read_text(errors="ignore")
        except Exception as e:
            return {"status": "DENY", "summary": "Workspace read failed.", "data": {"error": str(e)}, "artifacts": [], "reason_code": "READFILE_ERROR"}
        return {"status": "OK", "summary": "Workspace file read.", "data": {"relpath": relpath, "content": data[:2000]}, "artifacts": [], "reason_code": "ALLOW"}
