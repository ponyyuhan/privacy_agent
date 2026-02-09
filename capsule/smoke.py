from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict

import requests

from agent.mcp_client import McpStdioClient


def _try_read(path: str) -> dict[str, Any]:
    try:
        with open(path, "rb") as f:
            _ = f.read(32)
        return {"ok": True, "note": "unexpected: read succeeded"}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__, "details": str(e)[:200]}


def _try_internet(url: str) -> dict[str, Any]:
    try:
        r = requests.get(url, timeout=2.0)
        return {"ok": True, "status": int(r.status_code), "note": "unexpected: internet request succeeded"}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__, "details": str(e)[:200]}


def _try_gateway_http() -> dict[str, Any]:
    base = (os.getenv("MIRAGE_GATEWAY_HTTP_URL") or "http://127.0.0.1:8765").rstrip("/")
    token = (os.getenv("MIRAGE_HTTP_TOKEN") or "").strip()
    session = (os.getenv("MIRAGE_SESSION_ID") or "capsule-session").strip() or "capsule-session"
    headers: dict[str, str] = {"Content-Type": "application/json", "X-Mirage-Session": session}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = requests.post(
            f"{base}/act",
            json={
                "intent_id": "FetchResource",
                "inputs": {"resource_id": "octocat", "domain": "api.github.com"},
                "constraints": {},
                "caller": "capsule-smoke",
            },
            headers=headers,
            timeout=5.0,
        )
        return {"ok": r.status_code == 200, "http_status": int(r.status_code), "body": (r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text[:200])}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__, "details": str(e)[:200]}


def _try_gateway_mcp() -> dict[str, Any]:
    env = {
        "MIRAGE_GATEWAY_HTTP_URL": os.getenv("MIRAGE_GATEWAY_HTTP_URL") or "http://127.0.0.1:8765",
        "MIRAGE_HTTP_TOKEN": os.getenv("MIRAGE_HTTP_TOKEN") or "",
        "MIRAGE_SESSION_ID": os.getenv("MIRAGE_SESSION_ID") or "capsule-session",
    }
    with McpStdioClient([sys.executable, "-m", "capsule.mcp_proxy"], env=env) as mcp:
        mcp.initialize()
        out = mcp.call_tool(
            "act",
            {
                "intent_id": "FetchResource",
                "inputs": {"resource_id": "octocat", "domain": "api.github.com"},
                "constraints": {},
                "caller": "capsule-smoke",
            },
        )
    return {"ok": isinstance(out, dict) and out.get("status") in ("OK", "DENY"), "response": out}


def main() -> None:
    report: Dict[str, Any] = {
        "direct_fs_read": _try_read(os.path.expanduser("~/.ssh/id_rsa")),
        "direct_internet": _try_internet("https://example.com/"),
        "gateway_http_act": _try_gateway_http(),
        "gateway_mcp_act": _try_gateway_mcp(),
    }
    sys.stdout.write(json.dumps(report, ensure_ascii=True, indent=2) + "\n")


if __name__ == "__main__":
    main()

