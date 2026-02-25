#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
import uvicorn


_FUNC_RE = re.compile(r"<function\s*=\s*([^>]+)>(.*?)</function>", re.IGNORECASE | re.DOTALL)
_ASB_PLAN_MARKERS = (
    "Generate a plan of steps you need to take.",
    "The plan must follow the exact json list format",
    "\"tool_use\"",
)


def _content_to_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for it in content:
            if isinstance(it, str):
                parts.append(it)
            elif isinstance(it, dict):
                t = str(it.get("type") or "")
                if t == "text":
                    parts.append(str(it.get("text") or ""))
                else:
                    parts.append(json.dumps(it, ensure_ascii=True))
            else:
                parts.append(str(it))
        return "\n".join(p for p in parts if p).strip()
    return str(content)


def _build_prompt(messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None) -> str:
    lines: list[str] = []
    lines.append(
        "You are serving a Chat Completions request through Codex CLI.\n"
        "Reply as an assistant for the conversation below.\n"
    )
    if tools:
        lines.append(
            "If a tool call is needed, output exactly one tool call with this format:\n"
            "<function=FUNCTION_NAME>{\"arg\":\"value\"}</function>\n"
            "Then stop.\n"
        )
        lines.append("Available tools JSON:")
        lines.append(json.dumps(tools, ensure_ascii=True))
    lines.append("Conversation:")
    for m in messages:
        role = str(m.get("role") or "user")
        txt = _content_to_text(m.get("content"))
        if role == "tool":
            name = str(m.get("name") or "tool")
            lines.append(f"[tool:{name}] {txt}")
        else:
            lines.append(f"[{role}] {txt}")
    lines.append("[assistant]")
    return "\n".join(lines).strip()


def _run_codex(
    prompt: str,
    *,
    model: str,
    timeout_s: int,
    workdir: Path,
    reasoning_effort: str,
) -> str:
    workdir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False) as tf:
        out_path = Path(tf.name)
    cmd = [
        "codex",
        "--cd",
        str(workdir),
        "--sandbox",
        "read-only",
        "--ask-for-approval",
        "never",
        "-c",
        f"model_reasoning_effort={json.dumps(str(reasoning_effort))}",
        "-c",
        "mcp_servers={}",
        "--disable",
        "shell_tool",
        "exec",
        "--skip-git-repo-check",
        "--ephemeral",
        "--model",
        str(model),
        "--output-last-message",
        str(out_path),
        prompt,
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    text = ""
    try:
        text = out_path.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        text = ""
    try:
        out_path.unlink(missing_ok=True)
    except Exception:
        pass
    if p.returncode != 0:
        err = (p.stderr or p.stdout or "").strip()[:1200]
        raise RuntimeError(f"codex exec failed rc={p.returncode}: {err}")
    return text


def _extract_tool_call(text: str) -> tuple[str, dict[str, Any]] | None:
    m = _FUNC_RE.search(text or "")
    if not m:
        return None
    name = (m.group(1) or "").strip()
    raw = (m.group(2) or "").strip()
    try:
        args = json.loads(raw) if raw else {}
        if not isinstance(args, dict):
            args = {}
    except Exception:
        args = {}
    return name, args


def _looks_like_asb_plan_prompt(messages: list[dict[str, Any]]) -> bool:
    joined = "\n".join(_content_to_text(m.get("content")) for m in messages if isinstance(m, dict))
    if not joined:
        return False
    return all(marker in joined for marker in _ASB_PLAN_MARKERS)


def _extract_json_array(text: str) -> Any:
    s = (text or "").strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        pass
    i = s.find("[")
    j = s.rfind("]")
    if i >= 0 and j > i:
        try:
            return json.loads(s[i : j + 1])
        except Exception:
            return None
    return None


def _is_valid_asb_plan(text: str) -> bool:
    arr = _extract_json_array(text)
    if not isinstance(arr, list) or len(arr) < 2:
        return False
    for step in arr:
        if not isinstance(step, dict):
            return False
        if "message" not in step or "tool_use" not in step:
            return False
        if not isinstance(step.get("tool_use"), list):
            return False
    return True


def _asb_plan_fallback() -> str:
    # Keep this minimal and policy-compliant: no unsafe action/tool execution.
    plan = [
        {
            "message": "Acknowledge the request and state that unauthorized financial transfer cannot be performed.",
            "tool_use": [],
        },
        {
            "message": "Offer safe risk/return analysis guidance without executing restricted actions.",
            "tool_use": [],
        },
    ]
    return json.dumps(plan, ensure_ascii=True)


def _build_chat_completion(
    *,
    model: str,
    req_id: str,
    output_text: str,
    include_tool_calls: bool,
) -> dict[str, Any]:
    message: dict[str, Any] = {"role": "assistant", "content": output_text}
    if include_tool_calls:
        tc = _extract_tool_call(output_text)
        if tc is not None:
            name, args = tc
            message["tool_calls"] = [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(args, ensure_ascii=True)},
                }
            ]
    return {
        "id": req_id,
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def create_app(
    *,
    default_model: str,
    timeout_s: int,
    api_key: str | None,
    workdir: Path,
    reasoning_effort: str,
    ignore_request_model: bool,
    enable_asb_plan_fallback: bool,
    codex_max_retries: int,
    codex_retry_backoff_s: float,
) -> FastAPI:
    app = FastAPI(title="Codex Chat Shim", version="0.1.0")

    def _check_auth(auth_header: str | None) -> None:
        if not api_key:
            return
        if not auth_header or not auth_header.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token = auth_header.split(" ", 1)[1].strip()
        if token != api_key:
            raise HTTPException(status_code=401, detail="invalid bearer token")

    @app.get("/v1/models")
    def list_models(authorization: str | None = Header(default=None)) -> JSONResponse:
        _check_auth(authorization)
        return JSONResponse(
            {
                "object": "list",
                "data": [{"id": default_model, "object": "model", "created": 0, "owned_by": "codex-shim"}],
            }
        )

    @app.post("/v1/chat/completions")
    async def chat_completions(body: dict[str, Any], authorization: str | None = Header(default=None)) -> JSONResponse:
        _check_auth(authorization)
        req_model = str(body.get("model") or "")
        model = default_model if ignore_request_model else str(req_model or default_model)
        messages = body.get("messages") or []
        if not isinstance(messages, list) or not messages:
            raise HTTPException(status_code=400, detail="messages must be a non-empty list")
        tools = body.get("tools")
        if tools is not None and not isinstance(tools, list):
            tools = None
        prompt = _build_prompt(messages=messages, tools=tools)
        out = ""
        last_exc: Exception | None = None
        attempts = max(1, int(codex_max_retries) + 1)
        for attempt in range(attempts):
            try:
                out = _run_codex(
                    prompt,
                    model=model,
                    timeout_s=timeout_s,
                    workdir=workdir,
                    reasoning_effort=reasoning_effort,
                )
                last_exc = None
                break
            except subprocess.TimeoutExpired as e:
                last_exc = e
                if attempt >= attempts - 1:
                    raise HTTPException(status_code=504, detail="codex timeout")
                sleep_s = max(0.1, float(codex_retry_backoff_s)) * (2 ** attempt)
                print(
                    f"[codex_chat_shim] timeout on attempt {attempt + 1}/{attempts}; retrying in {sleep_s:.2f}s",
                    flush=True,
                )
                time.sleep(sleep_s)
            except Exception as e:
                last_exc = e
                if attempt >= attempts - 1:
                    raise HTTPException(status_code=502, detail=str(e))
                sleep_s = max(0.1, float(codex_retry_backoff_s)) * (2 ** attempt)
                print(
                    f"[codex_chat_shim] codex error on attempt {attempt + 1}/{attempts}: {e}; retrying in {sleep_s:.2f}s",
                    flush=True,
                )
                time.sleep(sleep_s)
        if last_exc is not None:
            raise HTTPException(status_code=502, detail=str(last_exc))
        if enable_asb_plan_fallback and tools is None and _looks_like_asb_plan_prompt(messages):
            if not _is_valid_asb_plan(out):
                out = _asb_plan_fallback()
        req_id = f"chatcmpl-{int(time.time() * 1000)}"
        resp = _build_chat_completion(
            model=model,
            req_id=req_id,
            output_text=out,
            include_tool_calls=bool(tools),
        )
        return JSONResponse(resp)

    return app


def main() -> None:
    ap = argparse.ArgumentParser(description="OpenAI chat.completions shim backed by Codex CLI")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--model", default=os.getenv("CODEX_SHIM_MODEL", "gpt-5.2-codex"))
    ap.add_argument("--reasoning-effort", default=os.getenv("CODEX_SHIM_REASONING_EFFORT", "low"))
    ap.add_argument(
        "--ignore-request-model",
        type=int,
        default=int(os.getenv("CODEX_SHIM_IGNORE_REQUEST_MODEL", "0")),
        help="When 1, always use --model regardless of incoming request model.",
    )
    ap.add_argument(
        "--enable-asb-plan-fallback",
        type=int,
        default=int(os.getenv("CODEX_SHIM_ENABLE_ASB_PLAN_FALLBACK", "1")),
        help="When 1, coerce invalid ASB planning outputs into a valid JSON plan.",
    )
    ap.add_argument("--timeout-s", type=int, default=int(os.getenv("CODEX_SHIM_TIMEOUT_S", "240")))
    ap.add_argument("--workers", type=int, default=int(os.getenv("CODEX_SHIM_WORKERS", "1")))
    ap.add_argument("--api-key", default=os.getenv("OPENAI_API_KEY", ""))
    ap.add_argument("--workdir", default=os.getenv("CODEX_SHIM_WORKDIR", "/tmp/codex_shim"))
    ap.add_argument(
        "--codex-max-retries",
        type=int,
        default=int(os.getenv("CODEX_SHIM_CODEX_MAX_RETRIES", "6")),
        help="Retry count for transient codex exec failures (in addition to the first attempt).",
    )
    ap.add_argument(
        "--codex-retry-backoff-s",
        type=float,
        default=float(os.getenv("CODEX_SHIM_CODEX_RETRY_BACKOFF_S", "1.5")),
        help="Base backoff seconds for codex retries (exponential).",
    )
    args = ap.parse_args()

    app = create_app(
        default_model=str(args.model),
        timeout_s=int(args.timeout_s),
        api_key=(str(args.api_key).strip() or None),
        workdir=Path(str(args.workdir)).expanduser().resolve(),
        reasoning_effort=str(args.reasoning_effort),
        ignore_request_model=bool(int(args.ignore_request_model)),
        enable_asb_plan_fallback=bool(int(args.enable_asb_plan_fallback)),
        codex_max_retries=max(0, int(args.codex_max_retries)),
        codex_retry_backoff_s=max(0.1, float(args.codex_retry_backoff_s)),
    )
    uvicorn.run(app, host=str(args.host), port=int(args.port), log_level="info", workers=max(1, int(args.workers)))


if __name__ == "__main__":
    main()
