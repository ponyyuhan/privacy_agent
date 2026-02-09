from __future__ import annotations

import os
from typing import Any, Dict

import uvicorn
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, ValidationError

from .config import settings
from .fss_pir import PirClient
from .guardrails import ObliviousGuardrails
from .handles import HandleStore
from .router import IntentRouter


class ActArgs(BaseModel):
    intent_id: str = Field(..., description="High-level intent ID (no low-level tools).")
    inputs: Dict[str, Any] = Field(default_factory=dict)
    constraints: Dict[str, Any] = Field(default_factory=dict)
    caller: str = Field(..., description="Skill/agent identity (untrusted).")


def _require_bearer_token(authorization: str | None) -> None:
    """
    Optional HTTP auth layer for the capsule transport.

    If MIRAGE_HTTP_TOKEN is set, requests must include:
      Authorization: Bearer <token>
    """

    token = (os.getenv("MIRAGE_HTTP_TOKEN") or "").strip()
    if not token:
        return
    if not authorization or authorization.strip() != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="missing/invalid bearer token")


def _resolve_session(x_mirage_session: str | None) -> str:
    # Session binding is enforced inside the gateway (trusted side) so sealed handles
    # are useless outside the issuing session.
    # For capsule use-cases, the proxy sets X-Mirage-Session.
    return (x_mirage_session or os.getenv("MIRAGE_SESSION_ID") or "demo-session").strip() or "demo-session"


app = FastAPI(title="MIRAGE Gateway (HTTP)", version="0.1")

_handles = HandleStore()
_pir = PirClient(
    policy0_url=settings.policy_servers[0],
    policy1_url=settings.policy_servers[1],
    domain_size=settings.fss_domain_size,
)
_guardrails = ObliviousGuardrails(
    pir=_pir,
    handles=_handles,
    domain_size=settings.fss_domain_size,
    max_tokens=settings.max_tokens_per_message,
)
_router = IntentRouter(handles=_handles, guardrails=_guardrails)


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True}


@app.post("/act")
def act(
    payload: dict[str, Any],
    authorization: str | None = Header(default=None),
    x_mirage_session: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_bearer_token(authorization)
    session = _resolve_session(x_mirage_session)

    try:
        act_args = ActArgs.model_validate(payload)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail={"error": "bad arguments", "details": e.errors()})

    obs = _router.act(
        act_args.intent_id,
        act_args.inputs,
        act_args.constraints,
        caller=act_args.caller,
        session=session,
    )
    return obs


def main() -> None:
    host = (os.getenv("MIRAGE_HTTP_BIND") or "127.0.0.1").strip() or "127.0.0.1"
    port = int(os.getenv("MIRAGE_HTTP_PORT") or os.getenv("PORT") or "8765")
    uvicorn.run(app, host=host, port=port, log_level=os.getenv("LOG_LEVEL", "info"))


if __name__ == "__main__":
    main()

