from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests


@dataclass(frozen=True, slots=True)
class ExecutorClient:
    base_url: str

    def send_message(
        self,
        *,
        action_id: str,
        channel: str,
        recipient: str,
        text: str,
        artifacts: list[dict[str, Any]],
        dlp_mode: str,
        evidence: dict[str, Any] | None = None,
        commit: dict[str, Any] | None = None,
        caller: str = "",
        session: str = "",
        user_confirm: bool = False,
        domain: str = "",
    ) -> Dict[str, Any]:
        payload = {
            "action_id": action_id,
            "channel": channel,
            "recipient": recipient,
            "domain": domain,
            "text": text,
            "artifacts": artifacts or [],
            "dlp_mode": dlp_mode,
            "evidence": evidence or {},
            "commit": commit or {},
            "caller": caller,
            "session": session,
            "user_confirm": bool(user_confirm),
        }
        r = requests.post(f"{self.base_url}/exec/send_message", json=payload, timeout=10)
        r.raise_for_status()
        return r.json()

    def fetch(
        self,
        *,
        action_id: str,
        resource_id: str,
        domain: str,
        evidence: dict[str, Any] | None = None,
        commit: dict[str, Any] | None = None,
        caller: str = "",
        session: str = "",
        user_confirm: bool = False,
        recipient: str = "",
        text: str = "",
    ) -> Dict[str, Any]:
        payload = {
            "action_id": action_id,
            "resource_id": resource_id,
            "domain": domain,
            "evidence": evidence or {},
            "commit": commit or {},
            "caller": caller,
            "session": session,
            "user_confirm": bool(user_confirm),
            "recipient": recipient,
            "text": text,
        }
        r = requests.post(f"{self.base_url}/exec/fetch", json=payload, timeout=10)
        r.raise_for_status()
        return r.json()

    def webhook(
        self,
        *,
        action_id: str,
        domain: str,
        path: str,
        body: str,
        evidence: dict[str, Any] | None = None,
        commit: dict[str, Any] | None = None,
        caller: str = "",
        session: str = "",
        user_confirm: bool = False,
        recipient: str = "",
        text: str = "",
    ) -> Dict[str, Any]:
        payload = {
            "action_id": action_id,
            "domain": domain,
            "path": path,
            "body": body,
            "evidence": evidence or {},
            "commit": commit or {},
            "caller": caller,
            "session": session,
            "user_confirm": bool(user_confirm),
            "recipient": recipient,
            "text": text,
        }
        r = requests.post(f"{self.base_url}/exec/webhook", json=payload, timeout=10)
        r.raise_for_status()
        return r.json()


def get_executor_client() -> Optional[ExecutorClient]:
    url = os.getenv("EXECUTOR_URL", "").strip()
    if not url:
        return None
    return ExecutorClient(base_url=url.rstrip("/"))
