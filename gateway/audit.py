from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


def _default_audit_path() -> str:
    # Keep artifacts out of the repo by default.
    return str(Path(__file__).resolve().parents[1] / "artifact_out" / "audit.jsonl")


@dataclass(frozen=True, slots=True)
class AuditEvent:
    ts: int
    event: str
    session: str
    caller: str
    intent_id: str
    action_id: str = ""
    status: str = ""
    reason_code: str = ""
    data: Dict[str, Any] | None = None

    def to_dict(self) -> Dict[str, Any]:
        out = {
            "ts": int(self.ts),
            "event": str(self.event),
            "session": str(self.session),
            "caller": str(self.caller),
            "intent_id": str(self.intent_id),
        }
        if self.action_id:
            out["action_id"] = str(self.action_id)
        if self.status:
            out["status"] = str(self.status)
        if self.reason_code:
            out["reason_code"] = str(self.reason_code)
        if self.data is not None:
            out["data"] = self.data
        return out


class AuditLogger:
    def __init__(self, path: str):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log(self, ev: AuditEvent) -> None:
        line = json.dumps(ev.to_dict(), ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")


_LOGGER: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    global _LOGGER
    if _LOGGER is not None:
        return _LOGGER
    path = os.getenv("AUDIT_LOG_PATH", "").strip() or _default_audit_path()
    _LOGGER = AuditLogger(path)
    return _LOGGER


def now_ts() -> int:
    return int(time.time())

