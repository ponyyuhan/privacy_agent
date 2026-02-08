from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Set
import os

import yaml


@dataclass(frozen=True, slots=True)
class Capabilities:
    allowed_intents: Set[str]
    egress: Dict[str, bool]

    def allow_intent(self, intent_id: str) -> bool:
        return str(intent_id) in self.allowed_intents

    def egress_ok(self, *, kind: str) -> bool:
        # kind: "send_message" | "fetch_resource" | "post_webhook"
        return bool(self.egress.get(str(kind), False))


_CACHE: Optional[Dict[str, Any]] = None


def _load_cfg() -> Dict[str, Any]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    p = os.getenv("CAPABILITIES_PATH", "").strip()
    if not p:
        p = str(Path(__file__).resolve().parent / "capabilities.yaml")
    try:
        _CACHE = yaml.safe_load(Path(p).read_text(encoding="utf-8")) or {}
    except Exception:
        _CACHE = {}
    if not isinstance(_CACHE, dict):
        _CACHE = {}
    return _CACHE


def get_capabilities(caller: str) -> Capabilities:
    cfg = _load_cfg()
    default = cfg.get("default") if isinstance(cfg.get("default"), dict) else {}
    callers = cfg.get("callers") if isinstance(cfg.get("callers"), dict) else {}
    c = callers.get(str(caller)) if isinstance(callers, dict) else None
    if not isinstance(c, dict):
        c = {}

    allow_intents = c.get("allow_intents", default.get("allow_intents", []))
    if not isinstance(allow_intents, list):
        allow_intents = []
    allowed_set = set(str(x) for x in allow_intents if x)

    egress0 = default.get("egress") if isinstance(default.get("egress"), dict) else {}
    egress1 = c.get("egress") if isinstance(c.get("egress"), dict) else {}
    egress: Dict[str, bool] = {}
    for k, v in dict(egress0).items():
        egress[str(k)] = bool(v)
    for k, v in dict(egress1).items():
        egress[str(k)] = bool(v)

    return Capabilities(allowed_intents=allowed_set, egress=egress)

