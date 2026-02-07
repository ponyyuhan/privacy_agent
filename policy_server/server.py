import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI
from pydantic import BaseModel, Field
from pathlib import Path
import os
import json
import base64
import hashlib
import hmac
import time
from .config import settings
from .db import BitsetDB

db = BitsetDB(settings.data_dir)

@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.load()
    yield

app = FastAPI(title=f"PolicyServer{settings.server_id}", version="0.1", lifespan=lifespan)

class PirQuery(BaseModel):
    db: str
    dpf_key_b64: str = Field(..., description="DPF/FSS key share (base64).")


class PirQueryBatch(BaseModel):
    db: str
    dpf_keys_b64: list[str]


class PirQueryBatchSigned(PirQueryBatch):
    action_id: str = Field(..., description="Opaque action identifier (bound into the MAC).")

@app.get("/health")
def health():
    return {"ok": True, "server_id": settings.server_id}

@app.get("/meta")
def meta():
    data_dir = Path(settings.data_dir)
    out: dict = {}
    p = data_dir / "meta.json"
    if p.exists():
        try:
            out.update(json.loads(p.read_text()))
        except Exception:
            out["meta_error"] = "failed_to_parse_meta_json"
    a = data_dir / "dfa_alphabet.json"
    if a.exists():
        try:
            out["dfa_alphabet"] = json.loads(a.read_text())
        except Exception:
            out["dfa_alphabet_error"] = "failed_to_parse_dfa_alphabet_json"
    return out

@app.post("/pir/query")
def pir_query(q: PirQuery):
    ans = db.query_one(q.db, q.dpf_key_b64, party=settings.server_id)
    return {"ans_share": ans}


@app.post("/pir/query_batch")
def pir_query_batch(q: PirQueryBatch):
    ans = db.query_batch(q.db, q.dpf_keys_b64, party=settings.server_id)
    return {"ans_shares": ans}


@app.post("/pir/query_block_batch")
def pir_query_block_batch(q: PirQueryBatch):
    blocks_b64 = db.query_block_batch(q.db, q.dpf_keys_b64, party=settings.server_id)
    return {"block_shares_b64": blocks_b64}


def _require_mac_key() -> bytes:
    kid, key = _active_mac_key()
    if not key:
        raise RuntimeError("POLICY_MAC_KEY not configured")
    return key


_MAC_KEYS = None
_ACTIVE_KID = None


def _parse_mac_keys(s: str) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for part in (s or "").split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            kid, hexkey = part.split(":", 1)
        else:
            kid, hexkey = "0", part
        kid = kid.strip() or "0"
        hexkey = hexkey.strip()
        if not hexkey:
            continue
        out[kid] = bytes.fromhex(hexkey)
    return out


def _active_mac_key() -> tuple[str, bytes]:
    global _MAC_KEYS, _ACTIVE_KID
    if _MAC_KEYS is None:
        s = os.getenv("POLICY_MAC_KEYS", "").strip()
        if s:
            _MAC_KEYS = _parse_mac_keys(s)
        elif settings.mac_key_hex:
            _MAC_KEYS = {"0": bytes.fromhex(settings.mac_key_hex)}
        else:
            _MAC_KEYS = {}
        _ACTIVE_KID = (os.getenv("POLICY_MAC_ACTIVE_KID", "").strip() or (next(iter(_MAC_KEYS.keys()), "0")))
    kid = str(_ACTIVE_KID or "0")
    key = _MAC_KEYS.get(kid) or b""
    return kid, key


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _mac_b64(key: bytes, payload: dict) -> str:
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    mac = hmac.new(key, msg, hashlib.sha256).digest()
    return base64.b64encode(mac).decode("ascii")


@app.post("/pir/query_batch_signed")
def pir_query_batch_signed(q: PirQueryBatchSigned):
    kid, key = _active_mac_key()
    if not key:
        raise RuntimeError("POLICY_MAC_KEY not configured")
    ts = int(time.time())
    ans = db.query_batch(q.db, q.dpf_keys_b64, party=settings.server_id)

    keys_concat = b"".join(base64.b64decode(k) for k in q.dpf_keys_b64)
    keys_sha256 = _sha256_hex(keys_concat)
    resp_bytes = bytes([int(x) & 1 for x in ans])
    resp_sha256 = _sha256_hex(resp_bytes)

    payload = {
        "v": 1,
        "kind": "bit",
        "server_id": int(settings.server_id),
        "kid": str(kid),
        "ts": ts,
        "action_id": str(q.action_id),
        "db": str(q.db),
        "keys_sha256": keys_sha256,
        "resp_sha256": resp_sha256,
    }
    return {
        "ans_shares": ans,
        "proof": {
            **payload,
            "mac_b64": _mac_b64(key, payload),
        },
    }


@app.post("/pir/query_block_batch_signed")
def pir_query_block_batch_signed(q: PirQueryBatchSigned):
    kid, key = _active_mac_key()
    if not key:
        raise RuntimeError("POLICY_MAC_KEY not configured")
    ts = int(time.time())
    blocks_b64 = db.query_block_batch(q.db, q.dpf_keys_b64, party=settings.server_id)

    keys_concat = b"".join(base64.b64decode(k) for k in q.dpf_keys_b64)
    keys_sha256 = _sha256_hex(keys_concat)
    resp_concat = b"".join(base64.b64decode(b) for b in blocks_b64)
    resp_sha256 = _sha256_hex(resp_concat)

    payload = {
        "v": 1,
        "kind": "block",
        "server_id": int(settings.server_id),
        "kid": str(kid),
        "ts": ts,
        "action_id": str(q.action_id),
        "db": str(q.db),
        "keys_sha256": keys_sha256,
        "resp_sha256": resp_sha256,
    }
    return {
        "block_shares_b64": blocks_b64,
        "proof": {
            **payload,
            "mac_b64": _mac_b64(key, payload),
        },
    }

def main():
    access_log = bool(int(os.getenv("ACCESS_LOG", "0")))
    uvicorn.run("policy_server.server:app", host="0.0.0.0", port=settings.port, reload=False, access_log=access_log)

if __name__ == "__main__":
    main()
