from __future__ import annotations

import base64
import json
import math
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple
from concurrent.futures import ThreadPoolExecutor

import requests

from fss.dpf import gen_dpf_keys


def _domain_bits(domain_size: int) -> int:
    if domain_size <= 0 or (domain_size & (domain_size - 1)) != 0:
        raise ValueError("domain_size must be a power of two")
    return int(math.log2(domain_size))

_HTTP_POOL = ThreadPoolExecutor(max_workers=8)
_TRACE_LOCK = threading.Lock()


def _trace_pir(
    *,
    server_id: int,
    endpoint: str,
    db: str,
    n_keys: int,
    domain_size: int,
    action_id: str | None,
    block_size: int | None = None,
    signed: bool = False,
) -> None:
    """
    Optional "single policy server transcript" logging for leakage evaluation.

    This logs only metadata visible to the policy server (endpoint, db, batch size),
    not the PIR index itself.
    """
    path = (os.getenv("MIRAGE_TRANSCRIPT_PATH") or os.getenv("PIR_TRANSCRIPT_PATH") or "").strip()
    if not path:
        return
    ev = {
        "ts": int(time.time() * 1000),
        "server_id": int(server_id),
        "endpoint": str(endpoint),
        "db": str(db),
        "n_keys": int(n_keys),
        "domain_size": int(domain_size),
        "signed": bool(signed),
    }
    if action_id:
        ev["action_id"] = str(action_id)
    if block_size is not None:
        ev["block_size"] = int(block_size)
    line = json.dumps(ev, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    with _TRACE_LOCK:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


@dataclass(frozen=True, slots=True)
class PirClient:
    """
    2-server PIR client using efficient FSS (DPF).

    Communication:
    - client -> each server: O(log N) bytes per query key (DPF key)
    - server -> client: 1 bit share
    """

    policy0_url: str
    policy1_url: str
    domain_size: int

    def query_bit(self, db_name: str, idx: int, timeout_s: int = 10, *, domain_size: int | None = None) -> int:
        return self.query_bits(db_name, [idx], timeout_s=timeout_s, domain_size=domain_size)[0]

    def query_bits(self, db_name: str, idxs: Iterable[int], timeout_s: int = 10, *, domain_size: int | None = None) -> List[int]:
        idx_list = list(idxs)
        if not idx_list:
            return []

        ds = int(domain_size or self.domain_size)
        nbits = _domain_bits(ds)
        keys0: list[str] = []
        keys1: list[str] = []
        for idx in idx_list:
            if idx < 0 or idx >= ds:
                raise ValueError("idx out of range")
            k0, k1 = gen_dpf_keys(alpha=idx, beta=1, domain_bits=nbits)
            keys0.append(base64.b64encode(k0).decode("ascii"))
            keys1.append(base64.b64encode(k1).decode("ascii"))

        payload0 = {"db": db_name, "dpf_keys_b64": keys0}
        payload1 = {"db": db_name, "dpf_keys_b64": keys1}

        _trace_pir(server_id=0, endpoint="/pir/query_batch", db=db_name, n_keys=len(keys0), domain_size=ds, action_id=None, signed=False)
        _trace_pir(server_id=1, endpoint="/pir/query_batch", db=db_name, n_keys=len(keys1), domain_size=ds, action_id=None, signed=False)

        f0 = _HTTP_POOL.submit(requests.post, f"{self.policy0_url}/pir/query_batch", json=payload0, timeout=timeout_s)
        f1 = _HTTP_POOL.submit(requests.post, f"{self.policy1_url}/pir/query_batch", json=payload1, timeout=timeout_s)
        r0 = f0.result()
        r1 = f1.result()
        r0.raise_for_status()
        r1.raise_for_status()
        a0 = [int(x) & 1 for x in r0.json()["ans_shares"]]
        a1 = [int(x) & 1 for x in r1.json()["ans_shares"]]
        if len(a0) != len(idx_list) or len(a1) != len(idx_list):
            raise ValueError("policy server returned wrong batch size")
        return [(x ^ y) & 1 for x, y in zip(a0, a1)]

    def query_block(self, db_name: str, idx: int, *, block_size: int, timeout_s: int = 10, domain_size: int | None = None) -> bytes:
        return self.query_blocks(db_name, [idx], block_size=block_size, timeout_s=timeout_s, domain_size=domain_size)[0]

    def query_blocks(self, db_name: str, idxs: Iterable[int], *, block_size: int, timeout_s: int = 10, domain_size: int | None = None) -> List[bytes]:
        idx_list = list(idxs)
        if not idx_list:
            return []
        if block_size <= 0 or block_size > 4096:
            raise ValueError("bad block_size")

        ds = int(domain_size or self.domain_size)
        nbits = _domain_bits(ds)
        keys0: list[str] = []
        keys1: list[str] = []
        for idx in idx_list:
            if idx < 0 or idx >= ds:
                raise ValueError("idx out of range")
            k0, k1 = gen_dpf_keys(alpha=idx, beta=1, domain_bits=nbits)
            keys0.append(base64.b64encode(k0).decode("ascii"))
            keys1.append(base64.b64encode(k1).decode("ascii"))

        payload0 = {"db": db_name, "dpf_keys_b64": keys0}
        payload1 = {"db": db_name, "dpf_keys_b64": keys1}

        _trace_pir(server_id=0, endpoint="/pir/query_block_batch", db=db_name, n_keys=len(keys0), domain_size=ds, action_id=None, block_size=block_size, signed=False)
        _trace_pir(server_id=1, endpoint="/pir/query_block_batch", db=db_name, n_keys=len(keys1), domain_size=ds, action_id=None, block_size=block_size, signed=False)

        f0 = _HTTP_POOL.submit(requests.post, f"{self.policy0_url}/pir/query_block_batch", json=payload0, timeout=timeout_s)
        f1 = _HTTP_POOL.submit(requests.post, f"{self.policy1_url}/pir/query_block_batch", json=payload1, timeout=timeout_s)
        r0 = f0.result()
        r1 = f1.result()
        r0.raise_for_status()
        r1.raise_for_status()

        s0 = [base64.b64decode(x) for x in (r0.json().get("block_shares_b64") or [])]
        s1 = [base64.b64decode(x) for x in (r1.json().get("block_shares_b64") or [])]
        if len(s0) != len(idx_list) or len(s1) != len(idx_list):
            raise ValueError("policy server returned wrong batch size")
        out: list[bytes] = []
        for b0, b1 in zip(s0, s1):
            if len(b0) != block_size or len(b1) != block_size:
                raise ValueError("policy server returned wrong block size")
            out.append(bytes([x ^ y for x, y in zip(b0, b1)]))
        return out

    def query_bits_signed(self, db_name: str, idxs: Iterable[int], *, action_id: str, timeout_s: int = 10, domain_size: int | None = None) -> Tuple[List[int], Dict[str, Any]]:
        """
        Like query_bits, but also returns per-server MAC proofs so an executor can verify
        that both policy servers participated.
        """
        idx_list = list(idxs)
        if not idx_list:
            return [], {"policy0": None, "policy1": None}

        ds = int(domain_size or self.domain_size)
        nbits = _domain_bits(ds)
        keys0: list[str] = []
        keys1: list[str] = []
        for idx in idx_list:
            if idx < 0 or idx >= ds:
                raise ValueError("idx out of range")
            k0, k1 = gen_dpf_keys(alpha=idx, beta=1, domain_bits=nbits)
            keys0.append(base64.b64encode(k0).decode("ascii"))
            keys1.append(base64.b64encode(k1).decode("ascii"))

        payload0 = {"db": db_name, "dpf_keys_b64": keys0, "action_id": action_id}
        payload1 = {"db": db_name, "dpf_keys_b64": keys1, "action_id": action_id}

        _trace_pir(server_id=0, endpoint="/pir/query_batch_signed", db=db_name, n_keys=len(keys0), domain_size=ds, action_id=action_id, signed=True)
        _trace_pir(server_id=1, endpoint="/pir/query_batch_signed", db=db_name, n_keys=len(keys1), domain_size=ds, action_id=action_id, signed=True)

        f0 = _HTTP_POOL.submit(requests.post, f"{self.policy0_url}/pir/query_batch_signed", json=payload0, timeout=timeout_s)
        f1 = _HTTP_POOL.submit(requests.post, f"{self.policy1_url}/pir/query_batch_signed", json=payload1, timeout=timeout_s)
        r0 = f0.result()
        r1 = f1.result()
        r0.raise_for_status()
        r1.raise_for_status()
        j0 = r0.json()
        j1 = r1.json()

        a0 = [int(x) & 1 for x in j0.get("ans_shares", [])]
        a1 = [int(x) & 1 for x in j1.get("ans_shares", [])]
        if len(a0) != len(idx_list) or len(a1) != len(idx_list):
            raise ValueError("policy server returned wrong batch size")
        recon = [(x ^ y) & 1 for x, y in zip(a0, a1)]
        proof = {"policy0": j0.get("proof"), "policy1": j1.get("proof"), "a0": a0, "a1": a1, "db": db_name, "action_id": action_id}
        return recon, proof

    def query_blocks_signed(self, db_name: str, idxs: Iterable[int], *, block_size: int, action_id: str, timeout_s: int = 10, domain_size: int | None = None) -> Tuple[List[bytes], Dict[str, Any]]:
        idx_list = list(idxs)
        if not idx_list:
            return [], {"policy0": None, "policy1": None}
        if block_size <= 0 or block_size > 4096:
            raise ValueError("bad block_size")

        ds = int(domain_size or self.domain_size)
        nbits = _domain_bits(ds)
        keys0: list[str] = []
        keys1: list[str] = []
        for idx in idx_list:
            if idx < 0 or idx >= ds:
                raise ValueError("idx out of range")
            k0, k1 = gen_dpf_keys(alpha=idx, beta=1, domain_bits=nbits)
            keys0.append(base64.b64encode(k0).decode("ascii"))
            keys1.append(base64.b64encode(k1).decode("ascii"))

        payload0 = {"db": db_name, "dpf_keys_b64": keys0, "action_id": action_id}
        payload1 = {"db": db_name, "dpf_keys_b64": keys1, "action_id": action_id}

        _trace_pir(server_id=0, endpoint="/pir/query_block_batch_signed", db=db_name, n_keys=len(keys0), domain_size=ds, action_id=action_id, block_size=block_size, signed=True)
        _trace_pir(server_id=1, endpoint="/pir/query_block_batch_signed", db=db_name, n_keys=len(keys1), domain_size=ds, action_id=action_id, block_size=block_size, signed=True)

        f0 = _HTTP_POOL.submit(requests.post, f"{self.policy0_url}/pir/query_block_batch_signed", json=payload0, timeout=timeout_s)
        f1 = _HTTP_POOL.submit(requests.post, f"{self.policy1_url}/pir/query_block_batch_signed", json=payload1, timeout=timeout_s)
        r0 = f0.result()
        r1 = f1.result()
        r0.raise_for_status()
        r1.raise_for_status()
        j0 = r0.json()
        j1 = r1.json()
        s0 = [base64.b64decode(x) for x in (j0.get("block_shares_b64") or [])]
        s1 = [base64.b64decode(x) for x in (j1.get("block_shares_b64") or [])]
        if len(s0) != len(idx_list) or len(s1) != len(idx_list):
            raise ValueError("policy server returned wrong batch size")
        out: list[bytes] = []
        for b0, b1 in zip(s0, s1):
            if len(b0) != block_size or len(b1) != block_size:
                raise ValueError("policy server returned wrong block size")
            out.append(bytes([x ^ y for x, y in zip(b0, b1)]))
        proof = {"policy0": j0.get("proof"), "policy1": j1.get("proof"), "s0_b64": j0.get("block_shares_b64"), "s1_b64": j1.get("block_shares_b64"), "db": db_name, "action_id": action_id, "block_size": block_size}
        return out, proof
