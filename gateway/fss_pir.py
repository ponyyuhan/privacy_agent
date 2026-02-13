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
from concurrent.futures import Future

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
    n_subreq: int | None = None,
    keys_per_subreq: int | None = None,
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
    if n_subreq is not None:
        ev["n_subreq"] = int(n_subreq)
    if keys_per_subreq is not None:
        ev["keys_per_subreq"] = int(keys_per_subreq)
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

    def query_bits_single_server_cleartext(
        self,
        db_name: str,
        idxs: Iterable[int],
        *,
        server_id: int = 0,
        timeout_s: int = 10,
        domain_size: int | None = None,
    ) -> list[int]:
        """
        Baseline-only single-server cleartext query.

        WARNING: this leaks plaintext indices to one policy server and should never
        be used in the full MIRAGE mode.
        """
        idx_list = [int(x) for x in idxs]
        if not idx_list:
            return []
        ds = int(domain_size or self.domain_size)
        for idx in idx_list:
            if idx < 0 or idx >= ds:
                raise ValueError("idx out of range")
        url = self.policy0_url if int(server_id) == 0 else self.policy1_url
        _trace_pir(
            server_id=int(server_id),
            endpoint="/pir/query_idx_batch",
            db=db_name,
            n_keys=len(idx_list),
            domain_size=ds,
            action_id=None,
            signed=False,
        )
        r = requests.post(
            f"{url}/pir/query_idx_batch",
            json={"db": db_name, "idxs": idx_list},
            timeout=timeout_s,
        )
        r.raise_for_status()
        bits = [int(x) & 1 for x in (r.json().get("ans_bits") or [])]
        if len(bits) != len(idx_list):
            raise ValueError("policy server returned wrong batch size")
        return bits

    def query_bits_single_server_cleartext_signed(
        self,
        db_name: str,
        idxs: Iterable[int],
        *,
        action_id: str,
        server_id: int = 0,
        timeout_s: int = 10,
        domain_size: int | None = None,
    ) -> tuple[list[int], dict[str, Any]]:
        """
        Signed variant of the single-server cleartext baseline query.
        """
        idx_list = [int(x) for x in idxs]
        if not idx_list:
            return [], {"policy0": None, "policy1": None}
        ds = int(domain_size or self.domain_size)
        for idx in idx_list:
            if idx < 0 or idx >= ds:
                raise ValueError("idx out of range")
        url = self.policy0_url if int(server_id) == 0 else self.policy1_url
        sid = int(server_id)
        _trace_pir(
            server_id=sid,
            endpoint="/pir/query_idx_batch_signed",
            db=db_name,
            n_keys=len(idx_list),
            domain_size=ds,
            action_id=action_id,
            signed=True,
        )
        r = requests.post(
            f"{url}/pir/query_idx_batch_signed",
            json={"db": db_name, "idxs": idx_list, "action_id": str(action_id)},
            timeout=timeout_s,
        )
        r.raise_for_status()
        j = r.json()
        bits = [int(x) & 1 for x in (j.get("ans_bits") or [])]
        if len(bits) != len(idx_list):
            raise ValueError("policy server returned wrong batch size")
        zeros = [0 for _ in bits]
        if sid == 0:
            proof = {
                "policy0": j.get("proof"),
                "policy1": None,
                "a0": bits,
                "a1": zeros,
                "db": db_name,
                "action_id": action_id,
                "baseline_mode": "single_server_cleartext",
            }
        else:
            proof = {
                "policy0": None,
                "policy1": j.get("proof"),
                "a0": zeros,
                "a1": bits,
                "db": db_name,
                "action_id": action_id,
                "baseline_mode": "single_server_cleartext",
            }
        return bits, proof


@dataclass(frozen=True, slots=True)
class PirMixConfig:
    """
    Gateway-side PIR microbatching / cover-traffic configuration.

    The mixer is intentionally narrow: it batches *signed bitset* PIR queries
    (`/pir/query_batch_multi_signed`) for a single `db_name` with a fixed
    number of keys per subrequest (constant-shape).
    """

    enabled: bool
    interval_ms: int
    pad_to: int
    fixed_n_keys: int
    db_name: str
    domain_size: int
    timeout_s: int = 10
    cover_traffic: bool = True


class _SignedBitBatchMixer:
    def __init__(self, *, policy0_url: str, policy1_url: str, cfg: PirMixConfig) -> None:
        self.policy0_url = str(policy0_url)
        self.policy1_url = str(policy1_url)
        self.cfg = cfg
        self._lock = threading.Lock()
        self._pending: list[tuple[str, list[str], list[str], Future]] = []
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, name="pir-mixer", daemon=True)
        self._t.start()

    def close(self) -> None:
        self._stop.set()
        try:
            self._t.join(timeout=1.0)
        except Exception:
            pass

    def submit(self, *, action_id: str, keys0_b64: list[str], keys1_b64: list[str]) -> Future:
        fut: Future = Future()
        if len(keys0_b64) != len(keys1_b64):
            fut.set_exception(ValueError("bad_key_share_lengths"))
            return fut
        if int(len(keys0_b64)) != int(self.cfg.fixed_n_keys):
            fut.set_exception(ValueError("bad_fixed_shape_n_keys"))
            return fut
        with self._lock:
            self._pending.append((str(action_id), list(keys0_b64), list(keys1_b64), fut))
        return fut

    def _mk_dummy_req(self) -> tuple[str, list[str], list[str]]:
        # Dummy subrequest: random action_id + random index keys. Indistinguishable
        # from real subrequests under DPF security (keys hide indices).
        action_id = f"cov_{int(time.time()*1000)}_{os.urandom(4).hex()}"
        ds = int(self.cfg.domain_size)
        nbits = _domain_bits(ds)
        keys0: list[str] = []
        keys1: list[str] = []
        for _ in range(int(self.cfg.fixed_n_keys)):
            idx = int.from_bytes(os.urandom(4), "little") % ds
            k0, k1 = gen_dpf_keys(alpha=idx, beta=1, domain_bits=nbits)
            keys0.append(base64.b64encode(k0).decode("ascii"))
            keys1.append(base64.b64encode(k1).decode("ascii"))
        return action_id, keys0, keys1

    def _flush_once(self) -> None:
        cfg = self.cfg
        batch: list[tuple[str, list[str], list[str], Future]] = []
        with self._lock:
            if self._pending:
                take = min(int(cfg.pad_to), len(self._pending))
                batch = self._pending[:take]
                self._pending = self._pending[take:]

        # If there are no real subrequests, still emit cover traffic if enabled.
        if not batch and not bool(cfg.cover_traffic):
            return

        # Pad with dummy subrequests up to pad_to.
        pad_to = int(cfg.pad_to)
        req0: list[dict[str, Any]] = []
        req1: list[dict[str, Any]] = []

        real_action_ids: set[str] = set()
        for action_id, k0s, k1s, _f in batch:
            real_action_ids.add(str(action_id))
            req0.append({"action_id": str(action_id), "dpf_keys_b64": list(k0s)})
            req1.append({"action_id": str(action_id), "dpf_keys_b64": list(k1s)})
        while len(req0) < pad_to:
            aid, k0s, k1s = self._mk_dummy_req()
            req0.append({"action_id": aid, "dpf_keys_b64": k0s})
            req1.append({"action_id": aid, "dpf_keys_b64": k1s})

        payload0 = {"db": str(cfg.db_name), "requests": req0}
        payload1 = {"db": str(cfg.db_name), "requests": req1}

        total_keys = int(len(req0)) * int(cfg.fixed_n_keys)
        _trace_pir(
            server_id=0,
            endpoint="/pir/query_batch_multi_signed",
            db=str(cfg.db_name),
            n_keys=total_keys,
            domain_size=int(cfg.domain_size),
            action_id=None,
            signed=True,
            n_subreq=int(len(req0)),
            keys_per_subreq=int(cfg.fixed_n_keys),
        )
        _trace_pir(
            server_id=1,
            endpoint="/pir/query_batch_multi_signed",
            db=str(cfg.db_name),
            n_keys=total_keys,
            domain_size=int(cfg.domain_size),
            action_id=None,
            signed=True,
            n_subreq=int(len(req0)),
            keys_per_subreq=int(cfg.fixed_n_keys),
        )

        try:
            f0 = _HTTP_POOL.submit(
                requests.post,
                f"{self.policy0_url}/pir/query_batch_multi_signed",
                json=payload0,
                timeout=int(cfg.timeout_s),
            )
            f1 = _HTTP_POOL.submit(
                requests.post,
                f"{self.policy1_url}/pir/query_batch_multi_signed",
                json=payload1,
                timeout=int(cfg.timeout_s),
            )
            r0 = f0.result()
            r1 = f1.result()
            r0.raise_for_status()
            r1.raise_for_status()
            j0 = r0.json()
            j1 = r1.json()
        except Exception as e:
            # Fail all *real* futures in this flush.
            for _aid, _k0, _k1, fut in batch:
                try:
                    fut.set_exception(e)
                except Exception:
                    pass
            return

        # Build action_id -> (ans_shares, proof)
        m0: dict[str, tuple[list[int], dict[str, Any]]] = {}
        m1: dict[str, tuple[list[int], dict[str, Any]]] = {}
        for it in (j0.get("responses") or []):
            if not isinstance(it, dict):
                continue
            aid = str(it.get("action_id") or "")
            if not aid:
                continue
            a = [int(x) & 1 for x in (it.get("ans_shares") or [])]
            pr = it.get("proof")
            m0[aid] = (a, pr if isinstance(pr, dict) else {})
        for it in (j1.get("responses") or []):
            if not isinstance(it, dict):
                continue
            aid = str(it.get("action_id") or "")
            if not aid:
                continue
            a = [int(x) & 1 for x in (it.get("ans_shares") or [])]
            pr = it.get("proof")
            m1[aid] = (a, pr if isinstance(pr, dict) else {})

        for aid, _k0, _k1, fut in batch:
            try:
                a0, p0 = m0.get(str(aid), (None, None))  # type: ignore[assignment]
                a1, p1 = m1.get(str(aid), (None, None))  # type: ignore[assignment]
                if not isinstance(a0, list) or not isinstance(a1, list) or len(a0) != len(a1):
                    raise ValueError("bad_policy_server_batch_response")
                recon = [(int(x) ^ int(y)) & 1 for x, y in zip(a0, a1)]
                ev = {
                    "policy0": p0,
                    "policy1": p1,
                    "a0": a0,
                    "a1": a1,
                    "db": str(cfg.db_name),
                    "action_id": str(aid),
                    "mixed": True,
                }
                fut.set_result((recon, ev))
            except Exception as e:
                try:
                    fut.set_exception(e)
                except Exception:
                    pass

    def _run(self) -> None:
        interval_s = max(0.001, float(self.cfg.interval_ms) / 1000.0)
        while not self._stop.is_set():
            t0 = time.perf_counter()
            self._flush_once()
            dt = time.perf_counter() - t0
            sleep_s = interval_s - dt
            if sleep_s > 0:
                self._stop.wait(timeout=sleep_s)


class MixedPirClient:
    """
    PirClient wrapper that optionally enables cover-traffic + microbatch mixing for
    signed bitset queries.
    """

    def __init__(self, base: PirClient, *, mix: PirMixConfig | None = None) -> None:
        self._base = base
        self.domain_size = int(base.domain_size)
        self._mix_cfg = mix
        self._mixer: _SignedBitBatchMixer | None = None
        if mix and mix.enabled:
            self._mixer = _SignedBitBatchMixer(policy0_url=base.policy0_url, policy1_url=base.policy1_url, cfg=mix)

    @property
    def policy0_url(self) -> str:
        return self._base.policy0_url

    @property
    def policy1_url(self) -> str:
        return self._base.policy1_url

    def close(self) -> None:
        if self._mixer:
            self._mixer.close()

    # Delegate non-mixed APIs.
    def query_bit(self, db_name: str, idx: int, timeout_s: int = 10, *, domain_size: int | None = None) -> int:
        return self._base.query_bit(db_name, idx, timeout_s=timeout_s, domain_size=domain_size)

    def query_bits(self, db_name: str, idxs: Iterable[int], timeout_s: int = 10, *, domain_size: int | None = None) -> List[int]:
        return self._base.query_bits(db_name, idxs, timeout_s=timeout_s, domain_size=domain_size)

    def query_block(self, db_name: str, idx: int, *, block_size: int, timeout_s: int = 10, domain_size: int | None = None) -> bytes:
        return self._base.query_block(db_name, idx, block_size=block_size, timeout_s=timeout_s, domain_size=domain_size)

    def query_blocks(self, db_name: str, idxs: Iterable[int], *, block_size: int, timeout_s: int = 10, domain_size: int | None = None) -> List[bytes]:
        return self._base.query_blocks(db_name, idxs, block_size=block_size, timeout_s=timeout_s, domain_size=domain_size)

    def query_blocks_signed(
        self,
        db_name: str,
        idxs: Iterable[int],
        *,
        block_size: int,
        action_id: str,
        timeout_s: int = 10,
        domain_size: int | None = None,
    ) -> Tuple[List[bytes], Dict[str, Any]]:
        return self._base.query_blocks_signed(db_name, idxs, block_size=block_size, action_id=action_id, timeout_s=timeout_s, domain_size=domain_size)

    def query_bits_single_server_cleartext_signed(
        self,
        db_name: str,
        idxs: Iterable[int],
        *,
        action_id: str,
        server_id: int = 0,
        timeout_s: int = 10,
        domain_size: int | None = None,
    ) -> tuple[list[int], dict[str, Any]]:
        return self._base.query_bits_single_server_cleartext_signed(
            db_name,
            idxs,
            action_id=action_id,
            server_id=server_id,
            timeout_s=timeout_s,
            domain_size=domain_size,
        )

    def query_bits_signed(
        self,
        db_name: str,
        idxs: Iterable[int],
        *,
        action_id: str,
        timeout_s: int = 10,
        domain_size: int | None = None,
    ) -> Tuple[List[int], Dict[str, Any]]:
        # If mixing isn't enabled (or db doesn't match), fall back to direct.
        mix = self._mix_cfg
        if not self._mixer or not mix or not mix.enabled:
            return self._base.query_bits_signed(db_name, idxs, action_id=action_id, timeout_s=timeout_s, domain_size=domain_size)
        if str(db_name) != str(mix.db_name):
            return self._base.query_bits_signed(db_name, idxs, action_id=action_id, timeout_s=timeout_s, domain_size=domain_size)

        idx_list = list(idxs)
        if not idx_list:
            return [], {"policy0": None, "policy1": None}
        ds = int(domain_size or mix.domain_size)
        if int(ds) != int(mix.domain_size):
            raise ValueError("mixed_pir_domain_size_mismatch")
        nbits = _domain_bits(ds)
        keys0: list[str] = []
        keys1: list[str] = []
        for idx in idx_list:
            if idx < 0 or idx >= ds:
                raise ValueError("idx out of range")
            k0, k1 = gen_dpf_keys(alpha=int(idx), beta=1, domain_bits=nbits)
            keys0.append(base64.b64encode(k0).decode("ascii"))
            keys1.append(base64.b64encode(k1).decode("ascii"))

        fut = self._mixer.submit(action_id=str(action_id), keys0_b64=keys0, keys1_b64=keys1)
        recon, ev = fut.result(timeout=max(1.0, float(timeout_s) + 5.0))
        return list(recon), dict(ev or {})
