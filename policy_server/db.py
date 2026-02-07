from __future__ import annotations

import base64
from pathlib import Path
from typing import Dict, List, Tuple

from fss.dpf import eval_dpf_pir_parity_share, eval_dpf_pir_block_share


class BitsetDB:
    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self._bitsets: Dict[str, bytes] = {}
        self._blocks: Dict[str, Tuple[bytes, int]] = {}  # name -> (data, block_size)

    def load(self) -> None:
        for name in ["banned_tokens", "allow_recipients", "allow_domains"]:
            p = self.data_dir / f"{name}.bitset"
            if not p.exists():
                raise FileNotFoundError(f"Missing DB file: {p}")
            self._bitsets[name] = p.read_bytes()

        # Optional "bundled" DB (concatenated bitsets) to hide db_name from policy servers.
        bundle = self.data_dir / "policy_bundle.bitset"
        if bundle.exists():
            self._bitsets["policy_bundle"] = bundle.read_bytes()

        # Optional block DBs (fixed-size blocks).
        blk = self.data_dir / "dfa_transitions.blk"
        if blk.exists():
            # Build script uses block_size=4; keep metadata simple for demo.
            self._blocks["dfa_transitions"] = (blk.read_bytes(), 4)

    def query_one(self, db_name: str, dpf_key_b64: str, *, party: int) -> int:
        if db_name not in self._bitsets:
            raise KeyError(f"Unknown db: {db_name}")
        key = base64.b64decode(dpf_key_b64)
        db = self._bitsets[db_name]
        return int(eval_dpf_pir_parity_share(key_bytes=key, db_bitset=db, party=party)) & 1

    def query_batch(self, db_name: str, dpf_keys_b64: List[str], *, party: int) -> List[int]:
        if db_name not in self._bitsets:
            raise KeyError(f"Unknown db: {db_name}")
        db = self._bitsets[db_name]
        out: list[int] = []
        for k in dpf_keys_b64:
            key = base64.b64decode(k)
            out.append(int(eval_dpf_pir_parity_share(key_bytes=key, db_bitset=db, party=party)) & 1)
        return out

    def query_block_batch(self, db_name: str, dpf_keys_b64: List[str], *, party: int) -> List[str]:
        if db_name not in self._blocks:
            raise KeyError(f"Unknown block db: {db_name}")
        db, block_size = self._blocks[db_name]
        out: list[str] = []
        for k in dpf_keys_b64:
            key = base64.b64decode(k)
            share = eval_dpf_pir_block_share(key_bytes=key, db_blocks=db, block_size=block_size, party=party)
            out.append(base64.b64encode(share).decode("ascii"))
        return out
