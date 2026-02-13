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
        # Load all bitset DBs present on disk (keeps the server generic as we add new DBs).
        bitset_paths = sorted(self.data_dir.glob("*.bitset"))
        if not bitset_paths:
            raise FileNotFoundError(f"No .bitset DB files found under: {self.data_dir}")
        for p in bitset_paths:
            name = p.stem
            self._bitsets[name] = p.read_bytes()

        # Optional block DBs (fixed-size blocks). Currently only DFA transitions are used by the demo,
        # but we load any *.blk for extensibility.
        for p in sorted(self.data_dir.glob("*.blk")):
            name = p.stem
            # Build script uses block_size=4; if you add more block DBs, encode block_size in meta.json.
            self._blocks[name] = (p.read_bytes(), 4)

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

    def query_idx_batch(self, db_name: str, idxs: List[int]) -> List[int]:
        """
        Single-server cleartext baseline query.

        This intentionally leaks query indices to the policy server and is used only
        for baseline/ablation experiments.
        """
        if db_name not in self._bitsets:
            raise KeyError(f"Unknown db: {db_name}")
        db = self._bitsets[db_name]
        nbits = len(db) * 8
        out: list[int] = []
        for idx in idxs:
            i = int(idx)
            if i < 0 or i >= nbits:
                out.append(0)
                continue
            out.append(int((db[i // 8] >> (i % 8)) & 1))
        return out
