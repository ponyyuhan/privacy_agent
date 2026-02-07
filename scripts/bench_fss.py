import os
import random
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fss.dpf import gen_dpf_keys, eval_dpf_pir_parity_share


def _set_bit(buf: bytearray, idx: int) -> None:
    buf[idx // 8] |= (1 << (idx % 8))


def main() -> None:
    domain_size = int(os.getenv("FSS_DOMAIN_SIZE", "4096"))
    if domain_size <= 0 or (domain_size & (domain_size - 1)) != 0:
        raise SystemExit("FSS_DOMAIN_SIZE must be a power of two")
    domain_bits = domain_size.bit_length() - 1

    nbytes = (domain_size + 7) // 8
    # A sparse-ish DB so reconstruction hits both 0 and 1 paths.
    db = bytearray(b"\x00" * nbytes)
    for _ in range(max(1, domain_size // 1024)):
        _set_bit(db, random.randrange(domain_size))

    idxs = [random.randrange(domain_size) for _ in range(50)]

    # Measure key sizes.
    k0, _k1 = gen_dpf_keys(alpha=idxs[0], beta=1, domain_bits=domain_bits)
    print(f"domain_size={domain_size} (2^{domain_bits})")
    print(f"db_bytes={nbytes}")
    print(f"dpf_key_bytes={len(k0)}")
    print(f"naive_onetime_key_bytes={nbytes}  (old O(N) keyshare baseline)")

    # Measure eval time (single-process; policy server does this).
    t0 = time.perf_counter()
    for idx in idxs:
        k0, k1 = gen_dpf_keys(alpha=idx, beta=1, domain_bits=domain_bits)
        a0 = eval_dpf_pir_parity_share(key_bytes=k0, db_bitset=bytes(db), party=0)
        a1 = eval_dpf_pir_parity_share(key_bytes=k1, db_bitset=bytes(db), party=1)
        _ = a0 ^ a1
    t1 = time.perf_counter()
    per = (t1 - t0) / len(idxs)
    print(f"eval_pir_share_avg_s={per:.6f}  (includes keygen+2 evals)")


if __name__ == "__main__":
    main()
