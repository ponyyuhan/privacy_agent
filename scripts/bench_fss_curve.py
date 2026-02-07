import os
import random
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fss.dpf import gen_dpf_keys, eval_dpf_pir_parity_share


def _set_bit(buf: bytearray, idx: int) -> None:
    buf[idx // 8] |= (1 << (idx % 8))


def bench(domain_size: int, iters: int = 20) -> dict:
    if domain_size <= 0 or (domain_size & (domain_size - 1)) != 0:
        raise ValueError("domain_size must be a power of two")
    domain_bits = domain_size.bit_length() - 1
    nbytes = (domain_size + 7) // 8
    db = bytearray(b"\x00" * nbytes)
    for _ in range(max(1, domain_size // 1024)):
        _set_bit(db, random.randrange(domain_size))

    idxs = [random.randrange(domain_size) for _ in range(iters)]

    k0, _k1 = gen_dpf_keys(alpha=idxs[0], beta=1, domain_bits=domain_bits)
    key_bytes = len(k0)

    t0 = time.perf_counter()
    for idx in idxs:
        k0, k1 = gen_dpf_keys(alpha=idx, beta=1, domain_bits=domain_bits)
        a0 = eval_dpf_pir_parity_share(key_bytes=k0, db_bitset=bytes(db), party=0)
        a1 = eval_dpf_pir_parity_share(key_bytes=k1, db_bitset=bytes(db), party=1)
        _ = a0 ^ a1
    t1 = time.perf_counter()
    avg_s = (t1 - t0) / len(idxs)

    return {
        "domain_size": domain_size,
        "domain_bits": domain_bits,
        "db_bytes": nbytes,
        "dpf_key_bytes": key_bytes,
        "avg_s_per_query": avg_s,
    }


def main() -> None:
    sizes = os.getenv("DOMAIN_SIZES", "1024,4096,16384").strip()
    domain_sizes = [int(x) for x in sizes.split(",") if x.strip()]
    iters = int(os.getenv("ITERS", "30"))
    out_csv = os.getenv("OUT_CSV", "")

    rows = []
    for ds in domain_sizes:
        rows.append(bench(ds, iters=iters))

    header = ["domain_size", "domain_bits", "db_bytes", "dpf_key_bytes", "avg_s_per_query"]
    lines = [",".join(header)]
    for r in rows:
        lines.append(",".join(str(r[h]) for h in header))

    csv_text = "\n".join(lines) + "\n"
    sys.stdout.write(csv_text)

    if out_csv:
        Path(out_csv).write_text(csv_text)


if __name__ == "__main__":
    main()

