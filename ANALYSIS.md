# Analysis Notes (Artifact Appendix)

This file collects the quantitative notes that back the artifact claims (beyond `EFFECTIVENESS.md`).

## 1) DPF/FSS Performance

Run:

```bash
python scripts/bench_fss_curve.py
```

Or via artifact:

```bash
bash scripts/run_artifact.sh
```

The curve CSV is written to `artifact_out/bench_fss_curve.csv`.

Notes:

- Client communication is **O(log N)** bytes per query key (DPF key share).
- Server evaluation remains **O(N)** for a naive bitset inner-product evaluation; the demo focuses on the privacy plumbing + artifact reproducibility.
- This repo uses a faster v2 PRG for DPF (single SHA-512 expansion + seed-bit output) to reduce constant factors.

## 1b) End-to-End Throughput (Gateway + 2 Policy Servers + Executor)

Run (short benchmark):

```bash
python scripts/bench_e2e_throughput.py
```

Or via artifact:

```bash
bash scripts/run_artifact.sh
```

Output is written to `artifact_out/bench_e2e.json`.

Notes:

- The benchmark exercises `SendMessage` end-to-end: gateway guardrails (PIR) + executor verification.
- For a compiled backend, set `POLICY_BACKEND=rust` (see `policy_server_rust/`), e.g.:

```bash
POLICY_BACKEND=rust python scripts/bench_e2e_throughput.py
```

## 2) DLP Guardrails: False Positives / False Negatives

### Coarse stage: 4-gram bitset (fast, approximate)

We hash each character 4-gram `g` to an index in `[0, N)`:

`idx = SHA256(g)[:32] mod N`

Policy stores a bitset `B` where each policy pattern sets multiple 4-gram positions.

At query time, the gateway checks a bounded number of 4-grams from the outbound message (default `MAX_TOKENS_PER_MESSAGE`).

**False positives**

Because `B` is a single bitset, unrelated 4-grams can collide onto set bits. If the bitset has `m` set bits, then a random query 4-gram hits with probability approximately:

`p ≈ m / N`.

For `T` queried 4-grams, the probability of at least one hit is:

`P_fp ≈ 1 - (1 - p)^T`.

This is why the demo adds an exact confirm stage when `DLP_MODE=dfa`.

**False negatives**

The 4-gram stage will *miss* patterns that:

- are not representable via fixed 4-grams (e.g., regex-style gaps), or
- are shorter than 4 characters, or
- are missed due to tokenization limits (`MAX_TOKENS_PER_MESSAGE`).

### Confirm stage: oblivious DFA (exact for the configured patterns)

When the coarse stage produces any hit, we run an Aho-Corasick DFA scan over the text via block PIR queries.

Properties:

- For the set of patterns compiled into the DFA, this confirm has **zero hash collisions**, so it can remove coarse false positives.
- It is more expensive (multiple PIR block lookups), so it is only run on demand (after coarse hit).

## 3) Leakage Surface (What Policy Servers Learn)

Even though query indices are hidden by DPF security, policy servers can still observe:

- `db` name (which database is being queried)
- request sizes (batch size, and in DFA mode: number of DFA steps)
- timing / frequency (how often the gateway checks)

This artifact keeps that surface explicit and bounded (batching, max token limits, DFA confirm only on coarse hits).

Mitigations implemented in this repo (optional knobs):

- `PAD_TOKEN_BATCH=1` (default) pads the DLP 4-gram batch to a fixed size (`MAX_TOKENS_PER_MESSAGE`).
- `USE_POLICY_BUNDLE=1` + `policy_server/policy.yaml:bundle_enabled=true` allow querying a single bundled bitset DB (`policy_bundle`) so each policy server does not see logical `db_name` for allowlists/DLP bitsets.
- `SHAPE_ALL_INTENTS=1` issues dummy checks so policy servers observe a more uniform query pattern across egress vs network intents.
