from __future__ import annotations

import os
import random
import unittest
from unittest.mock import patch
import threading
from concurrent.futures import Future

from gateway.fss_pir import PirClient
from gateway.fss_pir import PirMixConfig, _SignedBitBatchMixer
from gateway.policy_unified import (
    BundleConfig,
    UnifiedPolicyEngine,
    _bundle_shift,
    build_policy_unified_v1_circuit_default,
)
from gateway.tx_store import TxStore
from policy_server.mpc_engine import Gate, MpcSession


def _eval_circuit_clear(c, inputs: dict[str, int]) -> dict[str, int]:
    wires: list[int | None] = [None for _ in range(int(c.n_wires))]
    for name, wi in c.inputs.items():
        if name not in inputs:
            raise KeyError(f"missing input {name}")
        wires[int(wi)] = int(inputs[name]) & 1

    for g in c.gates:
        op = str(g.op).upper()
        if op == "CONST":
            wires[int(g.out)] = int(g.value or 0) & 1
        elif op == "NOT":
            a = wires[int(g.a)]  # type: ignore[arg-type]
            if a is None:
                raise ValueError("wire not ready")
            wires[int(g.out)] = (int(a) ^ 1) & 1
        elif op == "XOR":
            a = wires[int(g.a)]  # type: ignore[arg-type]
            b = wires[int(g.b)]  # type: ignore[arg-type]
            if a is None or b is None:
                raise ValueError("wire not ready")
            wires[int(g.out)] = (int(a) ^ int(b)) & 1
        elif op == "AND":
            a = wires[int(g.a)]  # type: ignore[arg-type]
            b = wires[int(g.b)]  # type: ignore[arg-type]
            if a is None or b is None:
                raise ValueError("wire not ready")
            wires[int(g.out)] = (int(a) & int(b)) & 1
        else:
            raise ValueError(f"unknown op {g.op}")

    out: dict[str, int] = {}
    for name, wi in c.outputs.items():
        v = wires[int(wi)]
        if v is None:
            raise ValueError("output wire not ready")
        out[str(name)] = int(v) & 1
    return out


def _eval_circuit_by_and_rounds(c, inputs: dict[str, int]) -> dict[str, int]:
    wires: list[int | None] = [None for _ in range(int(c.n_wires))]
    for name, wi in c.inputs.items():
        wires[int(wi)] = int(inputs[name]) & 1

    def eval_local() -> None:
        while True:
            progressed = 0
            for g in c.gates:
                op = str(g.op).upper()
                if op == "AND":
                    continue
                if wires[int(g.out)] is not None:
                    continue
                if op == "CONST":
                    wires[int(g.out)] = int(g.value or 0) & 1
                    progressed += 1
                elif op == "NOT":
                    a = wires[int(g.a)]  # type: ignore[arg-type]
                    if a is None:
                        continue
                    wires[int(g.out)] = (int(a) ^ 1) & 1
                    progressed += 1
                elif op == "XOR":
                    a = wires[int(g.a)]  # type: ignore[arg-type]
                    b = wires[int(g.b)]  # type: ignore[arg-type]
                    if a is None or b is None:
                        continue
                    wires[int(g.out)] = (int(a) ^ int(b)) & 1
                    progressed += 1
                else:
                    raise ValueError(f"unknown op {g.op}")
            if progressed == 0:
                break

    eval_local()
    for round_gates in (c.and_rounds or []):
        for gi in round_gates:
            g = c.gates[int(gi)]
            if str(g.op).upper() != "AND":
                raise ValueError("round contained non-AND gate")
            a = wires[int(g.a)]  # type: ignore[arg-type]
            b = wires[int(g.b)]  # type: ignore[arg-type]
            if a is None or b is None:
                raise ValueError("and gate inputs not ready")
            wires[int(g.out)] = (int(a) & int(b)) & 1
        eval_local()

    out: dict[str, int] = {}
    for name, wi in c.outputs.items():
        v = wires[int(wi)]
        if v is None:
            raise ValueError("output wire not ready")
        out[str(name)] = int(v) & 1
    return out


def _share_bit(rng: random.Random, x: int) -> tuple[int, int]:
    r = rng.randint(0, 1)
    return r, (r ^ (int(x) & 1)) & 1


class AlgorithmTests(unittest.TestCase):
    def test_bundle_shift_formula(self) -> None:
        b = BundleConfig(
            enabled=True,
            db="policy_bundle",
            base_domain_size=4096,
            bundle_domain_size=65536,
            bundle_stride=32768,
            bundle_id=1,
            logical_offsets={
                "allow_recipients": 0,
                "allow_domains": 4096,
                "banned_tokens": 8192,
                "ioc_domains": 12288,
                "banned_install_tokens": 16384,
            },
        )
        self.assertEqual(_bundle_shift(b, logical="allow_recipients", raw_idx=5), 32768 + 0 + 5)
        self.assertEqual(_bundle_shift(b, logical="allow_domains", raw_idx=5), 32768 + 4096 + 5)
        self.assertEqual(_bundle_shift(b, logical="banned_tokens", raw_idx=4097), 32768 + 8192 + (4097 % 4096))

    def test_unified_circuit_semantics_one_hot(self) -> None:
        rng = random.Random(0)
        c = build_policy_unified_v1_circuit_default()

        def check(intent: str) -> None:
            for _ in range(64):
                # Randomize all inputs; one-hot intent bits are enforced below.
                inp: dict[str, int] = {k: rng.randint(0, 1) for k in c.inputs.keys()}
                inp["intent_send"] = 1 if intent == "send" else 0
                inp["intent_fetch"] = 1 if intent == "fetch" else 0
                inp["intent_webhook"] = 1 if intent == "webhook" else 0
                inp["intent_skill_install"] = 1 if intent == "skill" else 0

                cap_send = int(inp["cap_send"])
                cap_fetch = int(inp["cap_fetch"])
                cap_webhook = int(inp["cap_webhook"])
                cap_skill = int(inp["cap_skill_install"])

                recipient_ok = int(inp["recipient_ok"])
                domain_ok = int(inp["domain_ok"])
                dlp_hit = int(inp["dlp_hit"])
                high_handle = int(inp["high_handle_present"])
                ioc_hit = int(inp["ioc_hit"])
                install_hit = int(inp["install_hit"])
                base64_obf = int(inp["base64_obf"])

                not_high = 1 ^ high_handle

                if intent == "send":
                    allow_pre = cap_send & recipient_ok & not_high
                    need_confirm = dlp_hit
                elif intent == "fetch":
                    allow_pre = cap_fetch & domain_ok
                    need_confirm = 0
                elif intent == "webhook":
                    allow_pre = cap_webhook & domain_ok & not_high
                    need_confirm = dlp_hit
                else:
                    allow_pre = cap_skill & (1 ^ ioc_hit)
                    need_confirm = 1 if (install_hit or base64_obf) else 0

                want = {
                    "allow_pre": int(allow_pre) & 1,
                    "need_confirm": int(need_confirm) & 1,
                    "patch0": int(need_confirm) & 1,
                    "patch1": 0,
                }
                got = _eval_circuit_clear(c, inp)
                self.assertEqual(got, want)

        for intent in ["send", "fetch", "webhook", "skill"]:
            check(intent)

    def test_and_round_schedule_matches_sequential_eval(self) -> None:
        rng = random.Random(1)
        c = build_policy_unified_v1_circuit_default()
        for _ in range(64):
            inp: dict[str, int] = {k: rng.randint(0, 1) for k in c.inputs.keys()}
            # Enforce a one-hot intent selector to match the compiler precondition.
            which = rng.choice(["intent_send", "intent_fetch", "intent_webhook", "intent_skill_install"])
            for k in ["intent_send", "intent_fetch", "intent_webhook", "intent_skill_install"]:
                inp[k] = 1 if k == which else 0

            got_seq = _eval_circuit_clear(c, inp)
            got_rounds = _eval_circuit_by_and_rounds(c, inp)
            self.assertEqual(got_rounds, got_seq)

    def test_beaver_and_correctness_single_gate(self) -> None:
        rng = random.Random(2)
        gates = [Gate(op="AND", out=2, a=0, b=1)]
        for _ in range(128):
            x = rng.randint(0, 1)
            y = rng.randint(0, 1)
            x0, x1 = _share_bit(rng, x)
            y0, y1 = _share_bit(rng, y)

            a = rng.randint(0, 1)
            b = rng.randint(0, 1)
            c = a & b
            a0, a1 = _share_bit(rng, a)
            b0, b1 = _share_bit(rng, b)
            c0, c1 = _share_bit(rng, c)

            s0 = MpcSession(
                action_id="a",
                program_id="p",
                request_sha256="h",
                party=0,
                n_wires=3,
                gates=gates,
                input_shares={0: x0, 1: y0},
                outputs={"out": 2},
            )
            s1 = MpcSession(
                action_id="a",
                program_id="p",
                request_sha256="h",
                party=1,
                n_wires=3,
                gates=gates,
                input_shares={0: x1, 1: y1},
                outputs={"out": 2},
            )

            d0, e0 = s0.and_mask(gate_index=0, a_share=a0, b_share=b0, c_share=c0)
            d1, e1 = s1.and_mask(gate_index=0, a_share=a1, b_share=b1, c_share=c1)
            d = (int(d0) ^ int(d1)) & 1
            e = (int(e0) ^ int(e1)) & 1
            z0 = s0.and_finish(gate_index=0, d=d, e=e)
            z1 = s1.and_finish(gate_index=0, d=d, e=e)
            z = (int(z0) ^ int(z1)) & 1
            self.assertEqual(z, (x & y) & 1)

            out0 = s0.finalize()["out"]
            out1 = s1.finalize()["out"]
            self.assertEqual((int(out0) ^ int(out1)) & 1, (x & y) & 1)

    def test_unified_pir_plan_fixed_key_count(self) -> None:
        old_env = dict(os.environ)
        try:
            os.environ["MAX_SKILL_DOMAINS"] = "4"
            os.environ["SIGNED_PIR"] = "1"

            pir = PirClient(policy0_url="http://p0.invalid", policy1_url="http://p1.invalid", domain_size=4096)
            eng = UnifiedPolicyEngine(pir=pir, handles=None, tx_store=TxStore(), domain_size=4096, max_tokens=8)

            bcfg = BundleConfig(
                enabled=True,
                db="policy_bundle",
                base_domain_size=4096,
                bundle_domain_size=65536,
                bundle_stride=32768,
                bundle_id=1,
                logical_offsets={
                    "allow_recipients": 0,
                    "allow_domains": 4096,
                    "banned_tokens": 8192,
                    "ioc_domains": 12288,
                    "banned_install_tokens": 16384,
                },
            )

            K = 2 + 8 + 4 + 8
            bits = [0 for _ in range(K)]
            bits[0] = 1  # recipient_ok
            bits[1] = 0  # domain_ok
            bits[2 + 3] = 1  # one banned token hit -> dlp_hit
            bits[2 + 8 + 4 + 5] = 1  # one install token hit -> install_hit

            with patch("gateway.policy_unified._load_bundle_cfg", return_value=bcfg):
                with patch.object(UnifiedPolicyEngine, "_query_bits_signed_or_single_server", return_value=(bits, {"proof": "ok"})) as q:
                    feats, ev = eng._pir_unified_plan(
                        recipient="alice@example.com",
                        domain="example.com",
                        text="hello",
                        skill_domains=["a.com"],
                        skill_md="# skill",
                        action_id="a_test",
                    )

            # Verify constant-shape call.
            _args, kwargs = q.call_args
            self.assertEqual(kwargs["db_name"], "policy_bundle")
            self.assertEqual(kwargs["action_id"], "a_test")
            self.assertEqual(kwargs["domain_size"], 65536)
            self.assertEqual(len(kwargs["idxs"]), K)

            # Verify feature extraction.
            self.assertEqual(int(feats["recipient_ok"]), 1)
            self.assertEqual(int(feats["domain_ok"]), 0)
            self.assertEqual(int(feats["dlp_hit"]), 1)
            self.assertEqual(int(feats["ioc_hit"]), 0)
            self.assertEqual(int(feats["install_hit"]), 1)
            self.assertIn("unified_bits", ev)
        finally:
            os.environ.clear()
            os.environ.update(old_env)

    def test_pir_mixer_flush_pads_to_constant_subrequests(self) -> None:
        # Validate the mixer core invariant (Algorithm A4): each tick emits exactly pad_to
        # subrequests, each with fixed_n_keys keys, regardless of how many real subrequests exist.
        cfg = PirMixConfig(
            enabled=True,
            interval_ms=50,
            pad_to=3,
            fixed_n_keys=4,
            db_name="policy_bundle",
            domain_size=65536,
            timeout_s=2,
            cover_traffic=True,
        )

        m = _SignedBitBatchMixer.__new__(_SignedBitBatchMixer)
        m.policy0_url = "http://p0.invalid"
        m.policy1_url = "http://p1.invalid"
        m.cfg = cfg
        m._lock = threading.Lock()
        m._pending = []

        # Two real subrequests, one dummy is expected to be injected (pad_to=3).
        keys0 = ["AA==", "AQ==", "Ag==", "Aw=="]
        keys1 = ["BA==", "BQ==", "Bg==", "Bw=="]
        f0: Future = Future()
        f1: Future = Future()
        m._pending.append(("a0", keys0, keys1, f0))
        m._pending.append(("a1", keys0, keys1, f1))

        class _Resp:
            def __init__(self, payload: dict):
                self._payload = payload

            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict:
                return dict(self._payload)

        def fake_post(url: str, *, json: dict, timeout: int):  # noqa: ARG001
            self.assertEqual(json.get("db"), "policy_bundle")
            reqs = json.get("requests") or []
            self.assertEqual(len(reqs), 3)
            for sub in reqs:
                self.assertEqual(len(sub.get("dpf_keys_b64") or []), 4)
            # Echo back responses with dummy proofs.
            responses = [{"action_id": str(sub["action_id"]), "ans_shares": [0, 0, 0, 0], "proof": {}} for sub in reqs]
            return _Resp({"responses": responses})

        with patch("gateway.fss_pir.requests.post", side_effect=fake_post):
            m._flush_once()

        self.assertTrue(f0.done())
        self.assertTrue(f1.done())
        recon0, ev0 = f0.result(timeout=1)
        recon1, ev1 = f1.result(timeout=1)
        self.assertEqual(len(recon0), 4)
        self.assertEqual(len(recon1), 4)
        self.assertTrue(ev0.get("mixed"))
        self.assertTrue(ev1.get("mixed"))


if __name__ == "__main__":
    unittest.main()
