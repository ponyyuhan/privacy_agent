from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import time

from common.federated_proof_token import mint_federated_proof_token


def canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign_v1(*, key_hex: str, method: str, path: str, session: str, principal: str, ts_ms: int, nonce: str, payload_sha256: str) -> str:
    msg = "\n".join(
        [
            "secureclaw-federated-sig-v1",
            method.upper(),
            path,
            session,
            principal,
            str(int(ts_ms)),
            nonce,
            payload_sha256,
        ]
    ).encode("utf-8")
    mac = hmac.new(bytes.fromhex(key_hex), msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate SecureClaw federated auth headers for /act.")
    ap.add_argument("--payload", required=True, help="JSON file path for /act payload")
    ap.add_argument("--session", required=True)
    ap.add_argument("--principal", required=True)
    ap.add_argument("--method", default="POST")
    ap.add_argument("--path", default="/act")
    ap.add_argument("--sig-kid", default="k0")
    ap.add_argument("--sig-key-hex", default="", help="Override MIRAGE_FEDERATED_SIG_KEYS[kid]")
    ap.add_argument("--proof-key-hex", default="", help="Override MIRAGE_FEDERATED_PROOF_KEY")
    ap.add_argument("--proof-ttl-s", type=int, default=120)
    ap.add_argument("--mtls-cert-sha256", default="", help="Optional x-mtls-client-cert-sha256")
    args = ap.parse_args()

    payload = json.loads(open(args.payload, "r", encoding="utf-8").read())
    if not isinstance(payload, dict):
        raise SystemExit("payload must be a JSON object")

    sig_key = str(args.sig_key_hex or "").strip()
    if not sig_key:
        # env MIRAGE_FEDERATED_SIG_KEYS format: kid1:hex,kid2:hex
        keys_raw = str(os.getenv("MIRAGE_FEDERATED_SIG_KEYS") or "")
        m = {}
        for p in keys_raw.split(","):
            p = p.strip()
            if not p:
                continue
            if ":" in p:
                k, v = p.split(":", 1)
            else:
                k, v = "0", p
            m[k.strip() or "0"] = v.strip()
        sig_key = str(m.get(str(args.sig_kid), "")).strip()
    if not sig_key:
        raise SystemExit("missing signature key: use --sig-key-hex or MIRAGE_FEDERATED_SIG_KEYS")

    ts_ms = int(time.time() * 1000)
    nonce = f"n{ts_ms}"
    payload_sha = hashlib.sha256(canonical_json(payload)).hexdigest()
    sig = sign_v1(
        key_hex=sig_key,
        method=str(args.method),
        path=str(args.path),
        session=str(args.session),
        principal=str(args.principal),
        ts_ms=ts_ms,
        nonce=nonce,
        payload_sha256=payload_sha,
    )

    proof_key = str(args.proof_key_hex or os.getenv("MIRAGE_FEDERATED_PROOF_KEY") or "").strip()
    proof = ""
    if proof_key:
        proof = mint_federated_proof_token(
            key_hex=proof_key,
            principal=str(args.principal),
            session=str(args.session),
            ttl_s=int(args.proof_ttl_s),
            evidence="federated-remote",
        )

    headers = {
        "x-mirage-session": str(args.session),
        "x-mirage-external-principal": str(args.principal),
        "x-mirage-sig-kid": str(args.sig_kid),
        "x-mirage-sig-ts-ms": str(ts_ms),
        "x-mirage-sig-nonce": nonce,
        "x-mirage-sig": sig,
    }
    if args.mtls_cert_sha256:
        headers["x-mtls-client-cert-sha256"] = str(args.mtls_cert_sha256)
    if proof:
        headers["x-mirage-proof-token"] = proof

    print(json.dumps({"headers": headers, "payload_sha256": payload_sha}, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
