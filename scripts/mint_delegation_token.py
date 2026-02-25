from __future__ import annotations

import argparse
import json
import os
import sys
import time

from common.delegation_token import mint_delegation_token, parse_and_verify_delegation_token


def main() -> None:
    ap = argparse.ArgumentParser(description="Mint a SecureClaw cross-agent delegation token.")
    ap.add_argument("--issuer", required=True, help="External principal, e.g. ext:internal-blue")
    ap.add_argument("--subject", required=True, help="Internal actor pattern, e.g. artifact or skill:abc*")
    ap.add_argument("--session", required=True, help="Bound session id")
    ap.add_argument("--scope", required=True, nargs="+", help="Intent scopes, e.g. intent:SendInterAgentMessage intent:MemoryRead")
    ap.add_argument("--ttl-s", type=int, default=600)
    ap.add_argument("--key-hex", default="", help="Override DELEGATION_TOKEN_KEY")
    args = ap.parse_args()

    key_hex = str(args.key_hex or os.getenv("DELEGATION_TOKEN_KEY") or "").strip()
    if not key_hex:
        raise SystemExit("missing key: provide --key-hex or DELEGATION_TOKEN_KEY")

    tok = mint_delegation_token(
        key_hex=key_hex,
        issuer=str(args.issuer),
        subject=str(args.subject),
        session=str(args.session),
        scope=[str(x) for x in (args.scope or [])],
        ttl_s=int(args.ttl_s),
    )

    chk = parse_and_verify_delegation_token(
        key_hex=key_hex,
        token=tok,
        expected_session=str(args.session),
        expected_subject=str(args.subject),
        expected_intent=str((args.scope or ["intent:*"])[0]).replace("intent:", ""),
        now_ms=int(time.time() * 1000),
    )
    out = {
        "status": "OK" if chk.ok else "ERROR",
        "token": tok,
        "verify_code": chk.code,
        "issuer": str(args.issuer),
        "subject": str(args.subject),
        "session": str(args.session),
        "scope": [str(x) for x in (args.scope or [])],
    }
    sys.stdout.write(json.dumps(out, indent=2, ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
