from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict


def _default_audit_path(repo_root: Path) -> Path:
    return repo_root / "artifact_out" / "audit.jsonl"


def _canonical_json_bytes(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sha256_hex(msg: bytes) -> str:
    return hashlib.sha256(msg).hexdigest()


def _hmac_sha256_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description="Verify MIRAGE audit.jsonl hash chaining (tamper-evident log).")
    p.add_argument("--path", default=os.getenv("AUDIT_LOG_PATH", str(_default_audit_path(repo_root))))
    p.add_argument("--key-hex", default=os.getenv("AUDIT_CHAIN_KEY_HEX", ""))
    args = p.parse_args(argv)

    path = Path(str(args.path))
    if not path.exists():
        print(json.dumps({"status": "MISSING", "path": str(path)}, ensure_ascii=True))
        return 2

    key_hex = (str(args.key_hex) or "").strip()
    key = bytes.fromhex(key_hex) if key_hex else b""

    prev = ""
    n = 0
    found_chain = False

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for ln_no, line in enumerate(f, start=1):
            line = (line or "").strip()
            if not line:
                continue
            n += 1
            try:
                obj = json.loads(line)
            except Exception:
                print(json.dumps({"status": "FAIL", "path": str(path), "line": ln_no, "error": "bad_json"}, ensure_ascii=True))
                return 3
            if not isinstance(obj, dict):
                print(json.dumps({"status": "FAIL", "path": str(path), "line": ln_no, "error": "not_object"}, ensure_ascii=True))
                return 3

            if "hash" not in obj:
                if found_chain:
                    print(json.dumps({"status": "FAIL", "path": str(path), "line": ln_no, "error": "missing_hash_field"}, ensure_ascii=True))
                    return 3
                continue

            found_chain = True
            want_prev = str(obj.get("prev_hash") or "")
            if want_prev != str(prev or ""):
                print(
                    json.dumps(
                        {"status": "FAIL", "path": str(path), "line": ln_no, "error": "prev_hash_mismatch", "expected": prev, "got": want_prev},
                        ensure_ascii=True,
                    )
                )
                return 3

            base = {k: v for (k, v) in obj.items() if k not in ("hash", "hash_alg")}
            msg = _canonical_json_bytes(base)

            alg = str(obj.get("hash_alg") or "sha256").strip().lower()
            if alg == "hmac_sha256":
                if not key:
                    print(json.dumps({"status": "FAIL", "path": str(path), "line": ln_no, "error": "missing_hmac_key"}, ensure_ascii=True))
                    return 3
                expected = _hmac_sha256_hex(key, msg)
            elif alg == "sha256":
                expected = _sha256_hex(msg)
            else:
                print(json.dumps({"status": "FAIL", "path": str(path), "line": ln_no, "error": f"unknown_hash_alg:{alg}"}, ensure_ascii=True))
                return 3

            got = str(obj.get("hash") or "")
            if got != expected:
                print(json.dumps({"status": "FAIL", "path": str(path), "line": ln_no, "error": "hash_mismatch"}, ensure_ascii=True))
                return 3

            prev = got

    out = {"status": "OK" if found_chain else "SKIPPED", "path": str(path), "lines": int(n), "final_hash": str(prev or "")}
    print(json.dumps(out, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

