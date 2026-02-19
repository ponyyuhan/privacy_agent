from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from capsule.verify_contract import verify


class CapsuleContractVerifierTests(unittest.TestCase):
    def test_contract_verifier_passes_on_satisfying_report(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        contract_path = repo_root / "spec" / "secureclaw_capsule_contract_v1.json"

        report = {
            "direct_fs_read": {"ok": False, "error": "PermissionError", "details": "Operation not permitted"},
            "direct_exec_true": {"ok": False, "spawned": False, "error": "PermissionError", "details": "sandbox blocked"},
            "direct_exec_sh": {"ok": False, "spawned": False, "error": "PermissionError", "details": "sandbox blocked"},
            "direct_internet": {"ok": False, "error": "ConnectionError", "details": "blocked"},
            "direct_exfil_post": {"ok": False, "error": "ConnectionError", "details": "blocked"},
            "gateway_act": {"ok": True, "transport": "uds", "http_status": 200},
            "gateway_mcp_act": {"ok": True, "response": {"status": "OK"}},
        }

        with tempfile.TemporaryDirectory() as td:
            rp = Path(td) / "capsule_smoke.json"
            op = Path(td) / "capsule_contract_verdict.json"
            rp.write_text(json.dumps(report, ensure_ascii=True), encoding="utf-8")
            ok, verdict = verify(contract_path=contract_path, report_path=rp, out_path=op)
            self.assertTrue(ok, msg=str(verdict))
            self.assertTrue(op.exists())

    def test_contract_verifier_fails_when_must_deny_probe_succeeds(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        contract_path = repo_root / "spec" / "secureclaw_capsule_contract_v1.json"

        report = {
            "direct_fs_read": {"ok": False, "error": "PermissionError", "details": "blocked"},
            "direct_exec_true": {"ok": False, "spawned": False, "error": "PermissionError", "details": "blocked"},
            "direct_exec_sh": {"ok": False, "spawned": False, "error": "PermissionError", "details": "blocked"},
            # Violation: public internet succeeds.
            "direct_internet": {"ok": True, "status": 200, "note": "unexpected success"},
            "direct_exfil_post": {"ok": False, "error": "ConnectionError", "details": "blocked"},
            "gateway_act": {"ok": True, "transport": "uds", "http_status": 200},
            "gateway_mcp_act": {"ok": True, "response": {"status": "OK"}},
        }

        with tempfile.TemporaryDirectory() as td:
            rp = Path(td) / "capsule_smoke.json"
            rp.write_text(json.dumps(report, ensure_ascii=True), encoding="utf-8")
            ok, verdict = verify(contract_path=contract_path, report_path=rp, out_path=None)
            self.assertFalse(ok)
            fails = [r for r in (verdict.get("results") or []) if not bool(r.get("ok"))]
            self.assertTrue(any(r.get("id") == "no_public_internet" for r in fails), msg=str(fails))


if __name__ == "__main__":
    unittest.main()

