import os
import sys
import unittest
from pathlib import Path

from agent.mcp_client import McpStdioClient


class McpGatewayTests(unittest.TestCase):
    def test_mcp_mirage_act_readfile_sensitive_returns_handle(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(repo_root)
        # Policy servers are not needed for ReadFile; keep them pointed at an unused address.
        env["POLICY0_URL"] = "http://127.0.0.1:1"
        env["POLICY1_URL"] = "http://127.0.0.1:1"
        env["FSS_DOMAIN_SIZE"] = "4096"

        with McpStdioClient([sys.executable, "-m", "gateway.mcp_server"], env=env) as mcp:
            mcp.initialize()
            obs = mcp.call_tool(
                "mirage.act",
                {
                    "intent_id": "ReadFile",
                    "inputs": {"path_spec": "~/.ssh/id_rsa", "purpose": "test"},
                    "constraints": {},
                    "caller": "unit-test",
                },
            )

        self.assertEqual(obs["status"], "OK")
        self.assertTrue(obs.get("artifacts"))
        self.assertIn("handle", obs["artifacts"][0])
        self.assertEqual(obs["artifacts"][0]["sensitivity"], "HIGH")


if __name__ == "__main__":
    unittest.main()

