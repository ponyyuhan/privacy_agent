import argparse
import subprocess
from pathlib import Path


def _cmd_demo(_args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent
    script = repo_root / "scripts" / "run_all.sh"
    r = subprocess.run(["bash", str(script)], check=False)
    return int(r.returncode)

def _cmd_artifact(_args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent
    script = repo_root / "scripts" / "run_artifact.sh"
    r = subprocess.run(["bash", str(script)], check=False)
    return int(r.returncode)

def _cmd_nanoclaw(_args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent
    script = repo_root / "scripts" / "run_nanoclaw.sh"
    r = subprocess.run(["bash", str(script)], check=False)
    return int(r.returncode)


def _cmd_build_dbs(_args: argparse.Namespace) -> int:
    r = subprocess.run(["python", "-m", "policy_server.build_dbs"], check=False)
    return int(r.returncode)


def _cmd_mcp_gateway(_args: argparse.Namespace) -> int:
    r = subprocess.run(["python", "-m", "gateway.mcp_server"], check=False)
    return int(r.returncode)

def _cmd_executor(_args: argparse.Namespace) -> int:
    r = subprocess.run(["python", "-m", "executor_server.server"], check=False)
    return int(r.returncode)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mirage-ogpp")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_demo = sub.add_parser("demo", help="Run the full MIRAGE-OG++ demo (policy servers + MCP gateway + nanoclaw agent).")
    p_demo.set_defaults(fn=_cmd_demo)

    p_art = sub.add_parser("artifact", help="Run the paper artifact workload (tests + micro-benchmark + end-to-end demo).")
    p_art.set_defaults(fn=_cmd_artifact)

    p_nc = sub.add_parser("nanoclaw", help="Run the demo via a real agent runtime (Claude Agent SDK / NanoClaw) over MCP.")
    p_nc.set_defaults(fn=_cmd_nanoclaw)

    p_build = sub.add_parser("build-dbs", help="Build policy bitset DBs for the PIR guardrails demo.")
    p_build.set_defaults(fn=_cmd_build_dbs)

    p_ps = sub.add_parser("policy-server", help="Run a policy server (configure via env SERVER_ID/PORT/DATA_DIR).")
    p_ps.set_defaults(fn=lambda _a: subprocess.run(["python", "-m", "policy_server.server"], check=False).returncode)

    p_gw = sub.add_parser("mcp-gateway", help="Run the gateway as an MCP stdio server.")
    p_gw.set_defaults(fn=_cmd_mcp_gateway)

    p_ex = sub.add_parser("executor-server", help="Run the executor server (verifies dual policy MAC proofs).")
    p_ex.set_defaults(fn=_cmd_executor)

    args = p.parse_args(argv)

    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
