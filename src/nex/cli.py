from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys

from .config import config_path, initialize, load_config
from .executor import execute
from .gate import Gate, GateError
from .lens import summarize
from .registry import TOOLS


def main() -> None:
    parser = argparse.ArgumentParser(prog="nex", description="Gated orchestration for authorized security labs")
    subs = parser.add_subparsers(dest="command", required=True)
    init = subs.add_parser("init"); init.add_argument("--scope", required=True, help="Comma-separated authorized IP/CIDR/domain scope")
    subs.add_parser("status"); subs.add_parser("tools")
    run = subs.add_parser("run"); run.add_argument("tool", choices=sorted(TOOLS)); run.add_argument("--args", required=True, help="JSON arguments")
    ns = parser.parse_args()
    try:
        if ns.command == "init":
            path = initialize([x.strip() for x in ns.scope.split(",") if x.strip()])
            print(f"Created {path}. Review the scope before running tools."); return
        if ns.command == "tools":
            for tool in TOOLS.values(): print(f"{tool.name:18} {tool.phase.value:14} {tool.risk.value}")
            return
        if ns.command == "status":
            config = load_config()
            print(f"config: {config_path()}\nscope: {', '.join(config['scope'])}\nphase: {config['phase']}\nregistered tools: {len(TOOLS)}\nollama: {'available' if shutil.which('ollama') else 'not found'}")
            return
        config, tool, args = load_config(), TOOLS[ns.tool], json.loads(ns.args)
        Gate().authorize(tool, args, config)
        code, output = execute(tool, args, int(config.get("timeouts", {}).get(tool.name, config.get("timeouts", {}).get("default", 120))))
        print(f"✓ {tool.name} (exit {code})")
        print("\n".join(summarize(tool.name, output)))
        print("\nRaw output is captured by this process; persistent session logging is the next milestone.")
    except (ValueError, GateError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"NEX blocked: {exc}", file=sys.stderr); raise SystemExit(2)


if __name__ == "__main__": main()
