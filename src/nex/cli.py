from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any

try:
    import readline
except ImportError:
    readline = None

from . import __version__
from .catalog import Catalog, CatalogValidationError
from .config import find_project_root, load_config
from .controller import Controller, ControllerError, ExecutionResult
from .memory import SessionMemory
from .planner import Planner, PlannerError


# ANSI styling
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_banner(phase: str, dual: bool, scope_count: int) -> None:
    banner = (
        f"{CYAN}{BOLD}\n"
        f"  _   _ _______  _  {RESET}\n"
        f"{CYAN}{BOLD} | \\ | | ____\\ \\/ /  {RESET}\n"
        f"{CYAN}{BOLD} |  \\| |  _|  \\  /   {RESET}\n"
        f"{CYAN}{BOLD} | |\\  | |___ /  \\   {RESET}\n"
        f"{CYAN}{BOLD} |_| \\_|_____/_/\\_\\  {RESET}\n"
        f"{DIM}  CyberEDT NEX v{__version__} | Navigate / Execute / eXplore{RESET}\n"
        f"{DIM}  Authorized Security Training Assistant (Offline Lab Mode){RESET}\n"
        f"  {'-'*58}\n"
        f"  Phase:     {GREEN}{BOLD}{phase}{RESET}\n"
        f"  Inference: {YELLOW}{'Dual Mode (Qwen3 + FunctionGemma)' if dual else 'Single Mode (Qwen3 0.6B)'}{RESET}\n"
        f"  Lab Scope: {scope_count} authorized target/range(s)\n"
        f"  {'-'*58}\n"
        f"  Type your goal in natural language, or use slash commands:\n"
        f"    {CYAN}/phase <name>{RESET}  Switch phase    {CYAN}/f{RESET}       Show full raw output\n"
        f"    {CYAN}/history{RESET}       Show action log {CYAN}/dual{RESET}    Toggle dual mode\n"
        f"    {CYAN}/scope{RESET}         View/add scope  {CYAN}/findings{RESET} Show findings\n"
        f"    {CYAN}/tools{RESET}         List tools      {CYAN}/exit{RESET}     Exit session\n"
    )
    print(banner)


class NexREPL:
    def __init__(
        self,
        catalog: Catalog,
        memory: SessionMemory,
        planner: Planner,
        controller: Controller,
        dual_mode: bool = False,
    ):
        self.catalog = catalog
        self.memory = memory
        self.planner = planner
        self.controller = controller
        self.dual_mode = dual_mode
        self.last_result: ExecutionResult | None = None

    def run(self) -> None:
        scope = self.memory.get_scope()
        print_banner(self.memory.get_phase(), self.dual_mode, len(scope))

        while True:
            current_phase = self.memory.get_phase()
            prompt_str = f"{CYAN}[NEX | {BOLD}{current_phase}{RESET}{CYAN}]>{RESET} "
            try:
                user_input = input(prompt_str).strip()
            except (KeyboardInterrupt, EOFError):
                print(f"\n{YELLOW}Exiting NEX. Session saved.{RESET}")
                break

            if not user_input:
                continue

            # Check slash commands
            if user_input.startswith("/"):
                self.handle_slash_command(user_input)
                continue

            # Process natural language request via Planner & Controller
            self.handle_natural_language(user_input)

    def handle_slash_command(self, cmd_line: str) -> None:
        parts = cmd_line.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("/exit", "/quit", "/q"):
            print(f"{YELLOW}Exiting NEX. Goodbye!{RESET}")
            sys.exit(0)

        elif cmd == "/phase":
            if not arg:
                print(f"Current phase: {GREEN}{self.memory.get_phase()}{RESET}")
                print(f"Available phases: {', '.join(self.catalog.phases)}")
            else:
                if arg in self.catalog.phases:
                    self.memory.set_phase(arg)
                    print(f"[+] Active phase switched to: {GREEN}{BOLD}{arg}{RESET}")
                else:
                    print(f"{RED}Unknown phase '{arg}'. Allowed: {', '.join(self.catalog.phases)}{RESET}")

        elif cmd == "/dual":
            self.dual_mode = not self.dual_mode
            status = "ENABLED" if self.dual_mode else "DISABLED"
            print(f"[+] Dual-model reasoning mode: {YELLOW}{status}{RESET}")

        elif cmd in ("/f", "/full"):
            last_raw = self.memory.get_last_raw_output()
            if last_raw:
                print(f"\n{DIM}--- Full Raw Output ---{RESET}")
                print(last_raw)
                print(f"{DIM}--- End Raw Output ---{RESET}\n")
            else:
                print(f"{YELLOW}No previous command raw output available.{RESET}")

        elif cmd == "/history":
            history = self.memory.get_recent_history(limit=15)
            if not history:
                print("No history recorded yet.")
                return
            print(f"\n{BOLD}Session Action History ({len(history)} entries):{RESET}")
            for h in history:
                status_color = GREEN if h["status"] == "EXECUTED" else (RED if h["status"] in ("FAILED", "TIMEOUT") else YELLOW)
                print(
                    f"  [{status_color}{h['status']:<8}{RESET}] "
                    f"{h['tool']} ({h['phase']}) | Tier: {h['approval_tier']}"
                )
                print(f"    Args: {h['args']}")
                print(f"    Reasoning: {h['reasoning']}")
                if h["summary"]:
                    print(f"    Result: {h['summary'][0]}")
            print()

        elif cmd == "/findings":
            findings = self.memory.get_findings()
            if not findings:
                print("No findings recorded yet.")
                return
            print(f"\n{MAGENTA}{BOLD}Discovered Session Findings ({len(findings)}):{RESET}")
            for f in findings:
                print(f"  * [{f['phase']}] {f['tool']} ({f['category']}): {f['finding']}")
            print()

        elif cmd == "/scope":
            if not arg:
                scope = self.memory.get_scope()
                print(f"\n{BOLD}Authorized Lab Scope:{RESET}")
                for s in scope:
                    print(f"  * {s}")
                print()
            else:
                self.memory.add_scope(arg)
                print(f"[+] Added to authorized lab scope: {GREEN}{arg}{RESET}")

        elif cmd == "/tools":
            current_phase = self.memory.get_phase()
            tools = self.catalog.get_tools_for_phase(current_phase)
            print(f"\n{BOLD}Tools for phase '{current_phase}' (and utility):{RESET}")
            for t in tools:
                tier_color = GREEN if t.approval_tier == "AUTO" else YELLOW
                print(f"  * {BOLD}{t.name:<14}{RESET} [{tier_color}{t.approval_tier}{RESET}] ({t.phase}) - {t.description}")
            print()

        elif cmd in ("/help", "/?"):
            print(f"""
{BOLD}NEX Slash Commands:{RESET}
  /phase <name>    View or change active CTF training phase
  /history         View recent tool invocations and operator decisions
  /f               Display full raw cached output of last run
  /dual            Toggle dual-model reasoning mode (Qwen3 + FunctionGemma)
  /scope [target]  View or add authorized IP/subnet/domain scope
  /findings        View all structured findings extracted by Summarizer
  /tools           List catalog tools available for current phase
  /exit            Exit the session
""")
        else:
            print(f"{RED}Unknown command '{cmd}'. Type /help for available commands.{RESET}")

    def handle_natural_language(self, user_input: str) -> None:
        current_phase = self.memory.get_phase()

        # Step 1: Planner constructs structured request
        try:
            print(f"{DIM}Thinking...{RESET}", end="\r")
            plan_req = self.planner.plan(user_input, dual=self.dual_mode)
        except PlannerError as exc:
            print(f"{RED}[!] Planner Error: {exc}{RESET}")
            return

        tool_name = plan_req["tool"]
        tool_args = plan_req["args"]
        reasoning = plan_req.get("reasoning", "")
        plan_phase = plan_req.get("phase", current_phase)

        # Show proposed request before running (even for AUTO tier)
        tool_def = self.catalog.get_tool(tool_name)
        tier_str = tool_def.approval_tier if tool_def else "AUTO"
        cmd_preview = self.controller.build_command_args(tool_def, tool_args) if tool_def else [tool_name]
        cmd_preview_str = " ".join(shlex.quote(c) for c in cmd_preview)

        print(f"\n{CYAN}→ Proposed Tool Call:{RESET} {BOLD}{tool_name}{RESET} [{tier_str}]")
        print(f"  Command:   {cmd_preview_str}")
        print(f"  Reasoning: {reasoning}")

        # Step 2: Controller Gate execution & validation
        try:
            result = self.controller.execute_request(
                tool_name=tool_name,
                args=tool_args,
                reasoning=reasoning,
            )
            self.last_result = result

            if result.status == "STOPPED":
                print(f"{YELLOW}[!] Action STOPPED by operator. Logged to session memory.{RESET}\n")
                return

            if result.status == "FAILED":
                print(f"{RED}[!] Execution Failed (exit {result.exit_code}):{RESET}")
                for s in result.summary:
                    print(f"    {s}")
                print(f"{DIM}Note: Failed execution context saved for Planner.{RESET}\n")
                return

            if result.status == "TIMEOUT":
                print(f"{RED}[!] Execution Timed Out after {result.duration_sec}s.{RESET}\n")
                return

            # Successful execution -> Display Summarizer result
            print(f"\n{GREEN}[✓] Executed successfully in {result.duration_sec}s (exit {result.exit_code}){RESET}")
            print(f"{BOLD}Summary:{RESET}")
            for line in result.summary:
                print(f"  {line}")

            print(f"\n{DIM}[Tip: Type /f to view the complete raw output]{RESET}\n")

        except ControllerError as exc:
            print(f"{RED}[!] Controller Gate Blocked Action: {exc}{RESET}\n")
        except Exception as exc:
            print(f"{RED}[!] Unexpected error: {exc}{RESET}\n")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nex",
        description="CyberEDT NEX: Offline, gated assistant for authorized cybersecurity training labs",
    )
    parser.add_argument(
        "--dual",
        action="store_true",
        help="Enable dual-model mode (Qwen3 reasoner + FunctionGemma structured request generator)",
    )
    parser.add_argument(
        "--phase",
        choices=["reconnaissance", "service_enumeration", "vulnerability_assessment", "post_engagement_review", "utility"],
        help="Initial training phase",
    )
    parser.add_argument(
        "--target",
        help="Target IP/domain to add to authorized scope on startup",
    )
    parser.add_argument(
        "--ephemeral",
        action="store_true",
        help="Run in ephemeral mode (in-memory SQLite database, no persistent state saved)",
    )
    parser.add_argument(
        "--catalog",
        default=None,
        help="Path to custom catalog.yaml",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to custom config.yaml",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"CyberEDT NEX {__version__}",
    )

    # Subparsers for CLI automation
    subparsers = parser.add_subparsers(dest="subcommand")

    # repl subcommand (default if no subcommand)
    subparsers.add_parser("repl", help="Start the interactive REPL session")

    # tools subcommand
    subparsers.add_parser("tools", help="List tools defined in the catalog")

    # status subcommand
    status_parser = subparsers.add_parser("status", help="Show system status and session details")
    status_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # init subcommand
    init_parser = subparsers.add_parser("init", help="Initialize or refresh lab scope and config")
    init_parser.add_argument("scope", nargs="?", help="Target IP or CIDR scope to add")

    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    project_root = find_project_root()
    catalog_path = Path(args.catalog) if args.catalog else project_root / "catalog.yaml"
    config_data = load_config(args.config)

    # Load and validate catalog (fail fast)
    try:
        catalog = Catalog.from_yaml_file(catalog_path)
    except CatalogValidationError as exc:
        print(f"{RED}[FATAL] Catalog validation failed: {exc}{RESET}", file=sys.stderr)
        sys.exit(1)

    # Memory setup
    if args.ephemeral:
        db_path = ":memory:"
    else:
        db_path = project_root / config_data.get("session", {}).get("memory_db_path", ".nex/session.db")

    artifacts_dir = project_root / config_data.get("session", {}).get("artifacts_dir", ".nex/raw")
    memory = SessionMemory(db_path=db_path, artifacts_dir=artifacts_dir)

    # Populate scope from config and command-line
    for scope_item in config_data.get("scope", {}).get("allowed_targets", []):
        memory.add_scope(scope_item)

    if args.target:
        memory.add_scope(args.target)

    # Set initial phase if specified
    if args.phase:
        memory.set_phase(args.phase)

    # Subcommand dispatch
    if args.subcommand == "tools":
        print(f"CyberEDT NEX Tool Catalog ({len(catalog.tools)} tools registered):\n")
        for phase in catalog.phases:
            tools = catalog.get_tools_for_phase(phase, include_utility=False)
            if tools:
                print(f"[{phase.upper()}]")
                for t in tools:
                    print(f"  * {t.name:<15} [{t.approval_tier}] - {t.description}")
        sys.exit(0)

    if args.subcommand == "status":
        status_info = {
            "version": __version__,
            "phase": memory.get_phase(),
            "scope": memory.get_scope(),
            "tools_count": len(catalog.tools),
            "ephemeral": args.ephemeral,
            "database": str(db_path),
            "history_count": len(memory.get_recent_history(limit=100)),
            "findings_count": len(memory.get_findings()),
        }
        if getattr(args, "json", False):
            print(json.dumps(status_info, indent=2))
        else:
            print(f"NEX Status (v{__version__}):")
            print(f"  Active Phase:   {status_info['phase']}")
            print(f"  Scope Count:    {len(status_info['scope'])}")
            print(f"  Catalog Tools:  {status_info['tools_count']}")
            print(f"  Database:       {status_info['database']}")
        sys.exit(0)

    if args.subcommand == "init":
        if args.scope:
            memory.add_scope(args.scope)
            print(f"[+] Added scope: {args.scope}")
        print("[+] NEX initialization complete. Scope refreshed.")
        sys.exit(0)

    # Initialize Planner and Controller
    planner_cfg = config_data.get("models", {})
    planner = Planner(
        catalog=catalog,
        memory=memory,
        planner_model_path=project_root / planner_cfg.get("planner_model_path", "models/qwen3-0.6b-instruct.Q4_K_M.gguf"),
        tool_caller_model_path=project_root / planner_cfg.get("tool_caller_model_path", "models/functiongemma-270m-it.Q8_0.gguf"),
        dual_mode=args.dual or planner_cfg.get("dual_mode", False),
        temperature=planner_cfg.get("temperature", 0.1),
    )

    controller = Controller(
        catalog=catalog,
        memory=memory,
        default_timeout=config_data.get("execution", {}).get("default_timeout_seconds", 300),
    )

    # Launch interactive REPL
    repl = NexREPL(
        catalog=catalog,
        memory=memory,
        planner=planner,
        controller=controller,
        dual_mode=args.dual or planner_cfg.get("dual_mode", False),
    )
    repl.run()


if __name__ == "__main__":
    main()
