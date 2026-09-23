from __future__ import annotations

import argparse
import json
import os
import random
import shlex
import sys
import time
from pathlib import Path
from typing import Any

try:
    import readline
except ImportError:
    readline = None

# Ensure stdout supports UTF-8 characters (especially on Windows legacy codepages)
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from . import __version__
from .catalog import Catalog, CatalogValidationError
from .config import find_project_root, load_config
from .controller import Controller, ControllerError, ExecutionResult
from .memory import SessionMemory
from .models_manager import download_models, install_llama_cpp_runtime
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

PHASE_ALIASES: dict[str, str] = {
    "1": "reconnaissance",
    "recon": "reconnaissance",
    "reconnaissance": "reconnaissance",
    "2": "service_enumeration",
    "enum": "service_enumeration",
    "enumeration": "service_enumeration",
    "service_enumeration": "service_enumeration",
    "3": "vulnerability_assessment",
    "vuln": "vulnerability_assessment",
    "vulnerability": "vulnerability_assessment",
    "vulnerability_assessment": "vulnerability_assessment",
    "4": "post_engagement_review",
    "post": "post_engagement_review",
    "review": "post_engagement_review",
    "post_engagement_review": "post_engagement_review",
    "5": "utility",
    "util": "utility",
    "utility": "utility",
}


def resolve_phase(query: str, phases: list[str]) -> str | None:
    """Resolve a phase query (number 1-5, short name, or exact name) to canonical phase."""
    q = query.strip().lower()
    if q in PHASE_ALIASES and PHASE_ALIASES[q] in phases:
        return PHASE_ALIASES[q]
    if q.isdigit():
        idx = int(q) - 1
        if 0 <= idx < len(phases):
            return phases[idx]
    for p in phases:
        if p.lower() == q:
            return p
    return None


def check_models_status(project_root: Path, config_data: dict[str, Any]) -> dict[str, Any]:
    """Inspect local filesystem and Python environment to report model availability."""
    planner_cfg = config_data.get("models", {})
    qwen_rel = planner_cfg.get("planner_model_path", "models/qwen3-0.6b-instruct.Q4_K_M.gguf")
    gemma_rel = planner_cfg.get("tool_caller_model_path", "models/functiongemma-270m-it.Q8_0.gguf")

    qwen_path = project_root / qwen_rel
    gemma_path = project_root / gemma_rel

    try:
        import llama_cpp
        llama_cpp_installed = True
    except ImportError:
        llama_cpp_installed = False

    qwen_exists = qwen_path.is_file()
    qwen_size = f"{qwen_path.stat().st_size / (1024 * 1024):.1f} MB" if qwen_exists else None

    gemma_exists = gemma_path.is_file()
    gemma_size = f"{gemma_path.stat().st_size / (1024 * 1024):.1f} MB" if gemma_exists else None

    if llama_cpp_installed and qwen_exists:
        mode = "Local GGUF Model Inference (llama-cpp-python)"
    else:
        mode = "Deterministic Heuristic Fallback Engine (Active & Offline)"

    return {
        "llama_cpp_installed": llama_cpp_installed,
        "qwen_path": qwen_path,
        "qwen_exists": qwen_exists,
        "qwen_size": qwen_size,
        "gemma_path": gemma_path,
        "gemma_exists": gemma_exists,
        "gemma_size": gemma_size,
        "mode": mode,
    }


def print_models_status(status: dict[str, Any]) -> None:
    """Print human-readable local model and inference engine status."""
    print(f"\n{BOLD}CyberEDT NEX — Local Model Verification:{RESET}")
    print("=" * 60)

    if status["llama_cpp_installed"]:
        print(f"  Inference Runtime:  {GREEN}[✓] llama-cpp-python INSTALLED{RESET}")
    else:
        print(f"  Inference Runtime:  {YELLOW}[-] llama-cpp-python NOT INSTALLED{RESET}")
        print(f"                      {DIM}(Install: pip install llama-cpp-python){RESET}")

    if status["qwen_exists"]:
        print(f"  Qwen3 0.6B GGUF:    {GREEN}[✓] FOUND{RESET} ({status['qwen_size']})")
        print(f"                      {DIM}{status['qwen_path']}{RESET}")
    else:
        print(f"  Qwen3 0.6B GGUF:    {YELLOW}[-] NOT FOUND{RESET}")
        print(f"                      Expected at: {status['qwen_path']}")

    if status["gemma_exists"]:
        print(f"  FunctionGemma GGUF: {GREEN}[✓] FOUND{RESET} ({status['gemma_size']})")
        print(f"                      {DIM}{status['gemma_path']}{RESET}")
    else:
        print(f"  FunctionGemma GGUF: {DIM}[-] NOT FOUND (optional, for --dual mode){RESET}")
        print(f"                      Expected at: {status['gemma_path']}")

    print("-" * 60)
    print(f"  Current Mode:       {CYAN}{BOLD}{status['mode']}{RESET}")
    print(f"\n  {BOLD}Quick Commands:{RESET}")
    print(f"    * Download GGUF weights:      {CYAN}nex models download{RESET}  (or in REPL: {CYAN}/m download{RESET})")
    print(f"    * Install inference engine:   {CYAN}nex models install{RESET}   (or in REPL: {CYAN}/m install{RESET})")
    print(f"    * Offline/Manual copy:        Place .gguf file into {CYAN}models/{RESET}")
    if not status["qwen_exists"] or not status["llama_cpp_installed"]:
        print(f"\n  {DIM}Note: NEX runs completely offline using the deterministic fallback engine.{RESET}")
    print("=" * 60 + "\n")


def gradient_green(text: str) -> None:
    """Print text line-by-line in a green gradient (dark -> bright)."""
    shades = [22, 28, 34, 40, 46, 82, 118]  # ANSI 256-color green ramp
    lines = text.strip("\n").split("\n")
    for i, line in enumerate(lines):
        shade = shades[min(i, len(shades) - 1)]
        try:
            print(f"\033[38;5;{shade}m{line}{RESET}")
        except UnicodeEncodeError:
            # Fallback if terminal cannot print unicode block characters
            safe_line = line.encode("ascii", "replace").decode("ascii")
            print(f"\033[38;5;{shade}m{safe_line}{RESET}")


def type_out(text: str, delay: float = 0.015, color: str = "\033[92m") -> None:
    """Type out text character-by-character with customizable delay."""
    is_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    for ch in text:
        sys.stdout.write(f"{color}{ch}{RESET}")
        sys.stdout.flush()
        if is_tty and delay > 0:
            time.sleep(delay)
    print()


def boot_sequence(skip_delay: bool = False) -> None:
    """Simulate system initialization and module mounting sequence."""
    steps = [
        "Initializing NEX core...",
        "Loading Qwen3 0.6B reasoning model...",
        "Mounting tool catalog (5 phases)...",
        "Starting Controller/Gate...",
        "Session memory: ready.",
    ]
    is_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and not skip_delay
    for step in steps:
        type_out(f"[NEX] {step}", delay=0.01 if is_tty else 0.0)
        if is_tty:
            time.sleep(random.uniform(0.04, 0.12))
    print()


def print_logo() -> None:
    """Display stylized NEX logo in 256-color green gradient."""
    logo = r"""
 ███╗   ██╗███████╗██╗  ██╗
 ████╗  ██║██╔════╝╚██╗██╔╝
 ██╔██╗ ██║█████╗   ╚███╔╝
 ██║╚██╗██║██╔══╝   ██╔██╗
 ██║ ╚████║███████╗██╔╝ ██╗
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
"""
    gradient_green(logo)
    try:
        print(f"{BOLD}\033[92m   Navigate · Execute · eXplore{RESET}")
        print(f"\033[90m   CyberEDT offline CTF agent — v{__version__}{RESET}\n")
    except UnicodeEncodeError:
        print(f"{BOLD}\033[92m   Navigate * Execute * eXplore{RESET}")
        print(f"\033[90m   CyberEDT offline CTF agent - v{__version__}{RESET}\n")


def print_banner(
    phase: str,
    dual: bool,
    scope_count: int,
    target: str | None = None,
    phases: list[str] | None = None,
    skip_boot: bool = False,
) -> None:
    if not skip_boot:
        boot_sequence()
        print_logo()

    target_display = f"{GREEN}{BOLD}{target}{RESET}" if target else f"{DIM}None (set with /target <ip> or /t <ip>){RESET}"
    phase_num_prefix = ""
    if phases and phase in phases:
        phase_num_prefix = f"[{phases.index(phase) + 1}] "
    banner = (
        f"  {'-'*58}\n"
        f"  Phase:     {GREEN}{BOLD}{phase_num_prefix}{phase}{RESET}\n"
        f"  Target:    {target_display}\n"
        f"  Inference: {YELLOW}{'Dual Mode (Qwen3 + FunctionGemma)' if dual else 'Single Mode (Qwen3 0.6B)'}{RESET}\n"
        f"  Lab Scope: {scope_count} authorized target/range(s)\n"
        f"  {'-'*58}\n"
        f"  Type your goal in natural language, or use slash commands:\n"
        f"    {CYAN}/phase <1-5>{RESET} Switch phase (or /p) {CYAN}/target <ip>{RESET}  Set target (or /t)\n"
        f"    {CYAN}/history{RESET}     Show action log       {CYAN}/f{RESET}          Show full raw output\n"
        f"    {CYAN}/scope{RESET}       View/add scope        {CYAN}/dual{RESET}       Toggle dual mode\n"
        f"    {CYAN}/tools{RESET}       List tools            {CYAN}/findings{RESET}   Show findings\n"
        f"    {CYAN}/models{RESET}      Check LLM status      {CYAN}/exit{RESET}        Exit session\n"
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
        fast_boot: bool = False,
    ):
        self.catalog = catalog
        self.memory = memory
        self.planner = planner
        self.controller = controller
        self.dual_mode = dual_mode
        self.fast_boot = fast_boot
        self.last_result: ExecutionResult | None = None

    def run(self) -> None:
        scope = self.memory.get_scope()
        print_banner(
            self.memory.get_phase(),
            self.dual_mode,
            len(scope),
            self.memory.get_target(),
            self.catalog.phases,
            skip_boot=self.fast_boot,
        )

        while True:
            current_phase = self.memory.get_phase()
            active_target = self.memory.get_target()
            if active_target:
                prompt_str = f"{CYAN}[NEX | {BOLD}{current_phase}{RESET}{CYAN} | {GREEN}{BOLD}{active_target}{RESET}{CYAN}]>{RESET} "
            else:
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

        elif cmd in ("/target", "/t"):
            if not arg:
                current_target = self.memory.get_target()
                if current_target:
                    print(f"Active lab target: {GREEN}{BOLD}{current_target}{RESET}")
                    print(f"Authorized scope: {', '.join(self.memory.get_scope()) or 'None'}")
                    print(f"Tip: Use {CYAN}/target <ip>{RESET} or {CYAN}/t <ip>{RESET} to change (or {CYAN}/target clear{RESET} to unset)")
                else:
                    print(f"{YELLOW}No active lab target set.{RESET}")
                    print(f"Usage: {CYAN}/target <ip_or_domain>{RESET} or {CYAN}/t <ip_or_domain>{RESET} (shortcut for nex --target)")
            elif arg.lower() in ("clear", "unset", "none"):
                self.memory.set_target(None)
                print(f"[+] Cleared active lab target.")
            else:
                self.memory.add_scope(arg)
                self.memory.set_target(arg)
                print(f"[+] Active lab target set to: {GREEN}{BOLD}{arg}{RESET} (added to authorized scope)")

        elif cmd in ("/phase", "/p"):
            if not arg:
                current_p = self.memory.get_phase()
                try:
                    curr_num = self.catalog.phases.index(current_p) + 1
                    num_prefix = f"[{curr_num}] "
                except ValueError:
                    num_prefix = ""
                print(f"Current phase: {GREEN}{BOLD}{num_prefix}{current_p}{RESET}")
                print(f"\n{BOLD}Available training phases:{RESET}")
                for i, p in enumerate(self.catalog.phases, start=1):
                    marker = f"{GREEN}* {RESET}" if p == current_p else "  "
                    print(f"{marker}[{i}] {p}")
                print(f"\nTip: Use {CYAN}/phase <1-5>{RESET} or {CYAN}/p <1-5>{RESET} to switch fast (e.g. {CYAN}/p 2{RESET} or {CYAN}/p next{RESET})")
            elif arg.lower() in ("next", "n", "+"):
                current_p = self.memory.get_phase()
                try:
                    idx = self.catalog.phases.index(current_p)
                    next_idx = (idx + 1) % len(self.catalog.phases)
                except ValueError:
                    next_idx = 0
                next_phase = self.catalog.phases[next_idx]
                self.memory.set_phase(next_phase)
                print(f"[+] Active phase switched to: [{next_idx + 1}] {GREEN}{BOLD}{next_phase}{RESET}")
            else:
                resolved = resolve_phase(arg, self.catalog.phases)
                if resolved:
                    self.memory.set_phase(resolved)
                    idx = self.catalog.phases.index(resolved) + 1
                    print(f"[+] Active phase switched to: [{idx}] {GREEN}{BOLD}{resolved}{RESET}")
                else:
                    options = ", ".join(f"[{i+1}] {p}" for i, p in enumerate(self.catalog.phases))
                    print(f"{RED}Unknown phase '{arg}'. Allowed numbers 1-{len(self.catalog.phases)} or names: {options}{RESET}")

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

        elif cmd in ("/models", "/m"):
            project_root = find_project_root()
            config_data = load_config()
            if arg in ("download", "d"):
                download_models(project_root, config_data)
            elif arg in ("install", "i"):
                install_llama_cpp_runtime()
            else:
                status = check_models_status(project_root, config_data)
                print_models_status(status)

        elif cmd in ("/help", "/?"):
            print(f"""
{BOLD}NEX Slash Commands:{RESET}
  /phase <1-5|name> Switch phase by number or name (shortcut: /p)
  /p <1-5|name>     Fast phase switch (e.g. /p 2: enum, /p 3: vuln, /p next)
  /target <ip>     Set active lab target IP/domain and add to scope (shortcut: /t)
  /t <ip>          Quick shortcut for /target (equivalent to nex --target)
  /models          Check local GGUF model files and inference engine status (shortcut: /m)
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
        help="Initial training phase name or number (1-5)",
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
        "--fast",
        action="store_true",
        help="Skip animated boot sequence on startup",
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

    # models subcommand
    models_parser = subparsers.add_parser("models", help="Check, download, or install local GGUF models")
    models_parser.add_argument("action", nargs="?", choices=["status", "download", "install"], default="status", help="Action: status, download, or install")
    models_parser.add_argument("--download", action="store_true", help="Download default GGUF model weights into models/ directory")
    models_parser.add_argument("--install", action="store_true", help="Install llama-cpp-python inference runtime via pip")

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
        memory.set_target(args.target)

    # Set initial phase if specified
    if args.phase:
        resolved_phase = resolve_phase(args.phase, catalog.phases)
        if resolved_phase:
            memory.set_phase(resolved_phase)
        else:
            print(f"{RED}[WARN] Unknown phase '{args.phase}'. Using default phase.{RESET}")

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

    if args.subcommand == "models":
        action = args.action
        if getattr(args, "download", False):
            action = "download"
        elif getattr(args, "install", False):
            action = "install"

        if action == "download":
            download_models(project_root, config_data)
            sys.exit(0)
        elif action == "install":
            install_llama_cpp_runtime()
            sys.exit(0)
        else:
            model_status = check_models_status(project_root, config_data)
            print_models_status(model_status)
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
        fast_boot=getattr(args, "fast", False),
    )
    repl.run()


if __name__ == "__main__":
    main()
