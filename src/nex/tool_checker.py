from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from typing import Any

from .catalog import Catalog, ToolDefinition

# ANSI styling
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
DIM = "\033[2m"

# Kali / Debian package installation mapping
PACKAGE_HINTS: dict[str, str] = {
    "nmap": "sudo apt install nmap",
    "whois": "sudo apt install whois",
    "dig": "sudo apt install dnsutils",
    "gobuster": "sudo apt install gobuster",
    "enum4linux": "sudo apt install enum4linux",
    "smbclient": "sudo apt install smbclient",
    "sqlmap": "sudo apt install sqlmap",
    "hydra": "sudo apt install hydra",
    "msfconsole": "sudo apt install metasploit-framework",
    "bash": "default pre-installed",
    "python3": "default pre-installed",
    "linpeas": "sudo apt install peass OR download from github.com/carlospolop/PEASS-ng",
    "pspy": "Download binary from github.com/DominicBreuker/pspy",
    "internal:note_capture": "built-in (ready)",
}


@dataclass
class ToolCheckResult:
    name: str
    phase: str
    tier: str
    binary: str
    installed: bool
    path: str | None
    hint: str


def check_tool(tool: ToolDefinition) -> ToolCheckResult:
    """Inspects a single tool definition and verifies executable presence in PATH."""
    first_cmd = tool.command_template[0] if tool.command_template else tool.name

    # 1. Internal built-in tools
    if first_cmd.startswith("internal:"):
        return ToolCheckResult(
            name=tool.name,
            phase=tool.phase,
            tier=tool.approval_tier,
            binary=first_cmd,
            installed=True,
            path="built-in (Python session memory)",
            hint="ready",
        )

    # 2. Dynamic binary path parameters (e.g. pspy)
    if first_cmd.startswith("{") and first_cmd.endswith("}"):
        candidate = shutil.which(tool.name) or shutil.which("pspy64") or shutil.which("pspy32")
        return ToolCheckResult(
            name=tool.name,
            phase=tool.phase,
            tier=tool.approval_tier,
            binary=tool.name,
            installed=candidate is not None,
            path=candidate,
            hint=PACKAGE_HINTS.get(tool.name, "Standalone script/binary"),
        )

    # 3. Standard executable command (e.g. nmap, gobuster, msfconsole)
    binary = first_cmd
    found_path = shutil.which(binary)
    hint = PACKAGE_HINTS.get(binary, PACKAGE_HINTS.get(tool.name, f"sudo apt install {binary}"))

    return ToolCheckResult(
        name=tool.name,
        phase=tool.phase,
        tier=tool.approval_tier,
        binary=binary,
        installed=found_path is not None,
        path=found_path,
        hint=hint,
    )


def check_all_tools(catalog: Catalog) -> list[ToolCheckResult]:
    """Inspect all catalog tools across all engagement phases."""
    return [check_tool(t) for t in catalog.tools.values()]


def print_tools_checkup(catalog: Catalog) -> dict[str, Any]:
    """Render a clean, formatted OS tool audit report to stdout."""
    results = check_all_tools(catalog)
    total = len(results)
    installed_count = sum(1 for r in results if r.installed)
    missing_results = [r for r in results if not r.installed]

    print(f"\n{BOLD}CyberEDT NEX — System Tool Audit (OS Environment):{RESET}")
    print("=" * 86)
    print(f"  {'#':<3} {'Tool':<15} {'Phase':<25} {'Status':<16} {'Binary / Install Hint'}")
    print("-" * 86)

    for idx, r in enumerate(results, start=1):
        if r.path and "built-in" in r.path:
            badge = f"{GREEN}[✓] BUILT-IN{RESET}"
            pad = "   "
            detail = f"{DIM}{r.path}{RESET}"
        elif r.installed:
            badge = f"{GREEN}[✓] INSTALLED{RESET}"
            pad = "  "
            detail = f"{DIM}{r.path}{RESET}"
        else:
            badge = f"{RED}[✗] MISSING{RESET}"
            pad = "    "
            detail = f"{YELLOW}{r.hint}{RESET}"

        print(f"  {idx:<3} {BOLD}{r.name:<15}{RESET} {r.phase:<26} {badge}{pad} {detail}")

    print("=" * 86)
    summary_color = GREEN if installed_count == total else (YELLOW if installed_count > 0 else RED)
    print(f"  Audit Summary: {summary_color}{BOLD}{installed_count} / {total} tools ready{RESET}")

    if missing_results:
        # Group apt packages for convenience
        apt_packages = []
        for r in missing_results:
            if "sudo apt install" in r.hint:
                pkg = r.hint.replace("sudo apt install", "").strip()
                apt_packages.append(pkg)

        print(f"\n  {BOLD}To install missing packages on Kali Linux:{RESET}")
        if apt_packages:
            print(f"    {CYAN}sudo apt update && sudo apt install -y {' '.join(apt_packages)}{RESET}")
        for r in missing_results:
            if "sudo apt install" not in r.hint and r.hint != "ready":
                print(f"    * {r.name}: {r.hint}")

    print("=" * 86 + "\n")

    return {
        "total": total,
        "installed": installed_count,
        "missing": [r.name for r in missing_results],
    }
