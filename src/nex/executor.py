from __future__ import annotations

import shutil
import subprocess
from typing import Any

from .models import Tool


def build_command(tool: Tool, args: dict[str, Any]) -> list[str]:
    if tool.name == "nmap_scan":
        scan = {"quick": ["-sV", "--top-ports", "100"], "full": ["-sV", "-sC", "-p-"], "udp": ["-sU", "--top-ports", "50"]}[args["scan_type"]]
        return ["nmap", *scan, *( ["-p", str(args["ports"])] if args.get("ports") else []), args["target"]]
    if tool.name == "whatweb_scan": return ["whatweb", args["target"]]
    if tool.name == "dns_enum": return ["dnsrecon", "-d", args["domain"], "-t", {"subdomains": "brt", "records": "std"}[args["mode"]]]
    if tool.name == "nikto_scan": return ["nikto", "-h", args["target"]]
    if tool.name == "gobuster_dir":
        words = {"small": "/usr/share/wordlists/dirb/common.txt", "medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", "large": "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt"}
        return ["gobuster", "dir", "-u", args["target"], "-w", words[args["wordlist"]], "--no-error"]
    if tool.name == "service_probe": return ["nmap", "-sV", "-p", str(args["port"]), args["target"]]
    if tool.name == "searchsploit_query": return ["searchsploit", args["service_name"], *( [args["version"]] if args.get("version") else [])]
    raise ValueError(f"No executor is registered for {tool.name}.")


def execute(tool: Tool, args: dict[str, Any], timeout: int) -> tuple[int, str]:
    command = build_command(tool, args)
    if not shutil.which(command[0]):
        raise RuntimeError(f"Required executable not found: {command[0]}")
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=timeout, check=False)
    return result.returncode, result.stdout
