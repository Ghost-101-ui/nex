from __future__ import annotations

import re


def summarize(tool: str, output: str) -> list[str]:
    if tool in {"nmap_scan", "service_probe"}:
        matches = re.findall(r"^(\d+/(?:tcp|udp))\s+(open)\s+([^\s]+)(?:\s+(.*))?$", output, re.M)
        return ["  ".join(part for part in row if part) for row in matches[:6]] or ["No open services reported."]
    if tool == "gobuster_dir":
        matches = re.findall(r"^(/\S+)\s+\(Status: (\d+)", output, re.M)
        return [f"{path}  status {status}" for path, status in matches[:6]] or ["No directories reported."]
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return lines[-6:] or ["No output reported."]
