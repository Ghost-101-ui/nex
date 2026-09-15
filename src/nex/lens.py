from __future__ import annotations

import re


def summarize(tool: str, output: str) -> list[str]:
    if tool in {"nmap_scan", "service_probe", "smb_enum", "ftp_anon_check"}:
        matches = re.findall(r"^(\d+/(?:tcp|udp))\s+(open)\s+([^\s]+)(?:\s+(.*))?$", output, re.M)
        return ["  ".join(part for part in row if part) for row in matches[:6]] or ["No open services reported."]
    if tool == "gobuster_dir":
        matches = re.findall(r"^(/\S+)\s+\(Status: (\d+)", output, re.M)
        return [f"{path}  status {status}" for path, status in matches[:6]] or ["No directories reported."]
    if tool == "whatweb_scan":
        matches = [line.strip() for line in output.splitlines() if line.lstrip().startswith("http")]
        return matches[:6] or ["No web technology fingerprint reported."]
    if tool == "dns_enum":
        matches = [line.strip() for line in output.splitlines() if re.search(r"(?:A |AAAA |MX |NS |Name Server)", line)]
        return matches[:6] or ["No DNS records reported."]
    if tool == "nikto_scan":
        matches = [line.strip() for line in output.splitlines() if line.lstrip().startswith(("+", "-"))]
        return matches[:6] or ["No Nikto findings reported."]
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return lines[-6:] or ["No output reported."]
