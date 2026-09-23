from __future__ import annotations

import re
from typing import Any, Callable


def parse_nmap(output: str) -> dict[str, Any]:
    """Extract open ports, services, versions, and host state from nmap output."""
    summary_lines = []
    findings = []
    
    # Check host status
    host_match = re.search(r"Host is up(?: \(([^)]+)\))?", output)
    if host_match:
        latency = f" ({host_match.group(1)})" if host_match.group(1) else ""
        summary_lines.append(f"Host status: UP{latency}")
    else:
        summary_lines.append("Host status: Unknown or Unresponsive")

    # Parse open ports table
    # Format: 22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu
    port_matches = re.findall(
        r"^(\d+/(?:tcp|udp))\s+(open[^\s]*)\s+([^\s]+)(?:\s+(.*))?$",
        output,
        re.MULTILINE,
    )

    if port_matches:
        summary_lines.append(f"Discovered {len(port_matches)} open port(s):")
        for port, state, service, version in port_matches[:12]:
            ver_str = f" [{version.strip()}]" if version and version.strip() else ""
            line = f"  • {port:<10} {state:<6} {service:<12}{ver_str}"
            summary_lines.append(line)
            findings.append({
                "category": "open_port",
                "finding": f"{port} ({service}{ver_str})",
            })
        if len(port_matches) > 12:
            summary_lines.append(f"  ... and {len(port_matches) - 12} more ports")
    else:
        summary_lines.append("No open ports reported.")

    # Check for OS details
    os_match = re.search(r"OS details:\s*(.*)", output)
    if os_match:
        os_info = os_match.group(1).strip()
        summary_lines.append(f"OS Detection: {os_info}")
        findings.append({"category": "os_detection", "finding": os_info})

    return {
        "summary": summary_lines,
        "findings": findings,
    }


def parse_whois(output: str) -> dict[str, Any]:
    """Extract key registrar, dates, and nameservers from whois output."""
    summary_lines = []
    findings = []

    fields = {
        "Registrar": r"Registrar:\s*(.*)",
        "Creation Date": r"Creation Date:\s*(.*)",
        "Registry Expiry Date": r"Registry Expiry Date:\s*(.*)",
        "Registrant Org": r"Registrant Organization:\s*(.*)",
    }

    found_any = False
    for label, pattern in fields.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            val = match.group(1).strip()
            summary_lines.append(f"{label}: {val}")
            findings.append({"category": label.lower().replace(" ", "_"), "finding": val})
            found_any = True

    # Name servers
    ns_matches = re.findall(r"Name Server:\s*([^\s\r\n]+)", output, re.IGNORECASE)
    if ns_matches:
        unique_ns = sorted(set(ns.lower() for ns in ns_matches))
        summary_lines.append(f"Name Servers ({len(unique_ns)}): {', '.join(unique_ns[:4])}")
        found_any = True

    if not found_any:
        # Generic non-empty lines preview
        lines = [line.strip() for line in output.splitlines() if line.strip() and not line.startswith("%")]
        summary_lines = lines[:6] or ["No standard WHOIS records found."]

    return {
        "summary": summary_lines,
        "findings": findings,
    }


def parse_dig(output: str) -> dict[str, Any]:
    """Extract DNS answers, query status, and records from dig output."""
    summary_lines = []
    findings = []

    status_match = re.search(r"status:\s*([A-Z]+)", output)
    status = status_match.group(1) if status_match else "UNKNOWN"
    summary_lines.append(f"DNS Query Status: {status}")

    # Answer section records
    # Format: example.com.  300  IN  A  93.184.216.34
    answers = re.findall(
        r"^([^\s;]+)\s+\d+\s+IN\s+([A-Z]+)\s+(.*)$",
        output,
        re.MULTILINE,
    )

    if answers:
        summary_lines.append(f"Answers ({len(answers)} record(s)):")
        for domain, rec_type, data in answers[:8]:
            line = f"  • {rec_type:<6} {domain:<20} -> {data.strip()}"
            summary_lines.append(line)
            findings.append({"category": f"dns_{rec_type.lower()}", "finding": f"{domain} -> {data.strip()}"})
    else:
        # Check if there are raw output lines
        raw_lines = [l.strip() for l in output.splitlines() if l.strip() and not l.startswith(";")]
        if raw_lines:
            summary_lines.extend(raw_lines[:6])
        else:
            summary_lines.append("No DNS answer records returned.")

    return {
        "summary": summary_lines,
        "findings": findings,
    }


def parse_gobuster(output: str) -> dict[str, Any]:
    """Extract discovered web paths and HTTP status codes from gobuster output."""
    summary_lines = []
    findings = []

    # Format: /admin (Status: 200) [Size: 1234]
    # or /login (Status: 301) [Size: 0] [--> /login/]
    matches = re.findall(
        r"^(/[^\s]+)\s+\(Status:\s*(\d+)\)(?:\s+\[(?:Size:\s*\d+)?\])?(?:\s+\[-->\s*([^\]]+)\])?",
        output,
        re.MULTILINE,
    )

    if matches:
        summary_lines.append(f"Discovered {len(matches)} path(s):")
        for path, status, redirect in matches[:10]:
            redir_str = f" -> {redirect.strip()}" if redirect else ""
            line = f"  • {path:<25} (HTTP {status}){redir_str}"
            summary_lines.append(line)
            findings.append({"category": "web_path", "finding": f"{path} (HTTP {status}){redir_str}"})
        if len(matches) > 10:
            summary_lines.append(f"  ... and {len(matches) - 10} more paths")
    else:
        summary_lines.append("No paths discovered.")

    return {
        "summary": summary_lines,
        "findings": findings,
    }


def parse_enum4linux(output: str) -> dict[str, Any]:
    """Extract OS details, workgroup, users, and shares from enum4linux output."""
    summary_lines = []
    findings = []

    # Domain/Workgroup
    workgroup_match = re.search(r"Domain/Workgroup name:\s*([^\r\n]+)", output)
    if workgroup_match:
        wg = workgroup_match.group(1).strip()
        summary_lines.append(f"Workgroup/Domain: {wg}")
        findings.append({"category": "smb_workgroup", "finding": wg})

    # OS Info
    os_match = re.search(r"OS info:\s*([^\r\n]+)", output)
    if os_match:
        os_info = os_match.group(1).strip()
        summary_lines.append(f"Target OS: {os_info}")
        findings.append({"category": "os_info", "finding": os_info})

    # Users
    users = re.findall(r"user:\[([^\]]+)\]", output, re.IGNORECASE)
    if users:
        unique_users = sorted(set(users))
        summary_lines.append(f"Discovered Users ({len(unique_users)}): {', '.join(unique_users[:8])}")
        for u in unique_users[:5]:
            findings.append({"category": "user_account", "finding": u})

    # Shares
    shares = re.findall(r"//[^\s/]+/([^\s]+)\s+Mapping:\s*([^\s,]+)", output)
    if shares:
        summary_lines.append(f"Discovered Shares ({len(shares)}):")
        for share_name, mapping in shares[:6]:
            summary_lines.append(f"  • {share_name:<16} (Mapping: {mapping})")
            findings.append({"category": "smb_share", "finding": f"{share_name} ({mapping})"})

    if not summary_lines:
        lines = [l.strip() for l in output.splitlines() if l.strip()]
        summary_lines = lines[-6:] or ["No SMB enumeration results reported."]

    return {
        "summary": summary_lines,
        "findings": findings,
    }


def parse_smbclient(output: str) -> dict[str, Any]:
    """Extract SMB shares and comments from smbclient -L output."""
    summary_lines = []
    findings = []

    # Format:
    # 	Sharename       Type      Comment
    # 	---------       ----      -------
    # 	print$          Disk      Printer Drivers
    # 	IPC$            IPC       IPC Service
    share_matches = re.findall(
        r"^\s+([A-Za-z0-9_$-]+)\s+(Disk|IPC|Printer|Admin)\s*(.*)?$",
        output,
        re.MULTILINE,
    )

    if share_matches:
        summary_lines.append(f"Available SMB Shares ({len(share_matches)}):")
        for name, stype, comment in share_matches:
            c_str = f" - {comment.strip()}" if comment and comment.strip() else ""
            summary_lines.append(f"  • {name:<15} [{stype}]{c_str}")
            findings.append({"category": "smb_share", "finding": f"{name} ({stype}){c_str}"})
    else:
        # Check for workgroup or server info
        lines = [l.strip() for l in output.splitlines() if l.strip()]
        summary_lines = lines[:6] or ["No SMB shares returned or access denied."]

    return {
        "summary": summary_lines,
        "findings": findings,
    }


def parse_http_server(output: str) -> dict[str, Any]:
    """Parse local HTTP server spin-up output."""
    summary_lines = ["Local HTTP transfer server initialized."]
    lines = [l.strip() for l in output.splitlines() if l.strip()]
    if lines:
        summary_lines.extend(lines[:3])
    return {
        "summary": summary_lines,
        "findings": [],
    }


def parse_note_capture(output: str) -> dict[str, Any]:
    """Parse session note capture utility confirmation."""
    cleaned = output.strip()
    return {
        "summary": [f"Note recorded: {cleaned[:80]}{'...' if len(cleaned) > 80 else ''}"],
        "findings": [{"category": "session_note", "finding": cleaned[:120]}],
    }


def fallback_parser(output: str) -> dict[str, Any]:
    """Fallback parser for unregistered tools: returns first N lines + total line count."""
    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
    total = len(lines)
    if not lines:
        return {"summary": ["(Command completed with empty output)"], "findings": []}

    preview = lines[:8]
    summary = [f"Output preview ({min(8, total)} of {total} lines):"]
    for ln in preview:
        summary.append(f"  {ln}")
    if total > 8:
        summary.append(
            f"  ... [{total - 8} additional lines cached, press [f] or /f to view full output]"
        )
    return {"summary": summary, "findings": []}


# ==============================================================
# Step 2 parsers — vulnerability_assessment + post_engagement_review
# ==============================================================


def parse_sqlmap(output: str) -> dict[str, Any]:
    """Extract confirmed injection points, DB backend, and discovered databases from sqlmap output."""
    summary_lines: list[str] = []
    findings: list[dict[str, str]] = []

    # Injection confirmation: "Parameter: id (GET)"
    param_matches = re.findall(r"^\s*Parameter:\s*(.+)$", output, re.MULTILINE)
    type_matches = re.findall(r"^\s*Type:\s*(.+)$", output, re.MULTILINE)

    if param_matches:
        summary_lines.append(f"[!] Injection confirmed in {len(param_matches)} parameter(s):")
        for i, param in enumerate(param_matches):
            itype = type_matches[i].strip() if i < len(type_matches) else "unknown type"
            label = f"  * Parameter '{param.strip()}' -- {itype}"
            summary_lines.append(label)
            findings.append({"category": "sql_injection", "finding": f"{param.strip()} ({itype})"})
    else:
        summary_lines.append("No confirmed injection points detected.")

    # Backend DBMS: "back-end DBMS: MySQL >= 5.0"
    db_match = re.search(r"back-end DBMS:?\s*(.+)", output, re.IGNORECASE)
    if db_match:
        backend = db_match.group(1).strip()
        summary_lines.append(f"Backend DBMS: {backend}")
        findings.append({"category": "db_backend", "finding": backend})

    # Discovered databases listed as "[*] dbname"
    db_list = re.findall(r"^\[\*\]\s+(\w+)\s*$", output, re.MULTILINE)
    if db_list:
        summary_lines.append(f"Databases ({len(db_list)}): {', '.join(db_list[:6])}")
        for db in db_list:
            findings.append({"category": "db_name", "finding": db})

    if not summary_lines:
        lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
        summary_lines = lines[-6:] or ["sqlmap produced no parseable output."]

    return {"summary": summary_lines, "findings": findings}


def parse_hydra(output: str) -> dict[str, Any]:
    """Extract valid credential pairs found by hydra."""
    summary_lines: list[str] = []
    findings: list[dict[str, str]] = []

    # "[22][ssh] host: 10.10.10.5   login: admin   password: pass123"
    cred_matches = re.findall(
        r"^\[\d+\]\[([^\]]+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)",
        output,
        re.MULTILINE,
    )

    if cred_matches:
        summary_lines.append(f"[!] Valid credential(s) found ({len(cred_matches)}):")
        for service, host, login, password in cred_matches:
            line = f"  * [{service}] {host} -- {login}:{password}"
            summary_lines.append(line)
            findings.append({
                "category": "valid_credential",
                "finding": f"{service}://{host} {login}:{password}",
            })
    else:
        summary_lines.append("No valid credentials found.")

    total_match = re.search(r"(\d+) valid password(?:s)? found", output, re.IGNORECASE)
    if total_match and not cred_matches:
        summary_lines.append(f"Total passwords found: {total_match.group(1)}")

    return {"summary": summary_lines, "findings": findings}


def parse_metasploit(output: str) -> dict[str, Any]:
    """Extract Metasploit session openings, exploit successes, and module info."""
    summary_lines: list[str] = []
    findings: list[dict[str, str]] = []

    # "[*] Meterpreter session 1 opened (10.0.0.1:4444 -> 10.10.10.5:54321)"
    session_matches = re.findall(
        r"\[\*\]\s+((?:Meterpreter|Command shell|Session)\s+session\s+\d+\s+opened[^\r\n]*)",
        output,
        re.IGNORECASE,
    )
    if session_matches:
        summary_lines.append(f"[!] Session(s) opened ({len(session_matches)}):")
        for s in session_matches:
            summary_lines.append(f"  * {s.strip()}")
            findings.append({"category": "msf_session", "finding": s.strip()})

    # Notable [+] success lines
    vuln_matches = re.findall(r"^\[\+\]\s+([^\r\n]{10,120})", output, re.MULTILINE)
    if vuln_matches:
        summary_lines.append(f"Notable events ({len(vuln_matches)}):")
        for v in vuln_matches[:6]:
            summary_lines.append(f"  * {v.strip()}")
            findings.append({"category": "msf_result", "finding": v.strip()})

    if not summary_lines:
        lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
        summary_lines = lines[-8:] or ["Metasploit produced no parseable output."]

    return {"summary": summary_lines, "findings": findings}


def parse_linpeas(output: str) -> dict[str, Any]:
    """Extract privilege-escalation vectors flagged by linpeas."""
    summary_lines: list[str] = []
    findings: list[dict[str, str]] = []

    # Pattern tuples: (regex, category_label)
    patterns: list[tuple[str, str]] = [
        (r"(?:SUID|SGID)\s+(?:binary|file)[^\r\n]*",           "suid_sgid"),
        (r"(?:Cron|crontab)[^\r\n]{0,80}(?:root|CRON)[^\r\n]*", "cron_job"),
        (r"(?:Writable)[^\r\n]{0,60}(?:etc|passwd|shadow|cron)[^\r\n]*", "writable_sensitive"),
        (r"CVE-\d{4}-\d{4,7}[^\r\n]*",                         "kernel_cve"),
        (r"(?:sudo)[^\r\n]{0,60}(?:NOPASSWD|ALL)[^\r\n]*",     "sudo_nopasswd"),
        (r"(?:password|passwd|secret|token|key)[^\r\n]{0,60}\S+", "credential_leak"),
        (r"(?:PATH|LD_PRELOAD)[^\r\n]{0,60}(?:writable|write)[^\r\n]*", "env_hijack"),
        (r"NFS[^\r\n]{0,60}(?:no_root_squash|no_squash)[^\r\n]*", "nfs_no_squash"),
    ]

    seen: set[str] = set()
    for pattern, category in patterns:
        for m in re.findall(pattern, output, re.IGNORECASE)[:4]:
            m_clean = m.strip()[:120]
            if m_clean and m_clean not in seen:
                seen.add(m_clean)
                summary_lines.append(f"  [{category}] {m_clean}")
                findings.append({"category": category, "finding": m_clean})

    if summary_lines:
        summary_lines.insert(0, f"Privilege-escalation vectors ({len(findings)}):")
    else:
        headers = [
            ln.strip() for ln in output.splitlines()
            if re.search(r"===|\[!\]|Interesting", ln) and ln.strip()
        ]
        if headers:
            summary_lines.append("Linpeas completed -- notable section headers:")
            summary_lines.extend([f"  {h}" for h in headers[:6]])
        else:
            summary_lines.append(
                "Linpeas completed -- press /f to review full output for PE vectors."
            )

    return {"summary": summary_lines, "findings": findings}


def parse_pspy(output: str) -> dict[str, Any]:
    """Extract interesting process events captured by pspy."""
    summary_lines: list[str] = []
    findings: list[dict[str, str]] = []

    # pspy line: "2026/09/23 10:00:01 CMD: UID=0    PID=12345  | /bin/bash /opt/backup.sh"
    cmd_matches = re.findall(
        r"CMD:\s+UID=(\d+)\s+PID=\d+\s+\|\s+(.+)$",
        output,
        re.MULTILINE,
    )

    suspicious_re = re.compile(
        r"(?:/tmp/|/dev/shm/|cron|backup|\.sh|\.py|sudo|su\s|passwd|secret)",
        re.IGNORECASE,
    )

    interesting: list[tuple[str, str]] = []
    for uid, cmd in cmd_matches:
        if uid == "0" or suspicious_re.search(cmd):
            interesting.append((uid, cmd.strip()))

    if interesting:
        summary_lines.append(f"Interesting process events ({len(interesting)}):")
        seen_cmds: set[str] = set()
        for uid, cmd in interesting:
            key = cmd[:80]
            if key not in seen_cmds:
                seen_cmds.add(key)
                label = "root" if uid == "0" else f"uid={uid}"
                summary_lines.append(f"  * [{label}] {cmd[:100]}")
                findings.append({"category": "process_event", "finding": f"[uid={uid}] {cmd[:100]}"})
                if len(seen_cmds) >= 10:
                    break
    else:
        total = len(cmd_matches)
        summary_lines.append(
            f"pspy captured {total} process event(s). "
            "No obviously suspicious commands detected -- press /f to review all."
        )

    return {"summary": summary_lines, "findings": findings}


PARSER_REGISTRY: dict[str, Callable[[str], dict[str, Any]]] = {
    "parse_nmap": parse_nmap,
    "parse_whois": parse_whois,
    "parse_dig": parse_dig,
    "parse_gobuster": parse_gobuster,
    "parse_enum4linux": parse_enum4linux,
    "parse_smbclient": parse_smbclient,
    "parse_http_server": parse_http_server,
    "parse_note_capture": parse_note_capture,
    # Step 2 — vulnerability_assessment
    "parse_sqlmap": parse_sqlmap,
    "parse_hydra": parse_hydra,
    "parse_metasploit": parse_metasploit,
    # Step 2 — post_engagement_review
    "parse_linpeas": parse_linpeas,
    "parse_pspy": parse_pspy,
}


def get_parser(parser_name: str) -> Callable[[str], dict[str, Any]]:
    """Retrieve the designated deterministic parser function, or fallback if unregistered."""
    return PARSER_REGISTRY.get(parser_name, fallback_parser)
