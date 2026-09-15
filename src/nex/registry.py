from __future__ import annotations

from .models import Phase, Risk, Tool

# Commands are constructed only from enums and validated values in executor.py.
TOOLS: dict[str, Tool] = {
    "nmap_scan": Tool("nmap_scan", Phase.RECON, Risk.SAFE, "nmap", ("target", "scan_type"), ("ports",)),
    "whatweb_scan": Tool("whatweb_scan", Phase.RECON, Risk.SAFE, "whatweb", ("target",)),
    "dns_enum": Tool("dns_enum", Phase.RECON, Risk.SAFE, "dnsrecon", ("domain", "mode")),
    "nikto_scan": Tool("nikto_scan", Phase.RECON, Risk.SAFE, "nikto", ("target",)),
    "gobuster_dir": Tool("gobuster_dir", Phase.ENUMERATION, Risk.SAFE, "gobuster", ("target", "wordlist")),
    "smb_enum": Tool("smb_enum", Phase.ENUMERATION, Risk.SAFE, "nmap", ("target",)),
    "ftp_anon_check": Tool("ftp_anon_check", Phase.ENUMERATION, Risk.SAFE, "nmap", ("target",)),
    "service_probe": Tool("service_probe", Phase.ENUMERATION, Risk.SAFE, "nmap", ("target", "port")),
    "searchsploit_query": Tool("searchsploit_query", Phase.EXPLOITATION, Risk.SAFE, "searchsploit", ("service_name",), ("version",)),
}

CONFIRM_ONLY = {
    "sqlmap_test", "hydra_bruteforce", "metasploit_run", "linpeas_run",
}
