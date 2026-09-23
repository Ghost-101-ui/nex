from __future__ import annotations

import unittest
from nex.summarizer import (
    parse_nmap,
    parse_whois,
    parse_dig,
    parse_gobuster,
    parse_enum4linux,
    parse_smbclient,
    fallback_parser,
    get_parser,
)


class TestSummarizerParsers(unittest.TestCase):
    def test_parse_nmap(self):
        sample_output = """
Starting Nmap 7.94 ( https://nmap.org ) at 2026-09-23 10:00 UTC
Nmap scan report for 10.10.10.5
Host is up (0.012s latency).
Not shown: 98 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
OS details: Linux 5.4 - 5.8
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
"""
        parsed = parse_nmap(sample_output)
        summary = "\n".join(parsed["summary"])
        self.assertIn("Host status: UP", summary)
        self.assertIn("22/tcp", summary)
        self.assertIn("OpenSSH 8.2p1", summary)
        self.assertIn("80/tcp", summary)
        self.assertIn("Apache httpd 2.4.41", summary)
        self.assertIn("Linux 5.4 - 5.8", summary)

        # Check findings
        findings = parsed["findings"]
        categories = [f["category"] for f in findings]
        self.assertIn("open_port", categories)
        self.assertIn("os_detection", categories)

    def test_parse_whois(self):
        sample_output = """
   Domain Name: LABTARGET.LOCAL
   Registry Domain ID: 123456_DOMAIN_COM-VRSN
   Registrar: Example Registrar, LLC
   Creation Date: 2020-01-15T12:00:00Z
   Registry Expiry Date: 2027-01-15T12:00:00Z
   Registrant Organization: CyberLab Training Corp
   Name Server: NS1.LABTARGET.LOCAL
   Name Server: NS2.LABTARGET.LOCAL
"""
        parsed = parse_whois(sample_output)
        summary = "\n".join(parsed["summary"])
        self.assertIn("Example Registrar, LLC", summary)
        self.assertIn("2020-01-15T12:00:00Z", summary)
        self.assertIn("CyberLab Training Corp", summary)
        self.assertIn("ns1.labtarget.local", summary)

    def test_parse_dig(self):
        sample_output = """
; <<>> DiG 9.18.1 <<>> ANY labtarget.local +noall +answer
;; global options: +cmd
labtarget.local.	300	IN	A	10.10.10.5
labtarget.local.	300	IN	MX	10 mail.labtarget.local.
"""
        parsed = parse_dig(sample_output)
        summary = "\n".join(parsed["summary"])
        self.assertIn("10.10.10.5", summary)
        self.assertIn("mail.labtarget.local", summary)

    def test_parse_gobuster(self):
        sample_output = """
===============================================================
Gobuster v3.5
===============================================================
[+] Url:                     http://10.10.10.5
===============================================================
/admin                (Status: 200) [Size: 1240]
/login                (Status: 301) [Size: 0] [--> /login/]
/images               (Status: 301) [Size: 0] [--> /images/]
"""
        parsed = parse_gobuster(sample_output)
        summary = "\n".join(parsed["summary"])
        self.assertIn("/admin", summary)
        self.assertIn("HTTP 200", summary)
        self.assertIn("/login", summary)
        self.assertIn("HTTP 301", summary)

    def test_parse_enum4linux(self):
        sample_output = """
 ==================================== 
|    Target Information on 10.10.10.5 |
 ==================================== 
Target ........... 10.10.10.5
Domain/Workgroup name: LABWORKGROUP
OS info: Linux (Samba 4.9.5-Debian)

[+] Users on 10.10.10.5:
user:[admin] rid:[0x3e8]
user:[student] rid:[0x3e9]

[+] Share Enumeration on 10.10.10.5:
//10.10.10.5/public Mapping: OK Listing: OK
//10.10.10.5/backups Mapping: DENIED Listing: DENIED
"""
        parsed = parse_enum4linux(sample_output)
        summary = "\n".join(parsed["summary"])
        self.assertIn("LABWORKGROUP", summary)
        self.assertIn("Linux (Samba 4.9.5-Debian)", summary)
        self.assertIn("admin", summary)
        self.assertIn("student", summary)
        self.assertIn("public", summary)

    def test_parse_smbclient(self):
        sample_output = """
	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	public          Disk      General Public Files
	IPC$            IPC       IPC Service (Samba 4.9.5)
"""
        parsed = parse_smbclient(sample_output)
        summary = "\n".join(parsed["summary"])
        self.assertIn("public", summary)
        self.assertIn("General Public Files", summary)
        self.assertIn("IPC$", summary)

    def test_fallback_parser(self):
        sample_output = "Line 1\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\nLine 7\nLine 8\nLine 9\nLine 10"
        parsed = fallback_parser(sample_output)
        summary = "\n".join(parsed["summary"])
        self.assertIn("Output preview (8 of 10 lines)", summary)
        self.assertIn("2 additional lines cached", summary)


if __name__ == "__main__":
    unittest.main()
