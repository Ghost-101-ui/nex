"""
Tests for the Step 2 deterministic summarizer parsers.

Covered parsers:
  - parse_sqlmap   (vulnerability_assessment)
  - parse_hydra    (vulnerability_assessment)
  - parse_metasploit (vulnerability_assessment)
  - parse_linpeas  (post_engagement_review)
  - parse_pspy     (post_engagement_review)
"""

import unittest
from nex.summarizer import (
    parse_sqlmap,
    parse_hydra,
    parse_metasploit,
    parse_linpeas,
    parse_pspy,
)


# ---------------------------------------------------------------------------
# parse_sqlmap
# ---------------------------------------------------------------------------
SQLMAP_CONFIRMED = """\
[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] GET parameter 'id' appears to be 'Boolean-based blind' injectable

Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1709=1709

back-end DBMS: MySQL >= 5.0

available databases [3]:
[*] information_schema
[*] security
[*] testdb
"""

SQLMAP_CLEAN = """\
[INFO] testing connection to the target URL
[INFO] heuristic (basic) test shows that GET parameter 'q' might not be injectable
[WARNING] GET parameter 'q' does not seem to be injectable
"""


class TestParseSqlmap(unittest.TestCase):

    def test_confirmed_injection_extracts_parameter_and_type(self):
        result = parse_sqlmap(SQLMAP_CONFIRMED)
        joined = "\n".join(result["summary"])
        self.assertIn("Injection confirmed", joined)
        self.assertIn("id", joined)
        self.assertIn("boolean-based blind", joined)

    def test_confirmed_injection_records_finding(self):
        result = parse_sqlmap(SQLMAP_CONFIRMED)
        categories = [f["category"] for f in result["findings"]]
        self.assertIn("sql_injection", categories)

    def test_backend_dbms_extracted(self):
        result = parse_sqlmap(SQLMAP_CONFIRMED)
        joined = "\n".join(result["summary"])
        self.assertIn("MySQL", joined)
        self.assertTrue(any(f["category"] == "db_backend" for f in result["findings"]))

    def test_discovered_databases_extracted(self):
        result = parse_sqlmap(SQLMAP_CONFIRMED)
        db_findings = [f for f in result["findings"] if f["category"] == "db_name"]
        # Expect information_schema, security, testdb
        db_names = {f["finding"] for f in db_findings}
        self.assertGreaterEqual(len(db_names), 2)

    def test_no_injection_reports_clean(self):
        result = parse_sqlmap(SQLMAP_CLEAN)
        joined = "\n".join(result["summary"])
        self.assertIn("No confirmed injection", joined)
        self.assertEqual(result["findings"], [])


# ---------------------------------------------------------------------------
# parse_hydra
# ---------------------------------------------------------------------------
HYDRA_SUCCESS = """\
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak
[DATA] max 16 tasks per 1 server, overall 16 tasks, 18 login tries

[22][ssh] host: 10.10.10.5   login: admin   password: password123
[22][ssh] host: 10.10.10.5   login: root    password: toor

1 valid password found.
"""

HYDRA_FAIL = """\
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak
[DATA] attack finished, 0 valid passwords found.
"""


class TestParseHydra(unittest.TestCase):

    def test_valid_creds_found(self):
        result = parse_hydra(HYDRA_SUCCESS)
        joined = "\n".join(result["summary"])
        self.assertIn("Valid credential", joined)
        self.assertIn("admin:password123", joined)
        self.assertIn("root:toor", joined)

    def test_findings_populated(self):
        result = parse_hydra(HYDRA_SUCCESS)
        categories = [f["category"] for f in result["findings"]]
        self.assertIn("valid_credential", categories)
        self.assertEqual(len(result["findings"]), 2)

    def test_no_creds_reports_clean(self):
        result = parse_hydra(HYDRA_FAIL)
        joined = "\n".join(result["summary"])
        self.assertIn("No valid credentials", joined)
        self.assertEqual(result["findings"], [])


# ---------------------------------------------------------------------------
# parse_metasploit
# ---------------------------------------------------------------------------
MSF_SUCCESS = """\
[*] Started reverse TCP handler on 10.0.0.1:4444
[*] 10.10.10.5:445 - Attempting to trigger the vulnerability...
[+] 10.10.10.5:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.5:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-= Win! -=-=-=-=-=-=
[*] Meterpreter session 1 opened (10.0.0.1:4444 -> 10.10.10.5:49876) at 2026-09-23 10:00:01
"""

MSF_FAIL = """\
[*] Started reverse TCP handler on 10.0.0.1:4444
[-] 10.10.10.5:445 - Exploit completed, but no session was created.
"""


class TestParseMetasploit(unittest.TestCase):

    def test_session_opened_detected(self):
        result = parse_metasploit(MSF_SUCCESS)
        joined = "\n".join(result["summary"])
        self.assertIn("Session", joined)
        self.assertIn("opened", joined)

    def test_session_finding_recorded(self):
        result = parse_metasploit(MSF_SUCCESS)
        categories = [f["category"] for f in result["findings"]]
        self.assertIn("msf_session", categories)

    def test_plus_lines_captured(self):
        result = parse_metasploit(MSF_SUCCESS)
        # [+] lines should appear in findings as msf_result
        plus_findings = [f for f in result["findings"] if f["category"] == "msf_result"]
        self.assertGreater(len(plus_findings), 0)

    def test_no_session_falls_back_to_output(self):
        result = parse_metasploit(MSF_FAIL)
        # No session findings; summary should not be empty
        self.assertTrue(len(result["summary"]) > 0)
        self.assertEqual([f for f in result["findings"] if f["category"] == "msf_session"], [])


# ---------------------------------------------------------------------------
# parse_linpeas
# ---------------------------------------------------------------------------
LINPEAS_OUTPUT = """\
====( Interesting Files )====
SUID binary found: /usr/bin/passwd
SGID file: /usr/bin/wall
Cron job running as root: /etc/cron.d/backup -> /bin/bash /opt/backup.sh
Writable file /etc/passwd (world-writable)
sudo -l output: (root) NOPASSWD: ALL
CVE-2021-4034 potentially applicable (pkexec local privilege escalation)
"""

LINPEAS_EMPTY = """\
====( Nothing interesting found )====
System appears hardened. No obvious PE vectors found.
"""


class TestParseLinpeas(unittest.TestCase):

    def test_suid_detected(self):
        result = parse_linpeas(LINPEAS_OUTPUT)
        categories = [f["category"] for f in result["findings"]]
        self.assertIn("suid_sgid", categories)

    def test_cron_detected(self):
        result = parse_linpeas(LINPEAS_OUTPUT)
        categories = [f["category"] for f in result["findings"]]
        self.assertIn("cron_job", categories)

    def test_sudo_nopasswd_detected(self):
        result = parse_linpeas(LINPEAS_OUTPUT)
        categories = [f["category"] for f in result["findings"]]
        self.assertIn("sudo_nopasswd", categories)

    def test_cve_detected(self):
        result = parse_linpeas(LINPEAS_OUTPUT)
        categories = [f["category"] for f in result["findings"]]
        self.assertIn("kernel_cve", categories)

    def test_header_line_present(self):
        result = parse_linpeas(LINPEAS_OUTPUT)
        self.assertTrue(result["summary"][0].startswith("Privilege-escalation vectors"))

    def test_empty_output_graceful(self):
        result = parse_linpeas(LINPEAS_EMPTY)
        # Should not raise; summary should contain a usable message
        joined = "\n".join(result["summary"])
        self.assertTrue(len(joined) > 0)


# ---------------------------------------------------------------------------
# parse_pspy
# ---------------------------------------------------------------------------
PSPY_OUTPUT = """\
2026/09/23 10:00:01 CMD: UID=0    PID=1234   | /bin/bash /opt/backup.sh
2026/09/23 10:00:05 CMD: UID=1000 PID=1235   | /bin/sleep 1
2026/09/23 10:01:00 CMD: UID=0    PID=1240   | /usr/bin/python3 /tmp/evil.py
2026/09/23 10:01:01 CMD: UID=1000 PID=1241   | /usr/bin/crontab -l
"""

PSPY_BORING = """\
2026/09/23 10:00:01 CMD: UID=1000 PID=999    | /usr/lib/systemd/systemd --user
2026/09/23 10:00:02 CMD: UID=1000 PID=1000   | /bin/bash
"""


class TestParsePspy(unittest.TestCase):

    def test_root_commands_flagged(self):
        result = parse_pspy(PSPY_OUTPUT)
        joined = "\n".join(result["summary"])
        self.assertIn("[root]", joined)

    def test_suspicious_path_tmp_flagged(self):
        result = parse_pspy(PSPY_OUTPUT)
        joined = "\n".join(result["summary"])
        self.assertIn("/tmp/evil.py", joined)

    def test_findings_recorded(self):
        result = parse_pspy(PSPY_OUTPUT)
        categories = [f["category"] for f in result["findings"]]
        self.assertIn("process_event", categories)

    def test_boring_output_reports_count(self):
        result = parse_pspy(PSPY_BORING)
        joined = "\n".join(result["summary"])
        self.assertIn("captured", joined)
        self.assertEqual(result["findings"], [])

    def test_deduplication(self):
        # Repeat same root command many times — should only appear once
        repeated = "\n".join(
            f"2026/09/23 10:0{i}:00 CMD: UID=0    PID={1000+i}   | /bin/bash /opt/backup.sh"
            for i in range(15)
        )
        result = parse_pspy(repeated)
        count = sum(1 for ln in result["summary"] if "/opt/backup.sh" in ln)
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
