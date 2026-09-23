# CyberEDT NEX — Operator Prompt Playbook & Task Guide

A practical guide to natural language prompts, task goals, and command mappings across all 5 authorized training phases in **NEX**.

---

## Quick Navigation

- [How NEX Prompting Works](#how-nex-prompting-works)
- [Phase 1: Reconnaissance (`/p 1`)](#phase-1-reconnaissance-p-1)
- [Phase 2: Service Enumeration (`/p 2`)](#phase-2-service-enumeration-p-2)
- [Phase 3: Vulnerability Assessment (`/p 3`)](#phase-3-vulnerability-assessment-p-3)
- [Phase 4: Post-Engagement Review (`/p 4`)](#phase-4-post-engagement-review-p-4)
- [Phase 5: Utility (`/p 5`)](#phase-5-utility-p-5)
- [Power Tips & Workflow Strategies](#power-tips--workflow-strategies)

---

## How NEX Prompting Works

1. **Target Context**: Set your target once using `/target <ip>` (or `/t <ip>`). NEX automatically feeds this active target into every prompt, so you can simply type `"scan open ports"` without repeating the IP.
2. **Phase Boundary Enforcement**: NEX only allows tools assigned to your active phase (plus utilities). If you are in Phase 1 (Recon), NEX will not run SQLMap or LinPEAS until you switch to Phase 3 or 4.
3. **Approval Gates**:
   - `[AUTO]` tools run immediately and summarize output.
   - `[APPROVAL]` tools pause and display a safety confirmation (`[p]roceed` / `[s]top`).

---

## Phase 1: Reconnaissance (`/p 1`)

> **Objective**: Identify live hosts, open ports, protocol versions, registered domains, and DNS infrastructure without intrusive interaction.

### 1. `nmap` [Tier: AUTO]
*Network discovery & service fingerprinting.*

| Task / Goal | Example Prompts | Generated Command Preview |
|---|---|---|
| **Standard Top Ports Scan** | `Scan target 10.10.10.5` | `nmap -sV -sC --top-ports 100 10.10.10.5` |
| | `Check what services are running on the target` | |
| **All Ports Full Scan** | `Run a full port scan on all 65535 ports` | `nmap -p- 10.10.10.5` |
| | `Scan all ports with service detection` | `nmap -sV -p- 10.10.10.5` |
| **Fast Discovery** | `Do a quick ping scan to check if host is alive` | `nmap -sn 10.10.10.5` |
| | `Quick top 20 ports check` | `nmap --top-ports 20 10.10.10.5` |
| **Aggressive / Vuln Scan** | `Run default safe scripts against target` | `nmap -sC -sV 10.10.10.5` |
| | `Scan target using vuln script category` | `nmap --script vuln 10.10.10.5` |

---

### 2. `whois` [Tier: AUTO]
*Domain and IP registration lookup.*

| Task / Goal | Example Prompts | Generated Command Preview |
|---|---|---|
| **Domain Registration** | `Look up WHOIS information for megacorp.local` | `whois megacorp.local` |
| | `Who owns the domain target.lab?` | `whois target.lab` |
| **IP Range Owner** | `Find registration and registrar info for 10.10.10.5` | `whois 10.10.10.5` |

---

### 3. `dig` [Tier: AUTO]
*DNS name servers, mail exchangers, and zone records.*

| Task / Goal | Example Prompts | Generated Command Preview |
|---|---|---|
| **All DNS Records (ANY)** | `Query all DNS records for target.lab` | `dig ANY target.lab +noall +answer` |
| | `Run a DNS lookup on domain megacorp.local` | `dig ANY megacorp.local +noall +answer` |
| **Mail Exchangers (MX)** | `Find mail servers (MX records) for target.lab` | `dig MX target.lab +noall +answer` |
| **Name Servers (NS)** | `Find nameservers for target.lab` | `dig NS target.lab +noall +answer` |
| **IPv4 Address (A)** | `Resolve A record for dev.target.lab` | `dig A dev.target.lab +noall +answer` |

---

## Phase 2: Service Enumeration (`/p 2`)

> **Objective**: Brute-force web directories, enumerate SMB/Samba shares, and dump domain/local users.

### 1. `gobuster` [Tier: AUTO]
*Web directory and file brute-forcing.*

| Task / Goal | Example Prompts | Generated Command Preview |
|---|---|---|
| **Default Directory Scan** | `Find web directories on http://10.10.10.5` | `gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirb/common.txt -q` |
| | `Brute-force directories on the web server` | |
| **Custom Wordlist** | `Search directories on http://10.10.10.5:8080 with medium wordlist` | `gobuster dir -u http://10.10.10.5:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -q` |
| **File Extensions** | `Look for php and html files on http://10.10.10.5` | `gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirb/common.txt -x php,html -q` |

---

### 2. `enum4linux` [Tier: AUTO]
*Windows/Samba SMB user and share enumeration.*

| Task / Goal | Example Prompts | Generated Command Preview |
|---|---|---|
| **Users & Shares** | `Enumerate SMB users and shares on 10.10.10.5` | `enum4linux -U -S 10.10.10.5` |
| | `Check Windows users and shares on target` | |
| **Full / Comprehensive** | `Run complete enum4linux scan on 10.10.10.5` | `enum4linux -a 10.10.10.5` |
| **Password Policy** | `Check password policy and domain info on target` | `enum4linux -P 10.10.10.5` |

---

### 3. `smbclient` [Tier: AUTO]
*Anonymous and authenticated SMB share listing.*

| Task / Goal | Example Prompts | Generated Command Preview |
|---|---|---|
| **Null Session Share List** | `List SMB shares on 10.10.10.5 anonymously` | `smbclient -L 10.10.10.5 -N` |
| | `Check if anonymous SMB login is allowed` | |
| **Check Shared Folders** | `Connect to smb on target and display shares` | `smbclient -L 10.10.10.5 -N` |

---

## Phase 3: Vulnerability Assessment (`/p 3`)

> **Objective**: Active probing, credential testing, and exploitation framework execution.  
> ⚠️ **Note**: Every tool in this phase requires operator approval confirmation (`[p]roceed` / `[s]top`).

### 1. `sqlmap` [Tier: APPROVAL]
*Automated SQL injection testing and database enumeration.*

| Task / Goal | Example Prompts | Generated Command Preview |
|---|---|---|
| **Test Parameter for SQLi** | `Test http://10.10.10.5/item.php?id=1 for SQL injection` | `sqlmap -u http://10.10.10.5/item.php?id=1 --batch --output-dir .nex/sqlmap` |
| | `Run sqlmap on target URL login endpoint` | |
| **Enumerate Databases** | `Extract databases from http://10.10.10.5/vuln.php?id=2` | `sqlmap -u http://10.10.10.5/vuln.php?id=2 --batch --output-dir .nex/sqlmap --dbs` |
| **Dump Database Tables** | `Dump tables from database on http://10.10.10.5/page?cat=1` | `sqlmap -u http://10.10.10.5/page?cat=1 --batch --output-dir .nex/sqlmap --tables` |

---

### 2. `hydra` [Tier: APPROVAL]
*Network login credential validation against services.*

| Task / Goal | Example Prompts | Generated Command Preview |
|---|---|---|
| **SSH Credential Test** | `Test SSH passwords on 10.10.10.5 with users.txt and passwords.txt` | `hydra -L users.txt -P passwords.txt 10.10.10.5 ssh` |
| | `Brute force SSH on target with wordlist rockyou.txt and admin user` | `hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.5 ssh` |
| **FTP Credential Test** | `Test FTP login on 10.10.10.5 using userlist.txt and pass.txt` | `hydra -L userlist.txt -P pass.txt 10.10.10.5 ftp` |
| **Web Form Auth** | `Test HTTP POST login on 10.10.10.5 with credentials lists` | `hydra -L users.txt -P passes.txt 10.10.10.5 http-post-form` |

---

### 3. `metasploit` [Tier: APPROVAL]
*Execution of verified exploit scripts and automation resources.*

| Task / Goal | Example Prompts | Generated Command Preview |
|---|---|---|
| **Execute Resource Script** | `Run metasploit resource script exploit.rc` | `msfconsole -q -r exploit.rc` |
| | `Execute msfconsole script ./scripts/handler.rc` | `msfconsole -q -r ./scripts/handler.rc` |

---

## Phase 4: Post-Engagement Review (`/p 4`)

> **Objective**: Internal privilege-escalation vectors, cron jobs, background processes, and sensitive file misconfigurations.  
> ⚠️ **Note**: Requires operator approval confirmation (`[p]roceed` / `[s]top`).

### 1. `linpeas` [Tier: APPROVAL]
*Linux privilege escalation checklist script.*

| Task / Goal | Example Prompts | Generated Command Preview |
|---|---|---|
| **Full Local Escalation Audit** | `Run linpeas privilege escalation check using /tmp/linpeas.sh` | `bash /tmp/linpeas.sh -a` |
| | `Audit target Linux system for privilege escalation vectors` | `bash ./linpeas.sh -a` |
| **Custom Script Path** | `Run linpeas script located at /opt/linpeas.sh` | `bash /opt/linpeas.sh -a` |

---

### 2. `pspy` [Tier: APPROVAL]
*Snoop running processes and cron jobs without root privileges.*

| Task / Goal | Example Prompts | Generated Command Preview |
|---|---|---|
| **Monitor Process Activity** | `Monitor background processes with /tmp/pspy64` | `/tmp/pspy64 -pf -i 100` |
| | `Watch running cron jobs and new processes with pspy` | `/tmp/pspy64 -pf -i 100` |
| **Slower Polling (Less CPU)** | `Run /tmp/pspy64 with 500ms interval` | `/tmp/pspy64 -pf -i 500` |

---

## Phase 5: Utility (`/p 5` or anytime)

> **Objective**: Local staging HTTP servers and session flag/evidence capture.  
> *Note: Utility tools are accessible from any phase.*

### 1. `http_server` [Tier: AUTO]
*Host local files for transfer to target machines.*

| Task / Goal | Example Prompts | Generated Command Preview |
|---|---|---|
| **Default Port 8000 Server** | `Start a local HTTP server to transfer files` | `python3 -m http.server 8000 --directory .` |
| | `Host current directory on web server` | |
| **Custom Port / Folder** | `Start HTTP server on port 9090 in /opt/payloads` | `python3 -m http.server 9090 --directory /opt/payloads` |
| | `Serve /tmp folder on port 80` | `python3 -m http.server 80 --directory /tmp` |

---

### 2. `note_capture` [Tier: AUTO]
*Record flags, credentials, or findings permanently in SQLite memory.*

| Task / Goal | Example Prompts | Effect |
|---|---|---|
| **Capture CTF Flag** | `Save note flag: THM{d4t4b4s3_pwn3d_2026}` | Saves to `session.db` |
| | `Record flag flag{12345_root_access}` | Shows in `/findings` |
| **Save Credential Finding** | `Note finding: admin / Password123 discovered on SSH` | Adds to session findings |
| **General Documentation** | `Save note: port 8080 hosts Apache Tomcat 9.0` | Accessible via `/findings` |

---

## Power Tips & Workflow Strategies

### 1. The 30-Second CTF Workflow
```text
[Step 1]  /t 10.10.10.5                               ← Set target
[Step 2]  /p 1                                        ← Recon phase
          Scan target for open ports
[Step 3]  /f                                          ← Expand nmap output
[Step 4]  /p 2                                        ← Service Enum phase
          Find directories on http://10.10.10.5
[Step 5]  /p 3                                        ← Vulnerability phase
          Test http://10.10.10.5/login?id=1 with sqlmap
          [Press 'p' to approve execution]
[Step 6]  Save note flag: CTF{s3cur1ty_succ3ss}      ← Save flag
[Step 7]  /findings                                   ← Review all findings
```

### 2. Dealing with Declined Tools
If you decline an approval prompt by pressing `s` (stop), you can ask NEX for an alternative:
```text
"The previous tool was stopped. What other tool in this phase can I use?"
```
NEX will inspect session memory, note that you declined the previous tool, and propose an alternative tool from the catalog.

### 3. Reviewing Full Raw Output
Summaries highlight ports, findings, and status. To inspect every raw line returned by the tool:
```text
/f
```
To review all previous runs and exit codes:
```text
/history
```
