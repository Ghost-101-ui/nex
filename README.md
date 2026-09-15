# CyberEDT NEX

NEX is a local, offline-friendly controller for **authorized CTF and lab** work on Kali. Models may propose a registered tool call, but the controller—not the model—validates arguments, target scope, phase rules, and confirmation requirements before execution.

## Current v0.4

- `nex init` is idempotent and automatically trusts RFC1918 lab ranges plus any detected Linux tunnel subnet (`tun*`, `wg*`, `tap*`, `ppp*`).
- Bare `nex` opens a small arrow-key menu; manual menu/flag use makes no model call.
- `nex run` accepts normal flags, e.g. `--target` and `--quick`; JSON remains an advanced escape hatch.
- `nex quick TARGET` runs the SAFE starter chain and records a session log.
- `nex report` writes a Markdown report from the session log, including possible flag matches.
- `nex run note_capture --content "..."` records CTF notes; raw outputs are stored under `.nex/raw/` for later session-only inspection.
- `nex objective`, `nex findings`, `nex artifacts`, `nex raw <action>`, and `nex resume` make sessions inspectable after a terminal restart.
- Public scope additions require one explicit acknowledgement: `nex init TARGET --authorized`.
- High-impact actions and the Ollama autonomous loop are intentionally not included in this first executable slice.

This is not a scanner for systems you do not own or lack written authorization to test.

## Kali install (development)

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
nex init
nex status
nex run nmap_scan --target 10.10.10.5 --quick
# Or, for a newly assigned authorized CTF target:
nex quick 10.10.10.5
```

For an authorized public target that is not detected from your VPN, acknowledge it as a scope explicitly:

```bash
nex init TARGET --i-own-this --authorized
```

Use `nex help` (or `nex --help`) for command help, `nex config show` to inspect scope, and `nex report` after a session.

## Architecture boundary

The planned Ollama layer is an untrusted proposer. It can emit `{"tool": ..., "args": ...}`, but must route through `Gate.authorize()`; it does not get a shell, command strings, or a way to override policy.

# CyberEDT NEX Guide

NEX is a local, deterministic command controller for **authorized CTFs and security labs** on Kali Linux. It wraps a fixed registry of tools, validates targets against scope, stores session evidence, and does not provide arbitrary shell execution.

> Only run NEX against systems you own or are explicitly authorized to test.

## What works without AI

All current scanning, menu, quick-chain, reporting, and evidence features work without a model or Ollama. These commands never invoke a model:

```bash
nex
nex run ...
nex quick ...
nex report
```

Ollama and Qwen are optional today. They are installed for the planned autonomous reasoning mode, which is not implemented yet.

## Install on Kali

```bash
git clone https://github.com/Ghost-101-ui/nex.git
cd nex
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

To update an existing copy:

```bash
cd ~/nex
git pull
source .venv/bin/activate
pip install -e .
```

## First-time setup

```bash
nex init
```

`nex init` is safe to run repeatedly. It preserves existing scope and refreshes automatic scope detection.

It does the following:

- Adds RFC1918 private ranges: `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`.
- Detects active Linux tunnel interfaces named `tun*`, `tap*`, `wg*`, or `ppp*`, then adds their IPv4 subnet.
- Checks whether Ollama is installed.
- Checks whether `qwen3:0.6b` is already available.
- In an interactive terminal, offers to run `ollama pull qwen3:0.6b` if the model is missing.

Configuration is stored locally in `nex.config.json`. This file is intentionally ignored by Git.

## Scope and authorization

Private networks and detected CTF VPN subnets are available automatically. A public IP address or domain needs stronger confirmation.

For an authorized public target, run:

```bash
nex init <target> --i-own-this --authorized
```

NEX then asks you to retype the exact target. This prevents a menu click or a simple `y` response from authorizing an arbitrary public system.

Review current scope:

```bash
nex config show
```

To add a scope after initialization, use the same flags for a public target:

```bash
nex config add-scope <target> --i-own-this --authorized
```

## Main commands

| Command | Purpose |
|---|---|
| `nex` | Open the arrow-key interactive menu. |
| `nex init [target]` | Refresh setup, private/VPN scope, and optional model checks. |
| `nex status` | Human-readable runtime, scope, phase, and session dashboard. |
| `nex status --json` | Machine-readable status. |
| `nex tools` | List registered wrappers and their phases. |
| `nex quick <target>` | Run the SAFE starter recon chain. |
| `nex run <tool> ...` | Run a registered tool using normal flags. |
| `nex objective "text"` | Set the purpose of the current session. |
| `nex findings` | Show recorded structured findings. |
| `nex artifacts` | List captured raw output files by action number. |
| `nex raw <number>` | Print raw output for an earlier action. |
| `nex resume` | Show persisted session status after reopening a terminal. |
| `nex report` | Generate `nex-report.md`. |
| `nex help` / `nex --help` | Show command help. |

## Normal scan commands

The normal workflow uses flags, not hand-written JSON.

```bash
# Nmap service scan against an allowed lab target
nex run nmap_scan --target 10.10.10.5 --quick

# Full TCP scan
nex run nmap_scan --target 10.10.10.5 --full

# UDP top-port scan
nex run nmap_scan --target 10.10.10.5 --udp

# Limit Nmap to specific ports
nex run nmap_scan --target 10.10.10.5 --quick --ports 22,80,443

# Web fingerprinting
nex run whatweb_scan --target 10.10.10.5

# Web server check
nex run nikto_scan --target 10.10.10.5

# Directory enumeration
nex run gobuster_dir --target 10.10.10.5 --wordlist medium

# DNS enumeration
nex run dns_enum --domain lab.example --mode subdomains
nex run dns_enum --domain lab.example --mode records

# Probe a single service
nex run service_probe --target 10.10.10.5 --port 80

# SMB and FTP discovery
nex run smb_enum --target 10.10.10.5
nex run ftp_anon_check --target 10.10.10.5

# Search the local Exploit-DB copy; this does not target a host
nex run searchsploit_query --service-name openssh --version 8.2
```

`--args '{...}'` remains available for scripts and advanced use, but is not needed for the documented workflow.

## Registered SAFE wrappers

| Phase | Wrapper | Underlying tool / behavior |
|---|---|---|
| Recon | `nmap_scan` | Nmap quick, full, or UDP scanning. |
| Recon | `whatweb_scan` | WhatWeb technology fingerprinting. |
| Recon | `dns_enum` | DNSRecon subdomain or record discovery. |
| Recon | `nikto_scan` | Nikto web-server checks. |
| Enumeration | `gobuster_dir` | Gobuster directory enumeration with Kali wordlists. |
| Enumeration | `smb_enum` | Nmap SMB discovery and share-enumeration scripts. |
| Enumeration | `ftp_anon_check` | Nmap FTP anonymous-access script. |
| Enumeration | `service_probe` | Nmap service/version probe for one port. |
| Exploitation research | `searchsploit_query` | Local Exploit-DB search only. |
| Utility | `note_capture` | Save a note in session memory. |
| Utility | `report_status` | Display the stored session object. |
| Utility | `file_search` | Search NEX-captured raw artifacts only. |
| Utility | `read_file` | Read a NEX-captured raw artifact only. |
| Utility | `flag_grep` | Look for CTF-style flags in one NEX artifact. |

NEX checks that a target is in scope before it runs a target-facing wrapper. It also validates normal enum values such as scan type, wordlist size, DNS mode, and port range.

## Quick workflow

For an allowed target:

```bash
nex objective "Initial authorized lab enumeration"
nex quick 10.10.10.5
nex findings
nex report
```

`nex quick` currently runs this SAFE chain:

1. Nmap quick scan
2. Nmap full TCP scan
3. WhatWeb
4. Gobuster with the small wordlist

It does not run any confirmation-tier action.

## Session memory and evidence

After every NEX action, the session records the action, arguments, phase, exit code, deterministic summary, possible flag matches, and raw output.

Local files created during use:

| File or folder | Purpose |
|---|---|
| `nex.config.json` | Local scope, phase, timeouts, and model settings. |
| `nex.session.json` | Objective, actions, findings, notes, flags, and last target. |
| `.nex/raw/` | Raw output captured from each action. |
| `nex-report.md` | Generated Markdown session report. |

These local runtime files are ignored by Git.

Examples:

```bash
nex run note_capture --content "HTTP on port 80 redirects to /login"
nex artifacts
nex raw 1
nex report
```

The evidence utilities only read files under `.nex/raw/`; they cannot read arbitrary filesystem paths.

## Models and Ollama

Manual usage does not need Ollama.

To install Ollama manually on Kali when you want local-model support:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Then use setup:

```bash
nex init
```

If you accept the prompt, NEX runs:

```bash
ollama pull qwen3:0.6b
```

For the optional tool-calling model check:

```bash
nex init --dual
```

If accepted, it pulls:

```bash
ollama pull hf.co/tinybiggames/functiongemma-270m-it-q8_0:Q8_0
```

Models are cached by Ollama, usually below `~/.ollama/models`, and can be used offline after they are pulled. At the current release, NEX does **not** yet invoke either model at runtime; autonomous reasoning and dual-model dispatch are future features.

## Phase behavior

NEX records phase history in `nex.config.json`.

- Recon is the initial phase.
- A successful recon action unlocks enumeration.
- Two successful enumeration actions unlock exploitation research.
- Earlier-phase actions remain available after a transition.

The currently available exploitation-phase action is `searchsploit_query`, which searches the local Exploit-DB database and does not interact with a target.

## Troubleshooting

### `NEX blocked: Target ... is outside the configured authorized lab scope`

Use `nex config show`. Connect the intended CTF VPN and rerun `nex init`, or—only when authorized—use the deliberate public-scope command:

```bash
nex init <target> --i-own-this --authorized
```

### `Required executable not found`

NEX does not bundle Kali tools. Install the missing tool with Kali's package manager, then rerun the command. For example:

```bash
sudo apt update
sudo apt install nmap whatweb gobuster nikto dnsrecon exploitdb
```

### Interactive menu says `questionary` is missing

Reinstall project dependencies in the active virtual environment:

```bash
source .venv/bin/activate
pip install -e .
```

### Qwen says `NOT INSTALLED`

This does not prevent scanning. When online, run `nex init` and accept the pull prompt, or use:

```bash
ollama pull qwen3:0.6b
```

## Current boundaries and roadmap

NEX v0.4 has deterministic SAFE wrappers, scope authorization, phase history, persistent session evidence, reporting, and an interactive menu.

Not implemented yet:

- Autonomous Qwen reasoning loop
- Runtime dual-model dispatch
- Offline model bundle extraction
- Confirmation-tier action controller and its reserved tool integrations
- Multi-target queue and external tool packs

This separation is intentional: manual scan and reporting workflows remain fast, inspectable, and usable without models.
