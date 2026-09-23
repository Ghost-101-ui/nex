# CyberEDT NEX

**Navigate / Execute / eXplore** — a portable, offline AI assistant for
authorized cybersecurity training environments (CTF competitions, personal lab
VMs, or written-permission engagements).

> **Authorized use only.**  NEX is designed exclusively for systems you own or
> have explicit written permission to test — competition infrastructure, personal
> lab VMs, or professional engagements.  Never point it at infrastructure you do
> not control.

---

## What NEX does

NEX converts natural-language requests into validated, human-approved,
**logged** invocations of standard Kali Linux security utilities.  It is a
workflow orchestration layer, not a new attack tool.

Key properties:

| Property | Detail |
|---|---|
| **Fully offline** | No cloud calls in the core loop; local GGUF models only |
| **Deterministic gate** | The model never executes anything; every call passes through the Python Controller |
| **Human-in-the-loop** | `APPROVAL`-tier tools always block for `[p]roceed / [s]top` before running |
| **Persistent memory** | SQLite session DB survives reboots on a Live USB persistence partition |
| **Phase-aware** | Planner only sees tools for the active CTF phase — enumeration tools are hidden during recon |

---

## Architecture

```
User NL input
      │
      ▼
┌──────────────┐   phase-filtered tool schema
│   Planner    │──────────────────────────────► catalog.yaml
│ (Qwen3 0.6B) │
│  [+ Gemma    │  {tool, args, phase, reasoning}
│  in --dual]  │
└──────────────┘
      │
      ▼
┌──────────────────────────────────────────────────┐
│          Controller / Gate  (pure Python)         │
│  1. Validate tool in catalog                     │
│  2. Check phase matches current phase            │
│  3. Check all required args present              │
│  4. Check target in authorized scope             │
│  5a. AUTO  → execute immediately                 │
│  5b. APPROVAL → print command, block for [p/s]   │
│       stop → log to memory, return to Planner    │
│       proceed → run with timeout, stream output  │
└──────────────────────────────────────────────────┘
      │
      ▼
┌──────────────┐
│  Summarizer  │  deterministic per-tool parser → short findings summary
│   (LENS)     │  /f to expand to full raw output
└──────────────┘
      │
      ▼
┌──────────────┐
│Session Memory│  SQLite: phase, scope, history, findings, notes
│  (SQLite)    │  Planner reads last N turns + all findings for context
└──────────────┘
```

### Dual-model mode (`--dual`)

| Role | Model | GGUF path |
|---|---|---|
| Reasoner (default + dual) | Qwen3 0.6B | `models/qwen3-0.6b-instruct.Q4_K_M.gguf` |
| Tool-call generator (dual only) | FunctionGemma 270M | `models/functiongemma-270m-it.Q8_0.gguf` |

In **single mode** (default) Qwen3 handles both reasoning and structured JSON
output.  In **dual mode** Qwen3 reasons and FunctionGemma emits the tool-call
JSON — useful when you want a faster, specialized emitter.

If no GGUF weights are present, NEX falls back to a deterministic heuristic
backend that still produces valid tool calls — so the system works immediately
even before downloading models.

---

## Install (Kali Linux — Live + Persistence)

### Catalog — all tools (v1.0.0)

| Tool | Phase | Tier | Purpose |
|---|---|---|---|
| nmap | reconnaissance | AUTO | Port + service version scanning |
| whois | reconnaissance | AUTO | Domain / IP registration lookup |
| dig | reconnaissance | AUTO | DNS record enumeration |
| gobuster | service_enumeration | AUTO | Web directory brute-force |
| enum4linux | service_enumeration | AUTO | SMB/NFS/LDAP enumeration |
| smbclient | service_enumeration | AUTO | SMB share listing |
| sqlmap | vulnerability_assessment | **APPROVAL** | SQL-injection detection and exploitation |
| hydra | vulnerability_assessment | **APPROVAL** | Network credential-policy testing |
| metasploit | vulnerability_assessment | **APPROVAL** | Exploitation framework (resource scripts) |
| linpeas | post_engagement_review | **APPROVAL** | Linux privilege-escalation checklist |
| pspy | post_engagement_review | **APPROVAL** | Unprivileged process spy |
| http_server | utility | AUTO | Local file-transfer HTTP server |
| note_capture | utility | AUTO | Store flags/notes in session memory |

### Quick install

```bash
git clone https://github.com/Ghost-101-ui/nex.git
cd nex
bash install.sh
```

`install.sh` will:
1. Verify Python 3.10+
2. Create `.venv/` and install the `nex` package (PyYAML dependency)
3. Report whether GGUF model weights are present in `models/`
4. Install a `nex` launcher to `/usr/local/bin` (or `~/.local/bin`)

### Manual install (development)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .           # installs nex entrypoint + pyyaml
# optionally add LLM inference:
pip install llama-cpp-python
```

### GGUF model weights (offline)

Place pre-downloaded weights in the `models/` directory:

```
models/
  qwen3-0.6b-instruct.Q4_K_M.gguf   ← default single-mode model
  functiongemma-270m-it.Q8_0.gguf   ← optional dual-mode tool caller
```

When offline, download from HuggingFace on a machine with internet access and
transfer via USB.  NEX operates without models — the heuristic fallback
handles all standard use-cases.

---

## First-run walkthrough

```bash
# Start the interactive REPL
nex

# Inside the REPL:
[NEX | reconnaissance]> I need to discover what ports are open on 10.10.10.5

→ Proposed Tool Call: nmap [AUTO]
  Command:   nmap -sV -sC --top-ports 100 10.10.10.5
  Reasoning: Scanning target 10.10.10.5 for open ports and service versions.

[✓] Executed successfully in 4.2s (exit 0)
Summary:
  Host status: UP (0.021s latency)
  Discovered 3 open port(s):
    22/tcp     open   ssh          [OpenSSH 8.2p1 Ubuntu 4ubuntu0.5]
    80/tcp     open   http         [Apache httpd 2.4.41]
    443/tcp    open   https        [Apache httpd 2.4.41]

[Tip: Type /f to view the complete raw output]

[NEX | reconnaissance]> /phase service_enumeration
[+] Active phase switched to: service_enumeration

[NEX | service_enumeration]> Check what directories exist on the web server
→ Proposed Tool Call: gobuster [AUTO]
  Command:   gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirb/common.txt -q
  ...

[NEX | service_enumeration]> /history
[NEX | service_enumeration]> /findings
[NEX | service_enumeration]> /exit
```

### CLI subcommands (non-interactive)

```bash
nex tools              # list all catalog tools
nex status             # human-readable session status
nex status --json      # machine-readable JSON
nex --target 10.10.10.5   # pre-add a scope target and start REPL
nex --phase service_enumeration   # start in a specific phase
nex --ephemeral        # in-memory session, nothing persisted
nex --dual             # enable dual-model mode
nex init 10.10.10.5   # add scope without launching REPL
```

---

## REPL slash commands

| Command | Purpose |
|---|---|
| `/phase <name>` | Switch active CTF training phase |
| `/history` | Show last 15 tool invocations with status |
| `/f` | Expand last result to full raw output |
| `/dual` | Toggle dual-model mode at runtime |
| `/scope [target]` | View authorized scope or add a new target |
| `/findings` | List all structured findings extracted by Summarizer |
| `/tools` | List tools available for the current phase |
| `/exit` | Exit the session |

---

## How to add a new tool to the catalog

Open [`catalog.yaml`](catalog.yaml) and append a new entry under the
appropriate phase.  Schema reference:

```yaml
- name: feroxbuster                     # unique identifier (snake_case)
  phase: service_enumeration            # one of the five CTF phases
  approval_tier: AUTO                   # AUTO or APPROVAL (see safety model)
  description: >
    Recursive web content discovery with automatic filtering.
    Used to find hidden directories and files on HTTP targets.
  command_template:                     # argument list — NO shell=True ever
    - "feroxbuster"
    - "--url"
    - "{url}"
    - "--depth"
    - "{depth}"
    - "-q"
  parser: parse_feroxbuster             # name of your Summarizer function
  timeout_seconds: 300
  parameters:
    url:
      type: string
      required: true
      description: "Target HTTP/HTTPS URL"
    depth:
      type: integer
      required: false
      default: 2
      description: "Recursion depth (1-5)"
```

**Rules for `command_template`:**
- Each element is a list item — never a joined shell string.
- Placeholders `{param_name}` are substituted by the Controller, **not** by
  shell expansion.  `shell=False` is enforced everywhere.
- Multi-word flag arguments (e.g. `{flags}`) are split with `shlex.split()`.

**Setting `timeout_seconds` for long-running tools:**
- `sqlmap` and `linpeas` can take 5–10 minutes on complex targets — use
  `timeout_seconds: 600` or more.
- `metasploit` resource scripts vary wildly; `900` is a safe ceiling.
- `pspy` is observation-window based — set `timeout_seconds` equal to the
  observation window you want, and stop the process via `[s]top` when done.

**Tools that take a binary path as a parameter (e.g. pspy):**
- Use `{binary_path}` as the first element of `command_template` instead of
  hardcoding the binary name.  This is necessary for tools that the operator
  manually transfers to the target.

After adding the entry, restart NEX — the catalog is validated at startup and
any schema error will surface with a clear message.

---

## How to write a new Summarizer parser

Open [`src/nex/summarizer.py`](src/nex/summarizer.py) and add a function:

```python
def parse_feroxbuster(output: str) -> dict[str, Any]:
    """Extract discovered URLs and status codes from feroxbuster output."""
    summary_lines: list[str] = []
    findings: list[dict[str, str]] = []

    # feroxbuster format:  200      GET   /admin  http://10.0.0.1/admin
    import re
    matches = re.findall(
        r"^(\d{3})\s+\w+\s+\d+l\s+\d+w.*?\s+(https?://\S+)$",
        output, re.MULTILINE
    )
    if matches:
        summary_lines.append(f"Discovered {len(matches)} URL(s):")
        for status, url in matches[:12]:
            summary_lines.append(f"  * {url}  (HTTP {status})")
            findings.append({"category": "web_path", "finding": f"{url} ({status})"})
    else:
        summary_lines.append("No URLs discovered.")

    return {"summary": summary_lines, "findings": findings}
```

Then register it in the `PARSER_REGISTRY` dict at the bottom of the file:

```python
PARSER_REGISTRY: dict[str, Callable[[str], dict[str, Any]]] = {
    ...  
    "parse_feroxbuster": parse_feroxbuster,   # <- add this line
}
```

**Parser contract:**
- Input: raw stdout+stderr string from the tool.
- Output: `{"summary": [str, ...], "findings": [{"category": str, "finding": str}, ...]}`
- `summary` lines are displayed in the REPL; `findings` are stored in SQLite.
- If unregistered, the generic `fallback_parser` (first 8 lines + count) is used — never crashes.
- **No LLM involved** — parsers are deterministic Python only.

**Tips for ANSI-heavy tools (linpeas, pspy):**
- These tools emit colour escape sequences (`\x1b[95m`, `\x1b[0m`, etc.) that
  clutter regex matching.  Strip ANSI before parsing:
  ```python
  import re
  ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
  clean = ansi_escape.sub("", output)
  ```
  The shipped `parse_linpeas` and `parse_pspy` patterns are written to be
  robust to plain-text output (after stripping or redirect-captured output).

**Tips for intermittent / long-running output (metasploit, sqlmap):**
- Both tools write partial results as they run — NEX streams stdout live.
  Parsers receive the **complete concatenated output** only after the process
  exits or times out.  Design parsers to scan the whole buffer, not just the
  last few lines.

---

## APPROVAL-tier safety model

### Why it exists

Some tools are **louder, more impactful, or legally sensitive** on a target.
Operators must explicitly confirm every invocation so there are no accidental
runs.  The model can *propose* these tools but **cannot execute them** — the
gate is pure Python and the model has no code path around it.

### How it works

1. Controller checks `approval_tier` from the catalog entry.
2. For `APPROVAL`:
   - Prints the **exact command line** that will be run.
   - Blocks on an interactive `[p]roceed / [s]top` prompt.
   - **[p]roceed** — runs the command, streams live output, records in memory.
   - **[s]top** — does not run anything; logs the declination (tool, args, reasoning, timestamp) to SQLite so the Planner sees it and proposes an alternative next turn.
3. For `AUTO`:
   - Executes immediately.
   - The proposed command is still **shown** before running (one-line preview) — there are no silent auto-runs.

### Marking a tool APPROVAL

In `catalog.yaml`:

```yaml
approval_tier: APPROVAL   # ← flag this tool
```

Add a YAML comment explaining why:

```yaml
# APPROVAL: sends credentials over the network; confirms intent before each attempt
- name: my_credential_tester
  approval_tier: APPROVAL
  ...
```

All Step 2 tools (sqlmap, hydra, metasploit, linpeas, pspy) are `APPROVAL` by
default.  Discovery and enumeration tools are `AUTO`.

---

## Project layout

```
nexTOOL/
├── catalog.yaml          ← Tool catalog (edit to add tools)
├── config.yaml           ← Model paths, timeouts, scope, log level
├── install.sh            ← One-step Kali setup script
├── pyproject.toml
├── README.md
├── models/               ← Drop GGUF weights here
│   ├── qwen3-0.6b-instruct.Q4_K_M.gguf
│   └── functiongemma-270m-it.Q8_0.gguf
├── src/nex/
│   ├── __init__.py
│   ├── catalog.py        ← YAML loader + schema validator
│   ├── cli.py            ← REPL, banner, slash commands, main()
│   ├── config.py         ← config.yaml loader, scope helpers
│   ├── controller.py     ← Deterministic gate + subprocess execution
│   ├── memory.py         ← SQLite session memory
│   ├── planner.py        ← Qwen3/FunctionGemma + heuristic fallback
│   └── summarizer.py     ← Per-tool deterministic parsers (LENS)
├── tests/
│   ├── test_catalog.py   ← Schema validation tests
│   ├── test_controller.py← AUTO/APPROVAL branching, stop logging
│   ├── test_memory.py    ← SQLite persistence round-trip
│   ├── test_planner.py   ← Phase-filtered prompts, JSON extraction
│   └── test_summarizer.py← Parser unit tests
└── .nex/
    ├── session.db        ← Persistent SQLite session
    └── raw/              ← Raw tool output artifacts
```

---

## Running the test suite

```bash
PYTHONPATH=src python -m unittest discover tests -v
```

All 25 tests cover:
- Catalog schema validation and phase filtering
- Controller AUTO/APPROVAL branching (mocked confirmation)
- Controller STOP logging to memory
- Out-of-scope target rejection
- Phase mismatch rejection
- Summarizer parsers: nmap, whois, dig, gobuster, enum4linux, smbclient, fallback
- Memory SQLite persistence round-trip (close + reopen)
- Memory ephemeral in-memory mode
- Planner phase-filtered prompt construction
- Planner heuristic fallback JSON generation
- JSON schema field validation

---

## Design decisions

| Decision | Rationale |
|---|---|
| SQLite over flat JSON | Survives concurrent writes, supports queries, no third-party dep |
| `shell=False` everywhere | Eliminates shell injection; args are always list literals |
| Heuristic fallback backend | System is immediately usable before GGUF weights are downloaded |
| Phase-filtered Planner prompt | Prevents model from hallucinating wrong-phase tools |
| Deterministic parsers | Output parsing never depends on model availability or correctness |
| `close()` on memory | Single persistent connection avoids WAL lock issues on Live USB fat32 |
