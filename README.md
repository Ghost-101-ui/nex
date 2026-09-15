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
