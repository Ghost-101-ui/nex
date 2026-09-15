# CyberEDT NEX

NEX is a local, offline-friendly controller for **authorized CTF and lab** work on Kali. Models may propose a registered tool call, but the controller—not the model—validates arguments, target scope, phase rules, and confirmation requirements before execution.

## Current v0.1

- `nex init` creates a local lab configuration and session store.
- `nex status` checks the configuration, registered tools, and Ollama availability.
- `nex tools` displays the fixed registry.
- `nex run TOOL --args JSON` validates and executes a registered wrapper.
- All target-facing commands require `NEX_LAB_ACK=I_AM_AUTHORIZED` and a target in `nex.config.json`.
- High-impact actions are intentionally not included in this first executable slice.

This is not a scanner for systems you do not own or lack written authorization to test.

## Kali install (development)

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
nex init --scope 10.10.10.0/24
nex status
export NEX_LAB_ACK=I_AM_AUTHORIZED
nex run nmap_scan --args '{"target":"10.10.10.5","scan_type":"quick"}'
```

`nex init` accepts one or more comma-separated IPs, CIDRs, or domains. Keep the scope narrowly limited to the lab allocation.

To review or add a later, separately authorized lab target without replacing the original scope:

```bash
nex config show
nex config add-scope 10.10.10.5 --authorized
```

`nex help` and `nex --help` both show command help.

## Architecture boundary

The planned Ollama layer is an untrusted proposer. It can emit `{"tool": ..., "args": ...}`, but must route through `Gate.authorize()`; it does not get a shell, command strings, or a way to override policy.
