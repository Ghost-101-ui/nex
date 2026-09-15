from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .config import add_scope, config_path, initialize, is_auto_trusted_scope, load_config
from .executor import execute
from .gate import Gate, GateError, in_scope
from .lens import summarize
from .models import Phase
from .registry import TOOLS
from .session import load as load_session
from .session import action_artifact, markdown_report, read_artifact, record, record_note, search_artifacts, set_objective

REASONER_MODEL = "qwen3:0.6b"
TOOL_CALLER_MODEL = "hf.co/tinybiggames/functiongemma-270m-it-q8_0:Q8_0"


def _ollama_models() -> set[str]:
    if not shutil.which("ollama"):
        return set()
    try:
        output = subprocess.check_output(["ollama", "list"], text=True, stderr=subprocess.DEVNULL)
        return {line.split()[0] for line in output.splitlines()[1:] if line.split()}
    except (OSError, subprocess.CalledProcessError):
        return set()


def _web(value: str) -> str:
    return value if "://" in value else f"http://{value}"


def _offer_model(model: str) -> None:
    """Pull only after an interactive affirmative answer; never on manual scans."""
    if model in _ollama_models():
        print(f"[ok] {model} found")
        return
    if not shutil.which("ollama"):
        print(f"[!] {model} unavailable because Ollama is not installed")
        return
    if not sys.stdin.isatty():
        print(f"[!] {model} not installed; run 'ollama pull {model}' when online")
        return
    if input(f"[?] {model} is missing. Pull it now? [y/N] ").strip().lower() in {"y", "yes"}:
        subprocess.run(["ollama", "pull", model], check=False)


def _confirm_public_scope(target: str, authorized: bool, ownership: bool) -> None:
    """A public target needs two explicit command flags and exact retyping."""
    if is_auto_trusted_scope(target):
        return
    if not (authorized and ownership):
        raise ValueError("Public scope requires both --i-own-this and --authorized.")
    if not sys.stdin.isatty():
        raise ValueError("Public scope confirmation must be completed in an interactive terminal.")
    typed = input(f"Type the exact target to confirm authorization ({target}): ").strip()
    if typed != target:
        raise ValueError("Target confirmation did not match; scope was not changed.")


def _flat_args(ns: argparse.Namespace) -> dict[str, Any]:
    if ns.args:
        parsed = json.loads(ns.args)
        if not isinstance(parsed, dict): raise ValueError("--args must be a JSON object.")
        return parsed
    if ns.tool == "nmap_scan":
        scan = "full" if ns.full else "udp" if ns.udp else "quick"
        return {k: v for k, v in {"target": ns.target, "scan_type": scan, "ports": ns.ports}.items() if v is not None}
    if ns.tool in {"whatweb_scan", "nikto_scan", "gobuster_dir"}:
        args = {"target": _web(ns.target)}
        if ns.tool == "gobuster_dir": args["wordlist"] = ns.wordlist
        return args
    if ns.tool == "dns_enum": return {"domain": ns.domain or ns.target, "mode": ns.mode}
    if ns.tool == "service_probe": return {"target": ns.target, "port": ns.port}
    if ns.tool in {"smb_enum", "ftp_anon_check"}: return {"target": ns.target}
    if ns.tool == "searchsploit_query": return {k: v for k, v in {"service_name": ns.service_name, "version": ns.version}.items() if v}
    if ns.tool == "note_capture": return {"content": ns.content}
    if ns.tool == "report_status": return {}
    if ns.tool == "file_search": return {k: v for k, v in {"pattern": ns.pattern, "path": ns.path}.items() if v}
    if ns.tool in {"read_file", "flag_grep"}: return {"path": ns.path}
    raise ValueError("Use --args for this tool.")


def _run(name: str, args: dict[str, Any], config: dict[str, Any]) -> None:
    tool = TOOLS[name]
    Gate().authorize(tool, args, config)
    if tool.executable == "internal":
        if name == "note_capture":
            record_note(args["content"]); output = "Note saved to session memory."
        elif name == "file_search": output = "\n".join(search_artifacts(args["pattern"], args.get("path"))) or "No matching session artifacts."
        elif name == "read_file": output = read_artifact(args["path"])
        elif name == "flag_grep":
            from .session import FLAG_PATTERN
            output = "\n".join(FLAG_PATTERN.findall(read_artifact(args["path"]))) or "No flag pattern found."
        else: output = json.dumps(load_session(), indent=2)
        code = 0
    else:
        timeout = int(config.get("timeouts", {}).get(tool.name, config.get("timeouts", {}).get("default", 120)))
        code, output = execute(tool, args, timeout)
    summary = summarize(tool.name, output)
    print(f"[ok] {tool.name} (exit {code})")
    print("\n".join(summary))
    flags = record(tool.name, args, code, output, config["phase"], summary)
    history = config.setdefault("phase_history", [])
    history.append({"tool": tool.name, "phase": tool.phase.value, "exit_code": code})
    if tool.phase is Phase.RECON and config["phase"] == Phase.RECON:
        config["phase"] = Phase.ENUMERATION
    elif tool.phase is Phase.ENUMERATION and config["phase"] == Phase.ENUMERATION:
        successful_enum = sum(1 for item in history if item["phase"] == Phase.ENUMERATION and item["exit_code"] == 0)
        if successful_enum >= 2: config["phase"] = Phase.EXPLOITATION
    config_path().write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    if flags: print("\n[!] possible flag found: " + ", ".join(flags))


def _status(as_json: bool) -> None:
    config, session, models = load_config(), load_session(), _ollama_models()
    if as_json:
        print(json.dumps({"version": __version__, "config": config, "models": sorted(models), "session": session}, indent=2)); return
    reasoner = config["models"]["reasoner"]
    print(f"NEX v{__version__}\n{'-' * 30}")
    print(f"Reasoner:        {reasoner:<20} {'READY' if reasoner in models else 'NOT INSTALLED'}")
    print(f"Tool-caller:     {'enabled' if config['models'].get('tool_caller') else 'not enabled'}")
    print(f"Scope:           {', '.join(config['scope'])}\nPhase:           {config['phase']}")
    print(f"Tools available: {len(TOOLS)} SAFE wrappers\nSession log:     {len(session['actions'])} actions run, {len(session['flags'])} possible flags")
    if session.get("objective"): print(f"Objective:       {session['objective']}")


def _interactive() -> None:
    config, session = load_config(), load_session()
    try: import questionary
    except ImportError: raise RuntimeError("Interactive mode requires questionary. Run 'pip install -e .' to install dependencies.")
    print(f"CyberEDT NEX | scope: {', '.join(config['scope'])} | phase: {config['phase']}")
    choice = questionary.select("What do you want to do:", choices=["Run a recon scan", "Run enumeration", "View findings so far", "Quit"]).ask()
    if not choice or choice == "Quit": return
    if choice == "View findings so far": print(json.dumps(session, indent=2)); return
    phase = Phase.RECON if choice == "Run a recon scan" else Phase.ENUMERATION
    names = [name for name, tool in TOOLS.items() if tool.phase is phase]
    name = questionary.select(f"{phase.value.title()} tool:", choices=names + ["< back"]).ask()
    if not name or name == "< back": return
    target = questionary.text("Target:", default=session.get("last_target") or "").ask()
    if not target: return
    if not in_scope(target, config["scope"]):
        print("Target is outside the authorized scope. For public targets, use: nex init <target> --i-own-this --authorized")
        return
    args: dict[str, Any] = {"target": target}
    if name == "nmap_scan": args["scan_type"] = questionary.select("Scan type:", choices=["quick", "full", "udp"]).ask()
    elif name in {"whatweb_scan", "nikto_scan", "gobuster_dir"}: args["target"] = _web(target)
    if name == "gobuster_dir": args["wordlist"] = questionary.select("Wordlist:", choices=["small", "medium", "large"]).ask()
    if name == "dns_enum": args = {"domain": target, "mode": "subdomains"}
    if name == "service_probe": args["port"] = int(questionary.text("Port:", default="80").ask() or "80")
    _run(name, args, config)


def main() -> None:
    if len(sys.argv) == 1:
        try: _interactive()
        except (ValueError, GateError, RuntimeError) as exc: print(f"NEX blocked: {exc}", file=sys.stderr)
        return
    if len(sys.argv) > 1 and sys.argv[1] == "help": sys.argv[1:] = ["--help"]
    parser = argparse.ArgumentParser(prog="nex", description="Gated orchestration for authorized security labs")
    subs = parser.add_subparsers(dest="command", required=True)
    init = subs.add_parser("init", help="Auto-detect lab scope and refresh configuration")
    init.add_argument("scope", nargs="?"); init.add_argument("--authorized", action="store_true"); init.add_argument("--i-own-this", action="store_true"); init.add_argument("--dual", action="store_true")
    status = subs.add_parser("status"); status.add_argument("--json", action="store_true")
    subs.add_parser("tools"); subs.add_parser("report", help="Write nex-report.md from session memory")
    subs.add_parser("findings", help="Show persistent structured findings")
    subs.add_parser("artifacts", help="List captured raw session artifacts")
    raw = subs.add_parser("raw", help="Display raw output for an action number"); raw.add_argument("action", type=int)
    objective = subs.add_parser("objective", help="Set the current session objective"); objective.add_argument("text")
    subs.add_parser("resume", help="Show the persisted session summary")
    config_parser = subs.add_parser("config"); config_subs = config_parser.add_subparsers(dest="config_command", required=True)
    config_subs.add_parser("show")
    scope_parser = config_subs.add_parser("add-scope"); scope_parser.add_argument("scope"); scope_parser.add_argument("--authorized", action="store_true"); scope_parser.add_argument("--i-own-this", action="store_true")
    quick = subs.add_parser("quick", help="Run SAFE recon and enumeration starter chain"); quick.add_argument("target")
    run = subs.add_parser("run", help="Run a registered tool with normal flags")
    run.add_argument("tool", choices=sorted(TOOLS)); run.add_argument("--args"); run.add_argument("--target"); run.add_argument("--domain"); run.add_argument("--ports"); run.add_argument("--port", type=int)
    run.add_argument("--quick", action="store_true"); run.add_argument("--full", action="store_true"); run.add_argument("--udp", action="store_true")
    run.add_argument("--wordlist", choices=["small", "medium", "large"], default="small"); run.add_argument("--mode", choices=["subdomains", "records"], default="subdomains")
    run.add_argument("--service-name"); run.add_argument("--version"); run.add_argument("--content"); run.add_argument("--pattern"); run.add_argument("--path")
    ns = parser.parse_args()
    try:
        if ns.command == "init":
            if ns.scope: _confirm_public_scope(ns.scope, ns.authorized, ns.i_own_this)
            path, detected = initialize([ns.scope] if ns.scope else None, ns.authorized)
            print("NEX SETUP\n" + "-" * 30)
            print(f"[ok] Ollama {'detected' if shutil.which('ollama') else 'not found'}")
            print(f"[ok] Session scope refreshed: {', '.join(detected) if detected else 'RFC1918 private ranges'}")
            _offer_model(REASONER_MODEL)
            if ns.dual: _offer_model(TOOL_CALLER_MODEL)
            print(f"[ok] Config: {path}\nNEX is ready. Run 'nex quick <target>' or bare 'nex' for the menu."); return
        if ns.command == "tools":
            for tool in TOOLS.values(): print(f"{tool.name:18} {tool.phase.value:14} {tool.risk.value}")
            return
        if ns.command == "status": _status(ns.json); return
        if ns.command == "resume": _status(False); return
        if ns.command == "objective": set_objective(ns.text); print("Session objective saved."); return
        if ns.command == "findings":
            findings = load_session()["findings"]
            print(json.dumps(findings, indent=2) if findings else "No findings recorded."); return
        if ns.command == "artifacts":
            actions = load_session()["actions"]
            if not actions: print("No captured artifacts.")
            for index, action in enumerate(actions, start=1): print(f"{index}: {action.get('raw_output', 'none')} ({action['tool']})")
            return
        if ns.command == "raw": print(action_artifact(ns.action).read_text(encoding="utf-8", errors="replace")); return
        if ns.command == "config":
            if ns.config_command == "show": print(json.dumps(load_config(), indent=2))
            else:
                _confirm_public_scope(ns.scope, ns.authorized, ns.i_own_this)
                add_scope(ns.scope, ns.authorized); print(f"Added authorized scope: {ns.scope}")
            return
        if ns.command == "report":
            path = Path.cwd() / "nex-report.md"; path.write_text(markdown_report(load_config()), encoding="utf-8"); print(f"Wrote {path}"); return
        if ns.command == "quick":
            config = load_config()
            if not in_scope(ns.target, config["scope"]): raise GateError("Target is outside scope. Run 'nex init <target> --authorized' first.")
            _run("nmap_scan", {"target": ns.target, "scan_type": "quick"}, config)
            _run("nmap_scan", {"target": ns.target, "scan_type": "full"}, config)
            _run("whatweb_scan", {"target": _web(ns.target)}, config)
            config["phase"] = "enumeration"; config_path().write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
            _run("gobuster_dir", {"target": _web(ns.target), "wordlist": "small"}, config)
            print("Quick chain complete. No CONFIRM-tier action was run."); return
        _run(ns.tool, _flat_args(ns), load_config())
    except (ValueError, GateError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"NEX blocked: {exc}", file=sys.stderr); raise SystemExit(2)


if __name__ == "__main__": main()
