from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SESSION_NAME = "nex.session.json"
FLAG_PATTERN = re.compile(r"(?:HTB|THM|flag|picoCTF|CTF)\{[^\r\n}]{1,200}\}", re.I)


def _path() -> Path:
    return Path.cwd() / SESSION_NAME


def load() -> dict[str, Any]:
    if _path().exists():
        return json.loads(_path().read_text(encoding="utf-8"))
    return {"actions": [], "findings": [], "flags": [], "last_target": None}


def save(data: dict[str, Any]) -> None:
    _path().write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def record(tool: str, args: dict[str, Any], exit_code: int, output: str, phase: str, summary: list[str]) -> list[str]:
    data = load()
    flags = FLAG_PATTERN.findall(output)
    data["actions"].append({"at": datetime.now(timezone.utc).isoformat(), "tool": tool, "args": args, "exit_code": exit_code, "phase": phase})
    for item in summary:
        finding = {"tool": tool, "phase": phase, "summary": item}
        if finding not in data["findings"]:
            data["findings"].append(finding)
    data["last_target"] = args.get("target") or args.get("domain") or data.get("last_target")
    for flag in flags:
        if flag not in data["flags"]:
            data["flags"].append(flag)
    save(data)
    return flags


def markdown_report(config: dict[str, Any]) -> str:
    data = load()
    lines = ["# NEX Session Report", "", f"- Phase: `{config['phase']}`", f"- Scope: {', '.join(config['scope'])}", "", "## Actions"]
    lines.extend([f"- {a['at']} — `{a['tool']}` (exit {a['exit_code']})" for a in data["actions"]] or ["- No actions recorded."])
    lines += ["", "## Findings"]
    lines.extend([f"- `{f['tool']}`: {f['summary']}" for f in data["findings"]] or ["- No findings recorded."])
    lines += ["", "## Possible flags"]
    lines.extend([f"- `{flag}`" for flag in data["flags"]] or ["- None found."])
    return "\n".join(lines) + "\n"
