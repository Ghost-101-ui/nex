from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SESSION_NAME = "nex.session.json"
ARTIFACT_DIR = ".nex/raw"
FLAG_PATTERN = re.compile(r"(?:HTB|THM|flag|picoCTF|CTF)\{[^\r\n}]{1,200}\}", re.I)


def _path() -> Path:
    return Path.cwd() / SESSION_NAME


def artifact_root() -> Path:
    root = Path.cwd() / ARTIFACT_DIR
    root.mkdir(parents=True, exist_ok=True)
    return root


def artifact_path(value: str) -> Path:
    candidate = Path(value).resolve()
    root = artifact_root().resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("Artifact paths must stay within NEX's .nex/raw session directory.")
    if not candidate.is_file():
        raise ValueError("Session artifact does not exist.")
    return candidate


def load() -> dict[str, Any]:
    if _path().exists():
        return json.loads(_path().read_text(encoding="utf-8"))
    return {"actions": [], "findings": [], "flags": [], "last_target": None}


def save(data: dict[str, Any]) -> None:
    _path().write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def record(tool: str, args: dict[str, Any], exit_code: int, output: str, phase: str, summary: list[str]) -> list[str]:
    data = load()
    flags = FLAG_PATTERN.findall(output)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw_file = artifact_root() / f"{len(data['actions']) + 1:03d}-{stamp}-{tool}.txt"
    raw_file.write_text(output, encoding="utf-8", errors="replace")
    data["actions"].append({"at": datetime.now(timezone.utc).isoformat(), "tool": tool, "args": args, "exit_code": exit_code, "phase": phase, "raw_output": str(raw_file.relative_to(Path.cwd()))})
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


def record_note(content: str) -> None:
    data = load()
    data.setdefault("notes", []).append({"at": datetime.now(timezone.utc).isoformat(), "content": content})
    save(data)


def search_artifacts(pattern: str, path: str | None = None) -> list[str]:
    root = artifact_path(path) if path else artifact_root()
    files = [root] if root.is_file() else list(root.rglob("*.txt"))
    return [str(item.relative_to(Path.cwd())) for item in files if pattern.casefold() in item.read_text(encoding="utf-8", errors="replace").casefold()]


def read_artifact(path: str) -> str:
    return artifact_path(path).read_text(encoding="utf-8", errors="replace")


def markdown_report(config: dict[str, Any]) -> str:
    data = load()
    lines = ["# NEX Session Report", "", f"- Phase: `{config['phase']}`", f"- Scope: {', '.join(config['scope'])}", "", "## Actions"]
    lines.extend([f"- {a['at']} — `{a['tool']}` (exit {a['exit_code']})" for a in data["actions"]] or ["- No actions recorded."])
    lines += ["", "## Findings"]
    lines.extend([f"- `{f['tool']}`: {f['summary']}" for f in data["findings"]] or ["- No findings recorded."])
    lines += ["", "## Possible flags"]
    lines.extend([f"- `{flag}`" for flag in data["flags"]] or ["- None found."])
    lines += ["", "## Notes"]
    lines.extend([f"- {note['at']}: {note['content']}" for note in data.get("notes", [])] or ["- None captured."])
    return "\n".join(lines) + "\n"
