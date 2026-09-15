from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CONFIG_NAME = "nex.config.json"


def config_path() -> Path:
    return Path.cwd() / CONFIG_NAME


def load_config() -> dict[str, Any]:
    path = config_path()
    if not path.exists():
        raise ValueError(f"Missing {CONFIG_NAME}; run 'nex init --scope <lab-scope>'.")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data.get("scope"), list) or not data["scope"]:
        raise ValueError("Configuration must contain a non-empty scope list.")
    return data


def initialize(scope: list[str]) -> Path:
    path = config_path()
    if path.exists():
        raise ValueError(f"{path} already exists; edit it deliberately rather than overwriting it.")
    data = {
        "scope": scope,
        "phase": "recon",
        "timeouts": {"default": 120, "nikto_scan": 600},
        "models": {"reasoner": "qwen3:0.6b", "tool_caller": None},
    }
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path
