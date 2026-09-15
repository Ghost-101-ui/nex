from __future__ import annotations

import json
import ipaddress
from pathlib import Path
import shutil
import subprocess
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


def private_scopes() -> list[str]:
    return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def is_auto_trusted_scope(item: str) -> bool:
    """RFC1918 is convenient for labs; every other scope needs ownership confirmation."""
    try:
        return ipaddress.ip_network(item, strict=False).is_private
    except ValueError:
        return False


def vpn_scopes() -> list[str]:
    """Discover tunnel interfaces on Linux without requiring a network call."""
    if not shutil.which("ip"):
        return []
    try:
        data = json.loads(subprocess.check_output(["ip", "-j", "address"], text=True, stderr=subprocess.DEVNULL))
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
        return []
    scopes: list[str] = []
    for interface in data:
        name = interface.get("ifname", "")
        if not (name.startswith(("tun", "tap", "wg", "ppp"))):
            continue
        for address in interface.get("addr_info", []):
            if address.get("family") == "inet":
                scopes.append(str(ipaddress.ip_interface(f"{address['local']}/{address['prefixlen']}").network))
    return scopes


def initialize(scope: list[str] | None = None, authorized: bool = False) -> tuple[Path, list[str]]:
    path = config_path()
    detected = [*private_scopes(), *vpn_scopes()]
    requested = scope or []
    if requested and not authorized:
        for item in requested:
            if not is_auto_trusted_scope(item):
                raise ValueError("Adding a public scope requires --authorized.")
    if path.exists():
        data = load_config()
    else:
        data = {"scope": [], "phase": "recon", "phase_history": [], "timeouts": {"default": 120, "nikto_scan": 600},
                "models": {"reasoner": "qwen3:0.6b", "tool_caller": None}}
    for item in [*detected, *requested]:
        if item not in data["scope"]:
            data["scope"].append(item)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path, detected


def add_scope(scope_item: str, authorized: bool = False) -> dict[str, Any]:
    """Add one deliberately supplied authorized lab scope without replacing existing scope."""
    if not is_auto_trusted_scope(scope_item) and not authorized:
        raise ValueError("Refusing to change scope without an authorization acknowledgement.")
    data = load_config()
    if scope_item not in data["scope"]:
        data["scope"].append(scope_item)
        config_path().write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return data
