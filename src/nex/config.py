from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

CONFIG_YAML_NAME = "config.yaml"
CONFIG_JSON_NAME = "nex.config.json"


def find_project_root() -> Path:
    """Find the root directory of the NEX project."""
    # Check current directory
    cwd = Path.cwd()
    if (cwd / CONFIG_YAML_NAME).exists() or (cwd / "catalog.yaml").exists():
        return cwd
    # Check parent directories
    for parent in Path(__file__).resolve().parents:
        if (parent / CONFIG_YAML_NAME).exists() or (parent / "catalog.yaml").exists():
            return parent
    return cwd


def config_yaml_path() -> Path:
    return find_project_root() / CONFIG_YAML_NAME


def private_scopes() -> list[str]:
    return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def is_auto_trusted_scope(item: str) -> bool:
    """RFC1918 is convenient for labs; public IPs require explicit operator authorization."""
    try:
        return ipaddress.ip_network(item, strict=False).is_private
    except ValueError:
        return False


def vpn_scopes() -> list[str]:
    """Discover tunnel interfaces on Linux without requiring network calls."""
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


DEFAULT_CONFIG: dict[str, Any] = {
    "version": "1.0",
    "models": {
        "planner_model_path": "models/qwen3-0.6b-instruct.Q4_K_M.gguf",
        "tool_caller_model_path": "models/functiongemma-270m-it.Q8_0.gguf",
        "dual_mode": False,
        "temperature": 0.1,
        "context_size": 2048,
    },
    "execution": {
        "default_timeout_seconds": 300,
        "auto_trust_private": True,
        "auto_detect_vpn": True,
    },
    "session": {
        "memory_db_path": ".nex/session.db",
        "artifacts_dir": ".nex/raw",
        "log_level": "INFO",
    },
    "scope": {
        "allowed_targets": [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ],
    },
}


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load configuration from config.yaml or fallback to defaults."""
    cfg_file = Path(path) if path else config_yaml_path()
    
    config = dict(DEFAULT_CONFIG)
    if cfg_file.exists() and yaml is not None:
        try:
            loaded = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                # Deep merge top-level sections
                for sec, val in loaded.items():
                    if isinstance(val, dict) and isinstance(config.get(sec), dict):
                        config[sec].update(val)
                    else:
                        config[sec] = val
        except Exception:
            pass

    # Ensure scopes include RFC1918 and detected VPN if enabled
    scope_list = list(config.get("scope", {}).get("allowed_targets", []))
    if config.get("execution", {}).get("auto_trust_private", True):
        for ps in private_scopes():
            if ps not in scope_list:
                scope_list.append(ps)

    if config.get("execution", {}).get("auto_detect_vpn", True):
        for vs in vpn_scopes():
            if vs not in scope_list:
                scope_list.append(vs)

    config.setdefault("scope", {})["allowed_targets"] = scope_list
    return config


def save_config(config: dict[str, Any], path: str | Path | None = None) -> None:
    cfg_file = Path(path) if path else config_yaml_path()
    if yaml is not None:
        cfg_file.write_text(yaml.safe_dump(config, indent=2, sort_keys=False), encoding="utf-8")
    else:
        # Fallback to json-styled representation or raw write
        cfg_file.write_text(json.dumps(config, indent=2), encoding="utf-8")
