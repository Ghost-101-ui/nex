from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from .models import Phase, Risk, Tool


class GateError(ValueError):
    pass


def _host(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return parsed.hostname or value.split("/")[0]


def in_scope(target: str, allowed: list[str]) -> bool:
    host = _host(target).lower().rstrip(".")
    try:
        candidate = ipaddress.ip_address(host)
    except ValueError:
        # Domain scopes deliberately require exact host or subdomain boundary matching.
        return any(host == item.lower().rstrip(".") or host.endswith("." + item.lower().rstrip("."))
                   for item in allowed if "/" not in item)
    for item in allowed:
        try:
            if candidate in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            if host == item.lower().rstrip("."):
                return True
    return False


class Gate:
    def authorize(self, tool: Tool, args: dict, config: dict, confirmed: bool = False) -> None:
        extra = set(args) - set(tool.required) - set(tool.optional)
        missing = set(tool.required) - set(args)
        if extra or missing:
            raise GateError(f"Invalid arguments; missing={sorted(missing)}, unsupported={sorted(extra)}")
        for field in ("target", "domain", "service_name", "version", "ports"):
            if field in args and (not isinstance(args[field], (str, int)) or not str(args[field]).strip()):
                raise GateError(f"{field} must be a non-empty scalar value.")
        allowed_values = {
            "scan_type": {"quick", "full", "udp"},
            "mode": {"subdomains", "records"},
            "wordlist": {"small", "medium", "large"},
        }
        for field, choices in allowed_values.items():
            if field in args and args[field] not in choices:
                raise GateError(f"{field} must be one of {sorted(choices)}.")
        if "port" in args and (not isinstance(args["port"], int) or not 1 <= args["port"] <= 65535):
            raise GateError("port must be an integer between 1 and 65535.")
        target = args.get("target") or args.get("domain")
        if target and not in_scope(str(target), config["scope"]):
            raise GateError(f"Target {target!r} is outside the configured authorized lab scope.")
        current = Phase(config.get("phase", "recon"))
        if tool.phase not in (current, Phase.UTILITY):
            raise GateError(f"{tool.name} belongs to {tool.phase.value}; current phase is {current.value}.")
        if tool.risk is Risk.CONFIRM and not confirmed:
            raise GateError("Confirmation required for this action.")
