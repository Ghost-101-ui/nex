from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore


class CatalogValidationError(ValueError):
    """Raised when catalog.yaml fails schema validation."""
    pass


ALLOWED_PHASES = {
    "reconnaissance",
    "service_enumeration",
    "vulnerability_assessment",
    "post_engagement_review",
    "utility",
}

ALLOWED_APPROVAL_TIERS = {"AUTO", "APPROVAL"}


@dataclass(frozen=True)
class ParameterDefinition:
    name: str
    type: str = "string"
    required: bool = False
    default: Any = None
    description: str = ""


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    phase: str
    approval_tier: str
    description: str
    command_template: list[str]
    parser: str
    timeout_seconds: int = 300
    parameters: dict[str, ParameterDefinition] = field(default_factory=dict)

    def required_params(self) -> set[str]:
        return {k for k, v in self.parameters.items() if v.required}

    def all_params(self) -> set[str]:
        return set(self.parameters.keys())


class Catalog:
    def __init__(self, tools: dict[str, ToolDefinition], phases: list[str], version: str = "1.0"):
        self.tools = tools
        self.phases = phases
        self.version = version

    @classmethod
    def from_yaml_file(cls, path: str | Path) -> Catalog:
        filepath = Path(path)
        if not filepath.exists():
            raise CatalogValidationError(f"Catalog file not found: {filepath}")

        content = filepath.read_text(encoding="utf-8")
        if yaml is None:
            # Fallback simple parser if PyYAML isn't available
            raise CatalogValidationError("PyYAML is required to parse catalog.yaml. Run 'pip install pyyaml'.")

        try:
            raw_data = yaml.safe_load(content)
        except Exception as exc:
            raise CatalogValidationError(f"Malformed YAML in {filepath}: {exc}") from exc

        if not isinstance(raw_data, dict):
            raise CatalogValidationError(f"Catalog root must be a dictionary, got {type(raw_data).__name__}")

        return cls.from_dict(raw_data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Catalog:
        if "version" not in data:
            raise CatalogValidationError("Catalog missing 'version' field.")

        phases = data.get("phases", [])
        if not isinstance(phases, list) or not phases:
            raise CatalogValidationError("Catalog must define a non-empty 'phases' list.")

        for phase in phases:
            if phase not in ALLOWED_PHASES:
                raise CatalogValidationError(
                    f"Unknown phase {phase!r}. Allowed phases: {sorted(ALLOWED_PHASES)}"
                )

        raw_tools = data.get("tools", [])
        if not isinstance(raw_tools, list):
            raise CatalogValidationError("'tools' must be a list in catalog.")

        tools: dict[str, ToolDefinition] = {}

        for index, item in enumerate(raw_tools):
            if not isinstance(item, dict):
                raise CatalogValidationError(f"Tool at index {index} must be an object.")

            # Validate required fields
            for req in ("name", "phase", "approval_tier", "description", "command_template", "parser"):
                if req not in item or item[req] is None or item[req] == "":
                    raise CatalogValidationError(f"Tool index {index} is missing required field '{req}'.")

            name = str(item["name"]).strip()
            if not re.match(r"^[a-zA-Z0-9_-]+$", name):
                raise CatalogValidationError(f"Tool name {name!r} contains invalid characters.")

            phase = str(item["phase"]).strip()
            if phase not in ALLOWED_PHASES:
                raise CatalogValidationError(
                    f"Tool '{name}' specifies invalid phase {phase!r}. Allowed: {sorted(ALLOWED_PHASES)}"
                )

            tier = str(item["approval_tier"]).strip().upper()
            if tier not in ALLOWED_APPROVAL_TIERS:
                raise CatalogValidationError(
                    f"Tool '{name}' specifies invalid approval_tier {tier!r}. Allowed: {sorted(ALLOWED_APPROVAL_TIERS)}"
                )

            template = item["command_template"]
            if not isinstance(template, list) or not template:
                raise CatalogValidationError(f"Tool '{name}' command_template must be a non-empty list of tokens.")

            parser_name = str(item["parser"]).strip()
            timeout = int(item.get("timeout_seconds", 300))

            # Parse parameters
            raw_params = item.get("parameters", {})
            if not isinstance(raw_params, dict):
                raise CatalogValidationError(f"Tool '{name}' parameters must be a dictionary.")

            params: dict[str, ParameterDefinition] = {}
            for p_name, p_data in raw_params.items():
                if not isinstance(p_data, dict):
                    raise CatalogValidationError(f"Tool '{name}' parameter '{p_name}' must be an object.")
                params[p_name] = ParameterDefinition(
                    name=p_name,
                    type=p_data.get("type", "string"),
                    required=bool(p_data.get("required", False)),
                    default=p_data.get("default", None),
                    description=str(p_data.get("description", "")),
                )

            if name in tools:
                raise CatalogValidationError(f"Duplicate tool name defined in catalog: '{name}'")

            tools[name] = ToolDefinition(
                name=name,
                phase=phase,
                approval_tier=tier,
                description=str(item["description"]).strip(),
                command_template=[str(t) for t in template],
                parser=parser_name,
                timeout_seconds=timeout,
                parameters=params,
            )

        return cls(tools=tools, phases=phases, version=str(data["version"]))

    def get_tool(self, name: str) -> ToolDefinition | None:
        return self.tools.get(name)

    def get_tools_for_phase(self, phase: str, include_utility: bool = True) -> list[ToolDefinition]:
        """Returns tools for the specified phase, optionally including utility tools."""
        results = [t for t in self.tools.values() if t.phase == phase]
        if include_utility and phase != "utility":
            results.extend([t for t in self.tools.values() if t.phase == "utility"])
        return results

    def to_tool_prompt_schema(self, phase: str, include_utility: bool = True) -> list[dict[str, Any]]:
        """Generates tool schema metadata used directly in Planner prompt construction.
        Crucially, this ensures the model ONLY sees tools for the current phase!"""
        tools = self.get_tools_for_phase(phase, include_utility=include_utility)
        schema_list = []
        for t in tools:
            schema_list.append({
                "name": t.name,
                "phase": t.phase,
                "approval_tier": t.approval_tier,
                "description": t.description,
                "parameters": {
                    p_name: {
                        "type": p.type,
                        "required": p.required,
                        "default": p.default,
                        "description": p.description,
                    }
                    for p_name, p in t.parameters.items()
                },
            })
        return schema_list
