from __future__ import annotations

import ipaddress
import os
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .catalog import Catalog, ToolDefinition
from .memory import SessionMemory
from .summarizer import get_parser


class ControllerError(ValueError):
    """Raised when request validation fails at the controller gate."""
    pass


def extract_host(target: str) -> str:
    """Extract host / IP from URL, domain, or IP string."""
    clean = target.strip()
    if "://" in clean:
        parsed = urlparse(clean)
        return parsed.hostname or clean.split("/")[0]
    return clean.split("/")[0].split(":")[0]


def is_target_in_scope(target: str, allowed_scope: list[str]) -> bool:
    """Check if the given target host/IP is in the authorized lab scope."""
    if not allowed_scope:
        return False

    host = extract_host(target).lower().rstrip(".")
    if not host:
        return False

    # Check if host is an IP address
    try:
        candidate_ip = ipaddress.ip_address(host)
        for item in allowed_scope:
            item_clean = item.strip()
            try:
                network = ipaddress.ip_network(item_clean, strict=False)
                if candidate_ip in network:
                    return True
            except ValueError:
                if host == item_clean.lower().rstrip("."):
                    return True
        return False
    except ValueError:
        # Host is a domain name
        for item in allowed_scope:
            item_clean = item.strip().lower().rstrip(".")
            if "/" not in item_clean:
                # Exact domain or subdomain match
                if host == item_clean or host.endswith("." + item_clean):
                    return True
        return False


@dataclass
class ExecutionResult:
    tool: str
    command: list[str]
    status: str  # EXECUTED, STOPPED, FAILED, TIMEOUT
    exit_code: int | None
    duration_sec: float
    summary: list[str]
    raw_output: str
    reasoning: str
    approval_tier: str


class Controller:
    """Deterministic validation and execution gate for NEX."""

    def __init__(
        self,
        catalog: Catalog,
        memory: SessionMemory,
        default_timeout: int = 300,
        confirm_callback: Callable[[list[str], str], bool] | None = None,
        stream_callback: Callable[[str], None] | None = None,
    ):
        self.catalog = catalog
        self.memory = memory
        self.default_timeout = default_timeout
        self.confirm_callback = confirm_callback
        self.stream_callback = stream_callback

    def build_command_args(self, tool: ToolDefinition, args: dict[str, Any]) -> list[str]:
        """Constructs argument list safely from command_template and validated args.
        Never interpolates raw strings into shell=True."""
        cmd: list[str] = []
        for token in tool.command_template:
            # Check if token contains a placeholder like {target}
            if "{" in token and "}" in token:
                # Find placeholder names
                formatted = token
                for param_name, param_val in args.items():
                    placeholder = f"{{{param_name}}}"
                    if placeholder in formatted:
                        formatted = formatted.replace(placeholder, str(param_val))
                
                # If placeholder was for multi-flag arguments (e.g. flags), split with shlex
                if token == "{flags}" or token == "{options}":
                    if formatted and formatted != token:
                        cmd.extend(shlex.split(formatted))
                else:
                    if formatted != token:
                        cmd.append(formatted)
            else:
                cmd.append(token)
        return cmd

    def validate_request(
        self,
        tool_name: str,
        args: dict[str, Any],
        current_phase: str,
    ) -> ToolDefinition:
        """Validates tool existence, phase compatibility, arguments, and scope."""
        tool = self.catalog.get_tool(tool_name)
        if not tool:
            raise ControllerError(f"Tool {tool_name!r} is not registered in the catalog.")

        # Phase validation: tool must match current phase or be a utility tool
        if tool.phase != "utility" and tool.phase != current_phase:
            raise ControllerError(
                f"Tool '{tool.name}' belongs to phase '{tool.phase}', but the current active phase is '{current_phase}'."
            )

        # Parameter validation
        required_params = tool.required_params()
        missing = required_params - set(args.keys())
        if missing:
            raise ControllerError(f"Missing required parameter(s) for '{tool.name}': {sorted(missing)}")

        # Scope validation: check target/url/domain parameters
        scope = self.memory.get_scope()
        for target_key in ("target", "domain", "url"):
            if target_key in args:
                target_val = str(args[target_key])
                if not is_target_in_scope(target_val, scope):
                    raise ControllerError(
                        f"Target '{target_val}' is outside the authorized lab scope. "
                        f"Current scope: {scope}"
                    )

        return tool

    def default_confirm_prompt(self, command: list[str], reasoning: str) -> bool:
        """Default interactive prompt for APPROVAL tier actions."""
        cmd_str = " ".join(shlex.quote(c) for c in command)
        print("\n" + "=" * 60)
        print(" [!] APPROVAL TIER CONFIRMATION REQUIRED")
        print(f"     Command:   {cmd_str}")
        print(f"     Reasoning: {reasoning}")
        print("=" * 60)
        try:
            choice = input("Proceed with execution? [p]roceed / [s]top: ").strip().lower()
            return choice in ("p", "proceed", "y", "yes")
        except (KeyboardInterrupt, EOFError):
            print("\nExecution aborted by user.")
            return False

    def execute_request(
        self,
        tool_name: str,
        args: dict[str, Any],
        reasoning: str = "",
        force_auto: bool = False,
    ) -> ExecutionResult:
        """Main gate method: validate, check tier, confirm if needed, execute, parse, and record."""
        current_phase = self.memory.get_phase()
        tool = self.validate_request(tool_name, args, current_phase)

        # Merge defaults
        resolved_args = {}
        for p_name, p_def in tool.parameters.items():
            if p_name in args:
                resolved_args[p_name] = args[p_name]
            elif p_def.default is not None:
                resolved_args[p_name] = p_def.default

        # Internal utilities handling (e.g. note_capture)
        if tool.command_template and tool.command_template[0].startswith("internal:"):
            return self._handle_internal_tool(tool, resolved_args, reasoning)

        command = self.build_command_args(tool, resolved_args)

        # Check approval tier
        needs_approval = (tool.approval_tier == "APPROVAL") and not force_auto

        if needs_approval:
            confirm_fn = self.confirm_callback or self.default_confirm_prompt
            proceed = confirm_fn(command, reasoning)
            if not proceed:
                # Stop requested!
                self.memory.record_stop(
                    tool=tool.name,
                    args=resolved_args,
                    phase=current_phase,
                    reasoning=reasoning,
                    approval_tier=tool.approval_tier,
                )
                return ExecutionResult(
                    tool=tool.name,
                    command=command,
                    status="STOPPED",
                    exit_code=None,
                    duration_sec=0.0,
                    summary=["Execution stopped by operator."],
                    raw_output="Action declined by operator.",
                    reasoning=reasoning,
                    approval_tier=tool.approval_tier,
                )

        # Check executable availability
        executable = command[0]
        if not shutil.which(executable):
            error_msg = f"Required executable not found in PATH: {executable}"
            self.memory.record_request(
                tool=tool.name,
                args=resolved_args,
                phase=current_phase,
                reasoning=reasoning,
                approval_tier=tool.approval_tier,
                status="FAILED",
                exit_code=127,
                duration_sec=0.0,
                summary=[error_msg],
                raw_output=error_msg,
            )
            return ExecutionResult(
                tool=tool.name,
                command=command,
                status="FAILED",
                exit_code=127,
                duration_sec=0.0,
                summary=[error_msg],
                raw_output=error_msg,
                reasoning=reasoning,
                approval_tier=tool.approval_tier,
            )

        # Execute command safely without shell=True
        timeout = tool.timeout_seconds or self.default_timeout
        start_time = time.time()
        output_chunks: list[str] = []
        status = "EXECUTED"
        exit_code = 0

        try:
            # We use Popen with context manager to stream live and ensure pipe cleanup
            with subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                shell=False,
                bufsize=1,
            ) as process:
                try:
                    if process.stdout:
                        for line in process.stdout:
                            output_chunks.append(line)
                            if needs_approval and self.stream_callback:
                                self.stream_callback(line)
                            elif needs_approval:
                                sys.stdout.write(line)
                                sys.stdout.flush()
                    process.wait(timeout=timeout)
                    exit_code = process.returncode
                    if exit_code != 0:
                        status = "FAILED"
                except subprocess.TimeoutExpired:
                    process.kill()
                    output_chunks.append(f"\n[!] Command timed out after {timeout} seconds.")
                    status = "TIMEOUT"
                    exit_code = -1

        except Exception as exc:
            output_chunks.append(f"\nExecution error: {exc}")
            status = "FAILED"
            exit_code = 1

        duration = time.time() - start_time
        raw_output = "".join(output_chunks)

        # Parse with summarizer
        parser_fn = get_parser(tool.parser)
        parsed = parser_fn(raw_output)
        summary = parsed.get("summary", ["(Completed)"])
        findings = parsed.get("findings", [])

        # Record findings in session memory
        for f in findings:
            self.memory.record_finding(
                tool=tool.name,
                phase=current_phase,
                category=f.get("category", "general"),
                finding=f.get("finding", ""),
            )

        # Record request history
        self.memory.record_request(
            tool=tool.name,
            args=resolved_args,
            phase=current_phase,
            reasoning=reasoning,
            approval_tier=tool.approval_tier,
            status=status,
            exit_code=exit_code,
            duration_sec=round(duration, 2),
            summary=summary,
            raw_output=raw_output,
        )

        return ExecutionResult(
            tool=tool.name,
            command=command,
            status=status,
            exit_code=exit_code,
            duration_sec=round(duration, 2),
            summary=summary,
            raw_output=raw_output,
            reasoning=reasoning,
            approval_tier=tool.approval_tier,
        )

    def _handle_internal_tool(
        self,
        tool: ToolDefinition,
        args: dict[str, Any],
        reasoning: str,
    ) -> ExecutionResult:
        """Handles internal execution for non-binary utility tools like note_capture."""
        action = tool.command_template[0].split(":", 1)[1]
        current_phase = self.memory.get_phase()

        if action == "note_capture":
            content = args.get("content", "")
            self.memory.record_note(content)
            raw = f"Note saved: {content}"
            summary = [f"Note recorded in session memory ({len(content)} chars)"]
            self.memory.record_finding(
                tool="note_capture",
                phase=current_phase,
                category="operator_note",
                finding=content[:100],
            )
            self.memory.record_request(
                tool=tool.name,
                args=args,
                phase=current_phase,
                reasoning=reasoning,
                approval_tier=tool.approval_tier,
                status="EXECUTED",
                exit_code=0,
                duration_sec=0.01,
                summary=summary,
                raw_output=raw,
            )
            return ExecutionResult(
                tool=tool.name,
                command=["internal", "note_capture"],
                status="EXECUTED",
                exit_code=0,
                duration_sec=0.01,
                summary=summary,
                raw_output=raw,
                reasoning=reasoning,
                approval_tier=tool.approval_tier,
            )

        raise ControllerError(f"Unknown internal utility action: {action}")
