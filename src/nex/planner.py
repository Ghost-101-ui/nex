from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from .catalog import Catalog
from .memory import SessionMemory

logger = logging.getLogger("nex.planner")


class PlannerError(ValueError):
    """Raised when the planner fails to generate a valid structured request."""
    pass


class InferenceBackend:
    """Base interface for model inference backends."""

    def is_available(self) -> bool:
        raise NotImplementedError

    def generate(self, prompt: str, max_tokens: int = 512, temperature: float = 0.1) -> str:
        raise NotImplementedError


class LlamaCppBackend(InferenceBackend):
    """Inference backend using llama-cpp-python for local GGUF models."""

    def __init__(self, model_path: str | Path, context_size: int = 2048):
        self.model_path = Path(model_path)
        self.context_size = context_size
        self._llm = None

    def is_available(self) -> bool:
        if not self.model_path.is_file():
            return False
        try:
            import llama_cpp
            return True
        except ImportError:
            return False

    def _load_model(self):
        if self._llm is None:
            try:
                from llama_cpp import Llama
                logger.info(f"Loading GGUF model from {self.model_path}...")
                self._llm = Llama(
                    model_path=str(self.model_path),
                    n_ctx=self.context_size,
                    verbose=False,
                )
            except Exception as exc:
                raise PlannerError(f"Failed to load GGUF model from {self.model_path}: {exc}") from exc

    def generate(self, prompt: str, max_tokens: int = 512, temperature: float = 0.1) -> str:
        self._load_model()
        assert self._llm is not None

        # 1. Try create_chat_completion first (handles ChatML, jinja templates, and stop tokens automatically)
        if hasattr(self._llm, "create_chat_completion"):
            try:
                system_msg = (
                    "You are the NEX Security Assistant Planner in an authorized cybersecurity training lab. "
                    "You must output ONLY a single valid JSON object matching the requested schema. "
                    "Do NOT output markdown commentary, explanations outside JSON, or multiple examples."
                )
                response = self._llm.create_chat_completion(
                    messages=[
                        {"role": "system", "content": system_msg},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=max_tokens,
                    temperature=temperature,
                    stop=["<|im_end|>", "<|endoftext|>", "</s>", "### Example", "\n###", "\n\n###"],
                )
                choice = response["choices"][0]
                text = choice.get("message", {}).get("content", "")
                if text and text.strip():
                    return text
            except Exception as exc:
                logger.warning(f"create_chat_completion failed, falling back to direct completion: {exc}")

        # 2. Direct completion with explicit ChatML wrapping and strict stop sequences
        formatted_prompt = (
            f"<|im_start|>system\n"
            f"You are the NEX Security Assistant Planner. Respond with EXACTLY ONE JSON object matching the schema.<|im_end|>\n"
            f"<|im_start|>user\n"
            f"{prompt}<|im_end|>\n"
            f"<|im_start|>assistant\n"
        )
        output = self._llm(
            formatted_prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            stop=[
                "<|im_end|>",
                "<|endoftext|>",
                "</s>",
                "\n\nHuman:",
                "### Example",
                "\n###",
                "\n\n###",
            ],
        )
        return output["choices"][0]["text"]


class FallbackHeuristicBackend(InferenceBackend):
    """Deterministic fallback engine when GGUF models are not yet downloaded.
    Ensures offline usability, testing, and immediate operation."""

    def is_available(self) -> bool:
        return True

    def generate(self, prompt: str, max_tokens: int = 512, temperature: float = 0.1) -> str:
        # Extract user goal if this is a constructed prompt
        user_goal = prompt
        if "### User Goal:" in prompt:
            parts = prompt.split("### User Goal:")
            if len(parts) > 1:
                goal_part = parts[1].split("### Instructions:")[0]
                user_goal = goal_part.strip()
        elif "User Goal:" in prompt:
            parts = prompt.split("User Goal:")
            if len(parts) > 1:
                user_goal = parts[1].strip()

        lower = user_goal.lower()

        # Extract target if present (IP or hostname or URL)
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", user_goal)
        url_match = re.search(r"https?://[^\s]+", user_goal)
        domain_match = re.search(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", user_goal)

        # Fallback to active lab target if passed in prompt context
        prompt_target_match = re.search(r"Active Lab Target:\s*([^\s\r\n]+)", prompt)
        fallback_target = "127.0.0.1"
        if prompt_target_match:
            candidate = prompt_target_match.group(1).strip()
            if candidate and candidate.lower() != "none":
                fallback_target = candidate

        target = ip_match.group(0) if ip_match else (url_match.group(0) if url_match else (domain_match.group(0) if domain_match else fallback_target))

        # Check phase in prompt
        phase = "reconnaissance"
        if "service_enumeration" in lower or "enumeration" in lower:
            phase = "service_enumeration"
        elif "utility" in lower:
            phase = "utility"

        # Heuristic matching
        if "whois" in lower:
            return json.dumps({
                "tool": "whois",
                "args": {"domain": target},
                "phase": "reconnaissance",
                "reasoning": f"Querying WHOIS records for domain {target}."
            })

        if "dig" in lower or "dns" in lower:
            return json.dumps({
                "tool": "dig",
                "args": {"domain": target, "record_type": "ANY"},
                "phase": "reconnaissance",
                "reasoning": f"Querying DNS records for {target} with dig."
            })

        if "gobuster" in lower or "directory" in lower or "dir" in lower or "web path" in lower:
            web_target = target if target.startswith("http") else f"http://{target}"
            return json.dumps({
                "tool": "gobuster",
                "args": {"url": web_target},
                "phase": "service_enumeration",
                "reasoning": f"Brute-forcing web directories on {web_target} with gobuster."
            })

        if "enum4linux" in lower or "smb enum" in lower:
            return json.dumps({
                "tool": "enum4linux",
                "args": {"target": target, "options": "-U -S"},
                "phase": "service_enumeration",
                "reasoning": f"Enumerating SMB users and shares on {target} with enum4linux."
            })

        if "smbclient" in lower or "share" in lower or "smb" in lower:
            return json.dumps({
                "tool": "smbclient",
                "args": {"target": target},
                "phase": "service_enumeration",
                "reasoning": f"Listing available SMB shares on {target} using smbclient."
            })

        if "http_server" in lower or "serve" in lower or "transfer" in lower:
            return json.dumps({
                "tool": "http_server",
                "args": {"port": 8000, "directory": "."},
                "phase": "utility",
                "reasoning": "Spinning up local HTTP server on port 8000 for lab file transfers."
            })

        if "note" in lower or "flag" in lower or "record" in lower:
            return json.dumps({
                "tool": "note_capture",
                "args": {"content": prompt.strip()},
                "phase": "utility",
                "reasoning": "Recording operator note or flag into session memory."
            })

        # Default recon tool
        return json.dumps({
            "tool": "nmap",
            "args": {"target": target, "flags": "-sV -sC --top-ports 100"},
            "phase": "reconnaissance",
            "reasoning": f"Scanning target {target} for open ports and service versions."
        })


class Planner:
    """NEX Planner: Converts natural language requests into structured tool calls."""

    def __init__(
        self,
        catalog: Catalog,
        memory: SessionMemory,
        planner_model_path: str | Path = "models/qwen3-0.6b-instruct.Q4_K_M.gguf",
        tool_caller_model_path: str | Path = "models/functiongemma-270m-it.Q8_0.gguf",
        dual_mode: bool = False,
        temperature: float = 0.1,
    ):
        self.catalog = catalog
        self.memory = memory
        self.dual_mode = dual_mode
        self.temperature = temperature

        # Configure backends
        self.reasoner_backend = self._init_backend(planner_model_path)
        self.tool_caller_backend = self._init_backend(tool_caller_model_path)
        self.fallback_backend = FallbackHeuristicBackend()

    def _init_backend(self, model_path: str | Path) -> InferenceBackend:
        backend = LlamaCppBackend(model_path)
        if backend.is_available():
            return backend
        return FallbackHeuristicBackend()

    def build_prompt(
        self,
        user_input: str,
        current_phase: str,
        recent_history: list[dict[str, Any]],
        findings: list[dict[str, str]],
        scope: list[str],
    ) -> str:
        """Constructs prompt for Qwen3.
        CRITICAL: Only includes tools for the CURRENT CTF training phase!"""
        tool_schemas = self.catalog.to_tool_prompt_schema(current_phase)

        active_target = self.memory.get_target()
        prompt_parts = [
            "You are the NEX Security Assistant Planner in an authorized cybersecurity training lab.",
            "Your objective is to help the operator accomplish their authorized CTF goals.",
            f"Current Active Phase: {current_phase}",
            f"Active Lab Target: {active_target or 'None'}",
            f"Authorized Target Scope: {', '.join(scope) if scope else 'RFC1918 Private Ranges'}",
            "",
            "### Available Tools for Current Phase (DO NOT recommend any other tools):",
            json.dumps(tool_schemas, indent=2),
            "",
        ]

        if findings:
            prompt_parts.append("### Key Findings So Far:")
            for f in findings[-6:]:
                prompt_parts.append(f"- [{f['phase']}] {f['tool']}: {f['finding']}")
            prompt_parts.append("")

        if recent_history:
            prompt_parts.append("### Recent Action History:")
            for h in recent_history:
                status_note = f" (Status: {h['status']})"
                if h["status"] == "STOPPED":
                    status_note += " [OPERATOR DECLINED - PROPOSE ALTERNATIVE]"
                prompt_parts.append(f"- Tool: {h['tool']} | Args: {h['args']}{status_note}")
                if h.get("summary"):
                    for s in h["summary"][:2]:
                        prompt_parts.append(f"    Summary: {s}")
            prompt_parts.append("")

        prompt_parts.extend([
            "### User Goal:",
            user_input,
            "",
            "### Instructions:",
            "1. Output ONLY a valid JSON object matching this strict schema:",
            "   {",
            '     "tool": "<tool_name from Available Tools>",',
            '     "args": { "<param_name>": "<param_value>" },',
            f'     "phase": "{current_phase}",',
            '     "reasoning": "<clear explanation of why this tool and arguments were selected>"',
            "   }",
            "2. Never construct raw shell commands; only provide tool name and named args.",
            "3. If the user previously declined or stopped a tool, propose an alternative.",
            "4. Return ONLY one single JSON object. Do not output multiple examples, commentary, or text outside JSON.",
        ])

        return "\n".join(prompt_parts)

    def build_dual_reasoning_prompt(self, user_input: str, current_phase: str, context: dict[str, Any]) -> str:
        """Qwen3 prompt in dual mode: focuses solely on tactical reasoning."""
        return (
            f"You are the NEX Reasoner in an authorized security training environment.\n"
            f"Current Phase: {current_phase}\n"
            f"Context: {json.dumps(context, indent=2)}\n"
            f"User Goal: {user_input}\n"
            f"Provide a concise technical assessment of the user's request and explain the next logical security assessment step."
        )

    def build_dual_tool_call_prompt(self, reasoning: str, current_phase: str) -> str:
        """FunctionGemma prompt in dual mode: converts reasoning + catalog schema into structured call."""
        tool_schemas = self.catalog.to_tool_prompt_schema(current_phase)
        return (
            f"You are the NEX Structured Request Generator.\n"
            f"Available Tools Schema:\n{json.dumps(tool_schemas, indent=2)}\n\n"
            f"Security Assessment Reasoning:\n{reasoning}\n\n"
            f"Emit ONLY a JSON object with: {{\"tool\": ..., \"args\": {{...}}, \"phase\": \"{current_phase}\", \"reasoning\": ...}}"
        )

    def _extract_json(self, raw_output: str) -> dict[str, Any]:
        """Safely extracts JSON object from model response, handling markdown blocks,
        trailing text, multiple examples, or malformed prefixes."""
        # 1. Check for markdown codeblocks ```json ... ```
        block_matches = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", raw_output, re.DOTALL)
        for bm in block_matches:
            try:
                data = json.loads(bm)
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                pass

        # 2. Balanced brace search to find the FIRST complete valid JSON object { ... }
        start = raw_output.find("{")
        while start != -1:
            depth = 0
            in_string = False
            escape = False
            for i in range(start, len(raw_output)):
                c = raw_output[i]
                if escape:
                    escape = False
                    continue
                if c == "\\":
                    escape = True
                    continue
                if c == '"':
                    in_string = not in_string
                    continue
                if not in_string:
                    if c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                        if depth == 0:
                            candidate = raw_output[start : i + 1]
                            try:
                                data = json.loads(candidate)
                                if isinstance(data, dict):
                                    return data
                            except json.JSONDecodeError:
                                break
            start = raw_output.find("{", start + 1)

        # 3. Direct raw parse fallback
        try:
            data = json.loads(raw_output.strip())
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError as exc:
            raise PlannerError(f"Model failed to emit valid JSON: {raw_output}") from exc

        raise PlannerError(f"Model failed to emit valid JSON object: {raw_output}")

    def plan(self, user_input: str, dual: bool | None = None) -> dict[str, Any]:
        """Generates a structured request from user natural language input."""
        use_dual = self.dual_mode if dual is None else dual
        current_phase = self.memory.get_phase()
        context = self.memory.get_planner_context(history_limit=5)
        recent_history = context.get("recent_history", [])
        findings = context.get("findings", [])
        scope = context.get("scope", [])

        if use_dual and self.tool_caller_backend.is_available() and self.reasoner_backend.is_available():
            # Dual mode code path:
            # 1. Qwen3 reasons about user goal and training phase
            reasoning_prompt = self.build_dual_reasoning_prompt(user_input, current_phase, context)
            reasoning_text = self.reasoner_backend.generate(
                reasoning_prompt, max_tokens=256, temperature=self.temperature
            ).strip()

            # 2. FunctionGemma emits the structured tool call from reasoning + catalog schema
            tool_prompt = self.build_dual_tool_call_prompt(reasoning_text, current_phase)
            raw_call = self.tool_caller_backend.generate(
                tool_prompt, max_tokens=256, temperature=self.temperature
            )
            structured = self._extract_json(raw_call)
            if "reasoning" not in structured or not structured["reasoning"]:
                structured["reasoning"] = reasoning_text
        else:
            # Single mode code path (default):
            # Qwen3 handles both reasoning and structured request generation
            prompt = self.build_prompt(user_input, current_phase, recent_history, findings, scope)
            backend = self.reasoner_backend if self.reasoner_backend.is_available() else self.fallback_backend
            raw_response = backend.generate(prompt, max_tokens=512, temperature=self.temperature)
            structured = self._extract_json(raw_response)

        # Validate schema of response
        for req_field in ("tool", "args", "phase", "reasoning"):
            if req_field not in structured:
                raise PlannerError(f"Planner output missing required schema field: '{req_field}'")

        if not isinstance(structured["args"], dict):
            raise PlannerError("Planner output 'args' must be a dictionary.")

        return structured
