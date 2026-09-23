from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from nex.catalog import Catalog, ToolDefinition, ParameterDefinition
from nex.controller import Controller, ControllerError
from nex.memory import SessionMemory


class TestControllerGate(unittest.TestCase):
    def setUp(self):
        # Setup in-memory SQLite session
        self.memory = SessionMemory(db_path=":memory:")
        self.memory.add_scope("10.10.10.0/24")
        self.memory.add_scope("lab.local")
        self.memory.set_phase("reconnaissance")

        import sys
        # Create a test catalog with both AUTO and APPROVAL tools
        tools = {
            "safe_tool": ToolDefinition(
                name="safe_tool",
                phase="reconnaissance",
                approval_tier="AUTO",
                description="Safe discovery tool",
                command_template=[sys.executable, "-c", "import sys; print(sys.argv[1])", "{target}"],
                parser="fallback_parser",
                parameters={
                    "target": ParameterDefinition("target", "string", required=True),
                },
            ),
            "approval_tool": ToolDefinition(
                name="approval_tool",
                phase="reconnaissance",
                approval_tier="APPROVAL",
                description="High-impact tool requiring human operator approval",
                command_template=[sys.executable, "-c", "import sys; print('IMPACT', sys.argv[1])", "{target}"],
                parser="fallback_parser",
                parameters={
                    "target": ParameterDefinition("target", "string", required=True),
                },
            ),
            "enum_tool": ToolDefinition(
                name="enum_tool",
                phase="service_enumeration",
                approval_tier="AUTO",
                description="Tool for enumeration phase only",
                command_template=[sys.executable, "-c", "import sys; print(sys.argv[1])", "{target}"],
                parser="fallback_parser",
                parameters={
                    "target": ParameterDefinition("target", "string", required=True),
                },
            ),
        }
        self.catalog = Catalog(tools=tools, phases=["reconnaissance", "service_enumeration", "utility"])

    def tearDown(self):
        self.memory.close()

    def test_auto_tier_executes_without_confirmation(self):
        """AUTO tier executes immediately without invoking confirmation callback."""
        mock_confirm = MagicMock(return_value=True)
        controller = Controller(
            catalog=self.catalog,
            memory=self.memory,
            confirm_callback=mock_confirm,
        )

        res = controller.execute_request("safe_tool", {"target": "10.10.10.5"}, reasoning="Recon")
        # Confirmation callback MUST NOT be called for AUTO tier
        mock_confirm.assert_not_called()
        self.assertEqual(res.status, "EXECUTED")
        self.assertEqual(res.approval_tier, "AUTO")
        self.assertIn("10.10.10.5", res.raw_output)

        # Check memory recorded execution
        history = self.memory.get_recent_history(limit=1)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["status"], "EXECUTED")

    def test_approval_tier_proceed_executes(self):
        """APPROVAL tier calls confirmation callback; executes if operator proceeds."""
        mock_confirm = MagicMock(return_value=True)
        controller = Controller(
            catalog=self.catalog,
            memory=self.memory,
            confirm_callback=mock_confirm,
        )

        res = controller.execute_request(
            "approval_tool", {"target": "10.10.10.5"}, reasoning="Need manual confirmation"
        )
        mock_confirm.assert_called_once()
        self.assertEqual(res.status, "EXECUTED")
        self.assertEqual(res.approval_tier, "APPROVAL")

    def test_approval_tier_stop_blocks_execution(self):
        """APPROVAL tier blocks execution if operator stops; logs rejection to memory."""
        mock_confirm = MagicMock(return_value=False)  # Operator says 'stop'
        controller = Controller(
            catalog=self.catalog,
            memory=self.memory,
            confirm_callback=mock_confirm,
        )

        res = controller.execute_request(
            "approval_tool", {"target": "10.10.10.5"}, reasoning="Exploration"
        )
        mock_confirm.assert_called_once()
        self.assertEqual(res.status, "STOPPED")
        self.assertIsNone(res.exit_code)

        # Verify stopped decision is logged in memory for the Planner
        history = self.memory.get_recent_history(limit=1)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["status"], "STOPPED")
        self.assertIn("STOPPED", history[0]["reasoning"])

    def test_missing_required_arguments_rejected(self):
        """Controller rejects requests missing required parameters."""
        controller = Controller(catalog=self.catalog, memory=self.memory)
        with self.assertRaises(ControllerError) as ctx:
            controller.execute_request("safe_tool", {})  # Missing 'target'
        self.assertIn("Missing required parameter", str(ctx.exception))

    def test_out_of_scope_target_rejected(self):
        """Controller gate blocks out-of-scope targets before execution."""
        controller = Controller(catalog=self.catalog, memory=self.memory)
        with self.assertRaises(ControllerError) as ctx:
            controller.execute_request("safe_tool", {"target": "8.8.8.8"})
        self.assertIn("outside the authorized lab scope", str(ctx.exception))

    def test_phase_mismatch_rejected(self):
        """Controller gate rejects tools that don't match the current phase."""
        controller = Controller(catalog=self.catalog, memory=self.memory)
        # Current phase is 'reconnaissance', tool is 'service_enumeration'
        with self.assertRaises(ControllerError) as ctx:
            controller.execute_request("enum_tool", {"target": "10.10.10.5"})
        self.assertIn("current active phase is 'reconnaissance'", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
