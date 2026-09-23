from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from nex.catalog import Catalog
from nex.cli import NexREPL
from nex.controller import Controller
from nex.memory import SessionMemory
from nex.planner import Planner


class TestCliSlashCommands(unittest.TestCase):
    def setUp(self):
        self.memory = SessionMemory(db_path=":memory:")
        self.catalog = Catalog(tools={}, phases=["reconnaissance", "service_enumeration"])
        self.planner = MagicMock(spec=Planner)
        self.controller = MagicMock(spec=Controller)
        self.repl = NexREPL(
            catalog=self.catalog,
            memory=self.memory,
            planner=self.planner,
            controller=self.controller,
        )

    def tearDown(self):
        self.memory.close()

    def test_target_command_and_shortcut(self):
        # 1. Initially no target
        self.assertIsNone(self.memory.get_target())

        # 2. Set target via /target
        self.repl.handle_slash_command("/target 10.10.10.5")
        self.assertEqual(self.memory.get_target(), "10.10.10.5")
        self.assertIn("10.10.10.5", self.memory.get_scope())

        # 3. Change target via /t shortcut
        self.repl.handle_slash_command("/t 192.168.1.100")
        self.assertEqual(self.memory.get_target(), "192.168.1.100")
        self.assertIn("192.168.1.100", self.memory.get_scope())

        # 4. View target without arguments
        self.repl.handle_slash_command("/target")
        self.repl.handle_slash_command("/t")

        # 5. Clear target
        self.repl.handle_slash_command("/t clear")
        self.assertIsNone(self.memory.get_target())

    def test_target_fallback_in_planner(self):
        # When active target is set, FallbackHeuristicBackend uses it
        from nex.planner import FallbackHeuristicBackend
        backend = FallbackHeuristicBackend()
        prompt = (
            "Current Active Phase: reconnaissance\n"
            "Active Lab Target: 10.10.10.75\n"
            "### User Goal:\n"
            "run nmap scan\n"
        )
        output = backend.generate(prompt)
        import json
        data = json.loads(output)
        self.assertEqual(data["tool"], "nmap")
        self.assertEqual(data["args"]["target"], "10.10.10.75")

    def test_phase_numbers_and_shortcuts(self):
        catalog_phases = [
            "reconnaissance",
            "service_enumeration",
            "vulnerability_assessment",
            "post_engagement_review",
            "utility",
        ]
        self.repl.catalog.phases = catalog_phases

        # Initially reconnaissance
        self.assertEqual(self.memory.get_phase(), "reconnaissance")

        # Switch with /phase 2
        self.repl.handle_slash_command("/phase 2")
        self.assertEqual(self.memory.get_phase(), "service_enumeration")

        # Switch with /phase 3
        self.repl.handle_slash_command("/phase 3")
        self.assertEqual(self.memory.get_phase(), "vulnerability_assessment")

        # Switch with /p 4
        self.repl.handle_slash_command("/p 4")
        self.assertEqual(self.memory.get_phase(), "post_engagement_review")

        # Switch with /p 1
        self.repl.handle_slash_command("/p 1")
        self.assertEqual(self.memory.get_phase(), "reconnaissance")

        # Switch with /p next
        self.repl.handle_slash_command("/p next")
        self.assertEqual(self.memory.get_phase(), "service_enumeration")

        # Switch with short alias
        self.repl.handle_slash_command("/p vuln")
        self.assertEqual(self.memory.get_phase(), "vulnerability_assessment")

        # Run without arguments
        self.repl.handle_slash_command("/phase")
        self.repl.handle_slash_command("/p")

        # Invalid phase number does not crash
        self.repl.handle_slash_command("/p 99")
        self.assertEqual(self.memory.get_phase(), "vulnerability_assessment")
