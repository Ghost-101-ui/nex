from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from nex.catalog import Catalog
from nex.cli import NexREPL
from nex.controller import Controller
from nex.memory import SessionMemory
from nex.planner import Planner
from nex.tool_checker import check_all_tools, check_tool, print_tools_checkup


class TestToolChecker(unittest.TestCase):
    def setUp(self):
        catalog_path = Path(__file__).resolve().parents[1] / "catalog.yaml"
        self.catalog = Catalog.from_yaml_file(catalog_path)
        self.memory = SessionMemory(db_path=":memory:")
        self.planner = Planner(catalog=self.catalog, memory=self.memory)
        self.controller = Controller(catalog=self.catalog, memory=self.memory)
        self.repl = NexREPL(
            catalog=self.catalog,
            memory=self.memory,
            planner=self.planner,
            controller=self.controller,
        )

    def tearDown(self):
        self.memory.close()

    def test_check_all_tools_returns_results_for_every_tool(self):
        results = check_all_tools(self.catalog)
        self.assertEqual(len(results), len(self.catalog.tools))

        tool_names = {r.name for r in results}
        self.assertIn("nmap", tool_names)
        self.assertIn("sqlmap", tool_names)
        self.assertIn("note_capture", tool_names)

    def test_internal_tools_detected_as_builtin(self):
        note_tool = self.catalog.get_tool("note_capture")
        self.assertIsNotNone(note_tool)
        res = check_tool(note_tool)
        self.assertTrue(res.installed)
        self.assertIn("built-in", res.path)

    def test_shutil_which_mocking(self):
        nmap_tool = self.catalog.get_tool("nmap")
        self.assertIsNotNone(nmap_tool)

        # Mock found
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            res = check_tool(nmap_tool)
            self.assertTrue(res.installed)
            self.assertEqual(res.path, "/usr/bin/nmap")

        # Mock missing
        with patch("shutil.which", return_value=None):
            res = check_tool(nmap_tool)
            self.assertFalse(res.installed)
            self.assertIsNone(res.path)
            self.assertIn("apt install", res.hint)

    def test_print_tools_checkup_summary(self):
        summary = print_tools_checkup(self.catalog)
        self.assertEqual(summary["total"], len(self.catalog.tools))
        self.assertIsInstance(summary["installed"], int)
        self.assertIsInstance(summary["missing"], list)

    def test_slash_check_command_in_repl(self):
        with patch("nex.cli.print_tools_checkup") as mock_check:
            self.repl.handle_slash_command("/check")
            self.assertTrue(mock_check.called)

        with patch("nex.cli.print_tools_checkup") as mock_doctor:
            self.repl.handle_slash_command("/doctor")
            self.assertTrue(mock_doctor.called)

        with patch("nex.cli.print_tools_checkup") as mock_tools_check:
            self.repl.handle_slash_command("/tools check")
            self.assertTrue(mock_tools_check.called)
