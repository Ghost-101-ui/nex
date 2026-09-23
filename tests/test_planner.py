from __future__ import annotations

import unittest
from pathlib import Path

from nex.catalog import Catalog
from nex.memory import SessionMemory
from nex.planner import Planner, PlannerError


class TestPlanner(unittest.TestCase):
    def setUp(self):
        catalog_path = Path(__file__).resolve().parents[1] / "catalog.yaml"
        self.catalog = Catalog.from_yaml_file(catalog_path)
        self.memory = SessionMemory(db_path=":memory:")
        self.memory.add_scope("10.10.10.0/24")
        self.memory.set_phase("reconnaissance")
        self.planner = Planner(catalog=self.catalog, memory=self.memory)

    def tearDown(self):
        self.memory.close()

    def test_prompt_construction_filters_to_current_phase_only(self):
        """Planner prompt MUST only include tools for the active phase (+ utility)."""
        prompt = self.planner.build_prompt(
            user_input="Scan target 10.10.10.5",
            current_phase="reconnaissance",
            recent_history=[],
            findings=[],
            scope=["10.10.10.0/24"],
        )

        # In reconnaissance phase:
        self.assertIn("nmap", prompt)
        self.assertIn("whois", prompt)
        self.assertIn("dig", prompt)
        self.assertIn("note_capture", prompt)  # utility is included

        # Enumeration tools must NOT be presented in the recon prompt!
        self.assertNotIn('"name": "gobuster"', prompt)
        self.assertNotIn('"name": "enum4linux"', prompt)
        self.assertNotIn('"name": "smbclient"', prompt)

    def test_prompt_construction_service_enumeration_phase(self):
        """When in service_enumeration phase, gobuster and smbclient appear, not nmap."""
        prompt = self.planner.build_prompt(
            user_input="Enumerate directories",
            current_phase="service_enumeration",
            recent_history=[],
            findings=[],
            scope=["10.10.10.0/24"],
        )
        self.assertIn("gobuster", prompt)
        self.assertIn("enum4linux", prompt)
        self.assertIn("smbclient", prompt)
        self.assertNotIn('"name": "nmap"', prompt)

    def test_plan_heuristic_fallback(self):
        """Verify fallback engine generates valid structured JSON request."""
        req = self.planner.plan("Scan 10.10.10.5 for open ports")
        self.assertEqual(req["tool"], "nmap")
        self.assertIn("target", req["args"])
        self.assertEqual(req["args"]["target"], "10.10.10.5")
        self.assertEqual(req["phase"], "reconnaissance")
        self.assertTrue(len(req["reasoning"]) > 0)

    def test_extract_json_validates_required_fields(self):
        """Planner validates that extracted JSON contains tool, args, phase, reasoning."""
        valid_json = '{"tool": "nmap", "args": {"target": "10.10.10.5"}, "phase": "reconnaissance", "reasoning": "Test"}'
        parsed = self.planner._extract_json(valid_json)
        self.assertEqual(parsed["tool"], "nmap")

        invalid_json = 'Not JSON at all'
        with self.assertRaises(PlannerError):
            self.planner._extract_json(invalid_json)


if __name__ == "__main__":
    unittest.main()
