from __future__ import annotations

import unittest
from pathlib import Path

from nex.catalog import Catalog, CatalogValidationError


class TestCatalogSchema(unittest.TestCase):
    def setUp(self):
        self.catalog_path = Path(__file__).resolve().parents[1] / "catalog.yaml"

    def test_load_real_catalog(self):
        """Verify the shipped catalog.yaml parses and satisfies schema."""
        catalog = Catalog.from_yaml_file(self.catalog_path)
        self.assertGreater(len(catalog.tools), 0)
        self.assertIn("reconnaissance", catalog.phases)
        self.assertIn("service_enumeration", catalog.phases)
        self.assertIn("vulnerability_assessment", catalog.phases)
        self.assertIn("post_engagement_review", catalog.phases)
        self.assertIn("utility", catalog.phases)

        # Check Step 1 tools exist
        self.assertIsNotNone(catalog.get_tool("nmap"))
        self.assertIsNotNone(catalog.get_tool("whois"))
        self.assertIsNotNone(catalog.get_tool("dig"))
        self.assertIsNotNone(catalog.get_tool("gobuster"))
        self.assertIsNotNone(catalog.get_tool("enum4linux"))
        self.assertIsNotNone(catalog.get_tool("smbclient"))
        self.assertIsNotNone(catalog.get_tool("http_server"))
        self.assertIsNotNone(catalog.get_tool("note_capture"))

    def test_phase_filtering(self):
        """Ensure get_tools_for_phase only returns tools in that phase (+ utility)."""
        catalog = Catalog.from_yaml_file(self.catalog_path)
        recon_tools = catalog.get_tools_for_phase("reconnaissance", include_utility=False)
        recon_names = {t.name for t in recon_tools}
        self.assertIn("nmap", recon_names)
        self.assertIn("whois", recon_names)
        self.assertIn("dig", recon_names)
        self.assertNotIn("gobuster", recon_names)

        # Schema generator for Planner prompt
        prompt_schema = catalog.to_tool_prompt_schema("reconnaissance", include_utility=True)
        schema_names = {t["name"] for t in prompt_schema}
        self.assertIn("nmap", schema_names)
        self.assertIn("note_capture", schema_names)
        self.assertNotIn("gobuster", schema_names)

    def test_missing_required_fields_fails(self):
        """Fail fast if a tool entry misses required schema fields."""
        bad_data = {
            "version": "1.0",
            "phases": ["reconnaissance"],
            "tools": [
                {
                    "name": "broken_tool",
                    # missing phase, approval_tier, description, etc.
                }
            ],
        }
        with self.assertRaises(CatalogValidationError):
            Catalog.from_dict(bad_data)

    def test_invalid_phase_fails(self):
        """Fail fast on unrecognized CTF phase."""
        bad_data = {
            "version": "1.0",
            "phases": ["invalid_phase_name"],
            "tools": [],
        }
        with self.assertRaises(CatalogValidationError):
            Catalog.from_dict(bad_data)

    def test_invalid_approval_tier_fails(self):
        """Fail fast on invalid approval tier."""
        bad_data = {
            "version": "1.0",
            "phases": ["reconnaissance"],
            "tools": [
                {
                    "name": "test_tool",
                    "phase": "reconnaissance",
                    "approval_tier": "SUPER_SAFE",  # invalid
                    "description": "test",
                    "command_template": ["echo"],
                    "parser": "parse_nmap",
                }
            ],
        }
        with self.assertRaises(CatalogValidationError):
            Catalog.from_dict(bad_data)


if __name__ == "__main__":
    unittest.main()
