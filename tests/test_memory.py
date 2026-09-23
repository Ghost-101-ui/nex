from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from nex.memory import SessionMemory


class TestSessionMemory(unittest.TestCase):
    def test_sqlite_persistence_round_trip(self):
        """Verify that SessionMemory persists state across connections to a local SQLite file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = Path(tmpdir) / "test_session.db"
            artifacts_dir = Path(tmpdir) / "raw"

            # 1. First session
            mem1 = SessionMemory(db_path=db_file, artifacts_dir=artifacts_dir)
            try:
                mem1.set_phase("service_enumeration")
                mem1.set_objective("Enumerate lab VM 10.10.10.5")
                mem1.add_scope("10.10.10.0/24")
                mem1.record_note("Found potential SMB port")
                mem1.record_finding("nmap", "reconnaissance", "open_port", "445/tcp (microsoft-ds)")

                mem1.record_request(
                    tool="nmap",
                    args={"target": "10.10.10.5"},
                    phase="reconnaissance",
                    reasoning="Initial port scan",
                    approval_tier="AUTO",
                    status="EXECUTED",
                    exit_code=0,
                    duration_sec=2.5,
                    summary=["Discovered 445/tcp open"],
                    raw_output="Nmap output for 10.10.10.5...",
                )

                mem1.record_stop(
                    tool="hydra",
                    args={"target": "10.10.10.5"},
                    phase="service_enumeration",
                    reasoning="Testing passwords",
                )
            finally:
                mem1.close()

            # 2. Simulate terminal restart: reconnect to the same SQLite file
            mem2 = SessionMemory(db_path=db_file, artifacts_dir=artifacts_dir)
            try:
                self.assertEqual(mem2.get_phase(), "service_enumeration")
                self.assertEqual(mem2.get_objective(), "Enumerate lab VM 10.10.10.5")
                self.assertIn("10.10.10.0/24", mem2.get_scope())

                # Check findings
                findings = mem2.get_findings()
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["category"], "open_port")
                self.assertEqual(findings[0]["finding"], "445/tcp (microsoft-ds)")

                # Check notes
                notes = mem2.get_notes()
                self.assertEqual(len(notes), 1)
                self.assertIn("Found potential SMB port", notes[0]["content"])

                # Check history
                history = mem2.get_recent_history(limit=5)
                self.assertEqual(len(history), 2)
                self.assertEqual(history[0]["status"], "EXECUTED")
                self.assertEqual(history[1]["status"], "STOPPED")

                # Check last raw output for /f command
                last_raw = mem2.get_last_raw_output()
                self.assertIsNotNone(last_raw)
                self.assertIn("Nmap output for 10.10.10.5", last_raw)
            finally:
                mem2.close()

    def test_ephemeral_in_memory_mode(self):
        """Verify that pure in-memory mode works without writing to disk."""
        mem = SessionMemory(db_path=":memory:")
        try:
            mem.set_phase("reconnaissance")
            mem.add_scope("192.168.1.0/24")
            self.assertEqual(mem.get_phase(), "reconnaissance")
            self.assertIn("192.168.1.0/24", mem.get_scope())
        finally:
            mem.close()

    def test_planner_context_cap(self):
        """Verify that get_planner_context caps history to avoid prompt overflow."""
        mem = SessionMemory(db_path=":memory:")
        try:
            for i in range(10):
                mem.record_request(
                    tool="nmap",
                    args={"target": f"10.0.0.{i}"},
                    phase="reconnaissance",
                    reasoning=f"Step {i}",
                    approval_tier="AUTO",
                    status="EXECUTED",
                    exit_code=0,
                    duration_sec=1.0,
                    summary=[f"Done {i}"],
                    raw_output=f"Output {i}",
                )

            context = mem.get_planner_context(history_limit=4)
            self.assertEqual(len(context["recent_history"]), 4)
        finally:
            mem.close()

    def test_target_persistence_and_clearing(self):
        """Verify setting, getting, and clearing active lab target."""
        mem = SessionMemory(db_path=":memory:")
        try:
            self.assertIsNone(mem.get_target())
            mem.set_target("10.10.10.15")
            self.assertEqual(mem.get_target(), "10.10.10.15")
            mem.set_target("10.10.10.20")
            self.assertEqual(mem.get_target(), "10.10.10.20")
            mem.set_target(None)
            self.assertIsNone(mem.get_target())
        finally:
            mem.close()


if __name__ == "__main__":
    unittest.main()
