from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class HistoryEntry:
    id: int
    timestamp: str
    tool: str
    args: dict[str, Any]
    phase: str
    reasoning: str
    approval_tier: str
    status: str  # EXECUTED, STOPPED, FAILED, TIMEOUT
    exit_code: int | None
    duration_sec: float | None
    summary: list[str]
    raw_output: str


@dataclass
class FindingEntry:
    id: int
    timestamp: str
    tool: str
    phase: str
    category: str
    finding: str


class SessionMemory:
    """SQLite-backed persistent or ephemeral session memory for NEX."""

    def __init__(self, db_path: str | Path = ":memory:", artifacts_dir: str | Path = ".nex/raw"):
        self.db_path = str(db_path)
        self.is_ephemeral = self.db_path == ":memory:"
        self.artifacts_dir = Path(artifacts_dir)
        if not self.is_ephemeral:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> SessionMemory:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _init_db(self) -> None:
        assert self._conn is not None
        with self._conn:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS session_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS scope_targets (
                    target TEXT PRIMARY KEY,
                    added_at TEXT NOT NULL,
                    is_authorized INTEGER NOT NULL DEFAULT 1
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS request_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    args_json TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    reasoning TEXT NOT NULL,
                    approval_tier TEXT NOT NULL,
                    status TEXT NOT NULL,
                    exit_code INTEGER,
                    duration_sec REAL,
                    summary_json TEXT NOT NULL,
                    raw_output TEXT NOT NULL,
                    artifact_file TEXT
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    category TEXT NOT NULL,
                    finding TEXT NOT NULL
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    content TEXT NOT NULL
                )
            """)
            # Initialize default phase if not present
            row = self._conn.execute("SELECT value FROM session_metadata WHERE key = 'phase'").fetchone()
            if not row:
                self._conn.execute(
                    "INSERT INTO session_metadata (key, value) VALUES ('phase', 'reconnaissance')"
                )
            row_cr = self._conn.execute("SELECT value FROM session_metadata WHERE key = 'created_at'").fetchone()
            if not row_cr:
                self._conn.execute(
                    "INSERT INTO session_metadata (key, value) VALUES ('created_at', ?)",
                    (datetime.now(timezone.utc).isoformat(),),
                )

    # ---------------- Metadata / Phase ----------------
    def get_phase(self) -> str:
        assert self._conn is not None
        row = self._conn.execute("SELECT value FROM session_metadata WHERE key = 'phase'").fetchone()
        return row["value"] if row else "reconnaissance"

    def set_phase(self, phase: str) -> None:
        assert self._conn is not None
        with self._conn:
            self._conn.execute(
                "INSERT INTO session_metadata (key, value) VALUES ('phase', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (phase,),
            )

    def get_objective(self) -> str | None:
        assert self._conn is not None
        row = self._conn.execute("SELECT value FROM session_metadata WHERE key = 'objective'").fetchone()
        return row["value"] if row else None

    def set_objective(self, objective: str) -> None:
        assert self._conn is not None
        with self._conn:
            self._conn.execute(
                "INSERT INTO session_metadata (key, value) VALUES ('objective', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (objective,),
            )

    def get_target(self) -> str | None:
        assert self._conn is not None
        row = self._conn.execute("SELECT value FROM session_metadata WHERE key = 'target'").fetchone()
        return row["value"] if row and row["value"] else None

    def set_target(self, target: str | None) -> None:
        assert self._conn is not None
        with self._conn:
            if target and target.strip():
                self._conn.execute(
                    "INSERT INTO session_metadata (key, value) VALUES ('target', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (target.strip(),),
                )
            else:
                self._conn.execute("DELETE FROM session_metadata WHERE key = 'target'")

    # ---------------- Scope ----------------
    def add_scope(self, target: str, is_authorized: bool = True) -> None:
        target = target.strip()
        if not target:
            return
        assert self._conn is not None
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO scope_targets (target, added_at, is_authorized) VALUES (?, ?, ?)",
                (target, datetime.now(timezone.utc).isoformat(), 1 if is_authorized else 0),
            )

    def get_scope(self) -> list[str]:
        assert self._conn is not None
        rows = self._conn.execute(
            "SELECT target FROM scope_targets WHERE is_authorized = 1 ORDER BY added_at ASC"
        ).fetchall()
        return [row["target"] for row in rows]

    # ---------------- History / Requests ----------------
    def record_request(
        self,
        tool: str,
        args: dict[str, Any],
        phase: str,
        reasoning: str,
        approval_tier: str,
        status: str,
        exit_code: int | None = None,
        duration_sec: float | None = None,
        summary: list[str] | None = None,
        raw_output: str = "",
    ) -> int:
        now = datetime.now(timezone.utc).isoformat()
        summary_list = summary or []
        artifact_path = ""

        if raw_output:
            try:
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                filename = f"{stamp}-{tool}.txt"
                file_target = self.artifacts_dir / filename
                file_target.write_text(raw_output, encoding="utf-8", errors="replace")
                artifact_path = str(file_target)
            except Exception:
                pass

        assert self._conn is not None
        with self._conn:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                INSERT INTO request_history (
                    timestamp, tool, args_json, phase, reasoning, approval_tier,
                    status, exit_code, duration_sec, summary_json, raw_output, artifact_file
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    tool,
                    json.dumps(args),
                    phase,
                    reasoning,
                    approval_tier,
                    status,
                    exit_code,
                    duration_sec,
                    json.dumps(summary_list),
                    raw_output,
                    artifact_path,
                ),
            )
            return cursor.lastrowid

    def record_stop(
        self,
        tool: str,
        args: dict[str, Any],
        phase: str,
        reasoning: str,
        approval_tier: str = "APPROVAL",
    ) -> int:
        """Records a tool invocation proposal that was stopped/declined by the human operator."""
        return self.record_request(
            tool=tool,
            args=args,
            phase=phase,
            reasoning=f"Operator STOPPED action. Original reasoning: {reasoning}",
            approval_tier=approval_tier,
            status="STOPPED",
            exit_code=None,
            duration_sec=0.0,
            summary=["Operator declined execution at confirmation gate."],
            raw_output="Action declined by operator.",
        )

    def get_recent_history(self, limit: int = 5) -> list[dict[str, Any]]:
        """Returns recent interactions formatted for Planner prompt context inclusion."""
        assert self._conn is not None
        rows = self._conn.execute(
            """
            SELECT id, timestamp, tool, args_json, phase, reasoning, approval_tier,
                   status, exit_code, summary_json
            FROM request_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        history = []
        for r in reversed(rows):
            history.append({
                "id": r["id"],
                "tool": r["tool"],
                "args": json.loads(r["args_json"]),
                "phase": r["phase"],
                "reasoning": r["reasoning"],
                "approval_tier": r["approval_tier"],
                "status": r["status"],
                "exit_code": r["exit_code"],
                "summary": json.loads(r["summary_json"]),
            })
        return history

    def get_last_raw_output(self) -> str | None:
        """Retrieves raw output of the most recent executed tool call."""
        assert self._conn is not None
        row = self._conn.execute(
            """
            SELECT raw_output FROM request_history
            WHERE status IN ('EXECUTED', 'FAILED', 'TIMEOUT')
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
        return row["raw_output"] if row else None

    # ---------------- Findings ----------------
    def record_finding(self, tool: str, phase: str, category: str, finding: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        assert self._conn is not None
        with self._conn:
            row = self._conn.execute(
                "SELECT id FROM findings WHERE tool = ? AND category = ? AND finding = ?",
                (tool, category, finding),
            ).fetchone()
            if not row:
                self._conn.execute(
                    "INSERT INTO findings (timestamp, tool, phase, category, finding) VALUES (?, ?, ?, ?, ?)",
                    (now, tool, phase, category, finding),
                )

    def get_findings(self) -> list[dict[str, str]]:
        assert self._conn is not None
        rows = self._conn.execute(
            "SELECT tool, phase, category, finding FROM findings ORDER BY id ASC"
        ).fetchall()
        return [
            {
                "tool": r["tool"],
                "phase": r["phase"],
                "category": r["category"],
                "finding": r["finding"],
            }
            for r in rows
        ]

    # ---------------- Notes ----------------
    def record_note(self, content: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        assert self._conn is not None
        with self._conn:
            self._conn.execute("INSERT INTO notes (timestamp, content) VALUES (?, ?)", (now, content))

    def get_notes(self) -> list[dict[str, str]]:
        assert self._conn is not None
        rows = self._conn.execute("SELECT timestamp, content FROM notes ORDER BY id ASC").fetchall()
        return [{"timestamp": r["timestamp"], "content": r["content"]} for r in rows]

    # ---------------- Context Query Interface for Planner ----------------
    def get_planner_context(self, history_limit: int = 5) -> dict[str, Any]:
        """Provides a concise, capped representation of session context for the Planner."""
        return {
            "current_phase": self.get_phase(),
            "objective": self.get_objective() or "General authorized CTF training discovery",
            "scope": self.get_scope(),
            "findings": self.get_findings(),
            "recent_history": self.get_recent_history(limit=history_limit),
        }
