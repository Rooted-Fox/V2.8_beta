"""Holds raw scanner findings before AI triage happens.

This is the queue that sits between "scan finished" and "approved for AI
review" - it exists specifically so running a scan never requires an
Anthropic API key. Findings sit here until someone explicitly approves
triage for that app from the dashboard.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Iterator, List, Optional

from config import settings
from models import RawFinding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    url TEXT,
    app_name TEXT NOT NULL,
    raw_severity TEXT,
    description TEXT,
    evidence TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class PendingFindingsStore:
    def __init__(self, db_path=None):
        self.db_path = str(db_path or settings.db_path)
        with self._connect() as conn:
            conn.execute(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def save_many(self, findings: List[RawFinding]) -> None:
        if not findings:
            return
        with self._connect() as conn:
            conn.executemany(
                """INSERT INTO pending_findings
                   (tool, category, title, url, app_name, raw_severity, description, evidence)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (f.tool, f.category.value, f.title, f.url, f.app_name, f.raw_severity, f.description, f.evidence)
                    for f in findings
                ],
            )

    def pending(self, app_name: Optional[str] = None) -> List[sqlite3.Row]:
        query = "SELECT * FROM pending_findings"
        params: tuple = ()
        if app_name:
            query += " WHERE app_name = ?"
            params = (app_name,)
        query += " ORDER BY created_at ASC"
        with self._connect() as conn:
            return conn.execute(query, params).fetchall()

    def pending_summary(self, app_name: Optional[str] = None) -> dict:
        """Counts per category - what the approval prompt shows before
        anyone agrees to spend tokens."""
        query = "SELECT category, COUNT(*) as count FROM pending_findings"
        params: tuple = ()
        if app_name:
            query += " WHERE app_name = ?"
            params = (app_name,)
        query += " GROUP BY category"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return {row["category"]: row["count"] for row in rows}

    def peek_for_triage(self, app_name: Optional[str] = None) -> List[RawFinding]:
        """Reads pending rows WITHOUT deleting them. Each RawFinding carries
        its row id so the caller can delete only the ones that were
        actually, successfully processed - this is what prevents findings
        from vanishing if an Opus call fails partway through triage."""
        rows = self.pending(app_name=app_name)
        return [
            RawFinding(
                id=row["id"],
                tool=row["tool"],
                category=row["category"],
                title=row["title"],
                url=row["url"],
                app_name=row["app_name"],
                raw_severity=row["raw_severity"],
                description=row["description"] or "",
                evidence=row["evidence"] or "",
            )
            for row in rows
        ]

    def delete_ids(self, ids: List[int]) -> None:
        """Delete specific pending rows by id - call this only after their
        findings have been successfully saved as TriagedFindings."""
        if not ids:
            return
        with self._connect() as conn:
            placeholders = ",".join("?" * len(ids))
            conn.execute(f"DELETE FROM pending_findings WHERE id IN ({placeholders})", ids)
