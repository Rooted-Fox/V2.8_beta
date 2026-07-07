"""Token governance: records every Claude API call's token usage and lets
an optional budget block further triage once it's exhausted. Nothing
calls the Anthropic API anywhere in this codebase without going through
agents.agent.OwaspAgent, and every one of those calls gets logged here.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Iterator, Optional

from config import settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS token_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class TokenStore:
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

    def record(self, category: str, input_tokens: int, output_tokens: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO token_usage (category, input_tokens, output_tokens) VALUES (?, ?, ?)",
                (category, input_tokens, output_tokens),
            )

    def total_used(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(SUM(input_tokens + output_tokens), 0) as total FROM token_usage"
            ).fetchone()
        return row["total"]

    def usage_by_category(self) -> dict:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT category, SUM(input_tokens + output_tokens) as total FROM token_usage GROUP BY category"
            ).fetchall()
        return {row["category"]: row["total"] for row in rows}

    def reset(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM token_usage")

    def has_budget(self, limit: Optional[int]) -> bool:
        """A limit of None or 0 means unlimited."""
        if not limit:
            return True
        return self.total_used() < limit
