"""Persistence layer for the ASVP platform.

All tables use ALTER TABLE migration so existing databases upgrade without
data loss. New columns default to safe values for legacy rows.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

from config import settings
from models import (AttackChain, OwaspCategory, RemediationStatus, Severity,
                    TriagedFinding, ValidationStatus)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_name TEXT NOT NULL DEFAULT 'unspecified',
    url TEXT,
    vulnerability_name TEXT NOT NULL DEFAULT '',
    tool TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL,
    cwe_id TEXT DEFAULT '',
    cwe_name TEXT DEFAULT '',
    vulnerable_parameter TEXT DEFAULT '',
    severity TEXT NOT NULL,
    cvss_score REAL,
    cvss_vector TEXT,
    confidence INTEGER DEFAULT 0,
    validation_status TEXT DEFAULT 'potential',
    source_count INTEGER DEFAULT 1,
    exploitable INTEGER NOT NULL DEFAULT 0,
    rationale TEXT,
    root_cause TEXT,
    attack_scenario TEXT,
    technical_impact TEXT,
    business_impact TEXT,
    reproduction_steps TEXT,
    evidence_summary TEXT,
    remediation TEXT,
    remediation_status TEXT NOT NULL DEFAULT 'open',
    remediation_notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT,
    remediated_at TEXT
);

CREATE TABLE IF NOT EXISTS attack_chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_name TEXT NOT NULL,
    chain_name TEXT NOT NULL,
    risk_score REAL DEFAULT 0,
    exploitation_difficulty TEXT DEFAULT 'medium',
    preconditions TEXT DEFAULT '',
    attack_flow TEXT DEFAULT '',
    business_impact TEXT DEFAULT '',
    mitigations TEXT DEFAULT '',
    finding_ids TEXT DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

_FINDING_MIGRATIONS = [
    "ALTER TABLE findings ADD COLUMN app_name TEXT NOT NULL DEFAULT 'unspecified'",
    "ALTER TABLE findings ADD COLUMN vulnerability_name TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE findings ADD COLUMN tool TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE findings ADD COLUMN cwe_id TEXT DEFAULT ''",
    "ALTER TABLE findings ADD COLUMN cwe_name TEXT DEFAULT ''",
    "ALTER TABLE findings ADD COLUMN vulnerable_parameter TEXT DEFAULT ''",
    "ALTER TABLE findings ADD COLUMN cvss_score REAL",
    "ALTER TABLE findings ADD COLUMN cvss_vector TEXT",
    "ALTER TABLE findings ADD COLUMN confidence INTEGER DEFAULT 0",
    "ALTER TABLE findings ADD COLUMN validation_status TEXT DEFAULT 'potential'",
    "ALTER TABLE findings ADD COLUMN source_count INTEGER DEFAULT 1",
    "ALTER TABLE findings ADD COLUMN root_cause TEXT",
    "ALTER TABLE findings ADD COLUMN attack_scenario TEXT",
    "ALTER TABLE findings ADD COLUMN technical_impact TEXT",
    "ALTER TABLE findings ADD COLUMN business_impact TEXT",
    "ALTER TABLE findings ADD COLUMN reproduction_steps TEXT",
    "ALTER TABLE findings ADD COLUMN evidence_summary TEXT",
    "ALTER TABLE findings ADD COLUMN remediation_status TEXT NOT NULL DEFAULT 'open'",
    "ALTER TABLE findings ADD COLUMN remediation_notes TEXT",
    "ALTER TABLE findings ADD COLUMN updated_at TEXT",
    "ALTER TABLE findings ADD COLUMN remediated_at TEXT",
]


class FindingsStore:
    def __init__(self, db_path=None):
        self.db_path = str(db_path or settings.db_path)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            for stmt in _FINDING_MIGRATIONS:
                try:
                    conn.execute(stmt)
                except sqlite3.OperationalError:
                    pass

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ---- findings ----

    def save(self, f: TriagedFinding) -> int:
        with self._connect() as conn:
            cur = conn.execute("""
                INSERT INTO findings (
                    app_name, url, vulnerability_name, tool, category,
                    cwe_id, cwe_name, vulnerable_parameter, severity, cvss_score, cvss_vector,
                    confidence, validation_status, source_count, exploitable,
                    rationale, root_cause, attack_scenario, technical_impact,
                    business_impact, reproduction_steps, evidence_summary,
                    remediation, remediation_status, remediation_notes
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                f.app_name, f.url, f.vulnerability_name, f.tool,
                f.category.value, f.cwe_id, f.cwe_name, f.vulnerable_parameter, f.severity.value,
                f.cvss_score, f.cvss_vector, f.confidence,
                f.validation_status.value, f.source_count, int(f.exploitable),
                f.rationale, f.root_cause, f.attack_scenario, f.technical_impact,
                f.business_impact, f.reproduction_steps, f.evidence_summary,
                f.remediation, f.remediation_status.value, f.remediation_notes,
            ))
            return cur.lastrowid

    def all(self, app_name: Optional[str] = None) -> List[sqlite3.Row]:
        query = "SELECT * FROM findings"
        params: tuple = ()
        if app_name:
            query += " WHERE app_name = ?"
            params = (app_name,)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            return conn.execute(query, params).fetchall()

    def get(self, finding_id: int) -> Optional[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()

    def list_apps(self) -> List[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT app_name FROM findings ORDER BY app_name"
            ).fetchall()
        return [r["app_name"] for r in rows]

    def severity_summary(self, app_name: Optional[str] = None) -> dict:
        q = "SELECT severity, COUNT(*) c FROM findings WHERE remediation_status NOT IN ('remediated','dismissed')"
        p: tuple = ()
        if app_name:
            q += " AND app_name = ?"
            p = (app_name,)
        q += " GROUP BY severity"
        with self._connect() as conn:
            rows = conn.execute(q, p).fetchall()
        result = {s.value: 0 for s in Severity}
        for r in rows:
            result[r["severity"]] = r["c"]
        return result

    def category_summary(self, app_name: Optional[str] = None) -> dict:
        q = "SELECT category, COUNT(*) c FROM findings WHERE remediation_status = 'open'"
        p: tuple = ()
        if app_name:
            q += " AND app_name = ?"
            p = (app_name,)
        q += " GROUP BY category"
        with self._connect() as conn:
            rows = conn.execute(q, p).fetchall()
        result = {c.value: 0 for c in OwaspCategory}
        for r in rows:
            result[r["category"]] = r["c"]
        return result

    def remediation_summary(self, app_name: Optional[str] = None) -> dict:
        q = "SELECT remediation_status, COUNT(*) c FROM findings"
        p: tuple = ()
        if app_name:
            q += " WHERE app_name = ?"
            p = (app_name,)
        q += " GROUP BY remediation_status"
        with self._connect() as conn:
            rows = conn.execute(q, p).fetchall()
        result = {s.value: 0 for s in RemediationStatus}
        for r in rows:
            result[r["remediation_status"]] = r["c"]
        return result

    def update_remediation(self, finding_id: int, status: RemediationStatus,
                           notes: Optional[str] = None) -> None:
        now = __import__("datetime").datetime.utcnow().isoformat()
        remediated_at = now if status == RemediationStatus.REMEDIATED else None
        with self._connect() as conn:
            conn.execute(
                "UPDATE findings SET remediation_status=?, remediation_notes=?, "
                "updated_at=?, remediated_at=? WHERE id=?",
                (status.value, notes, now, remediated_at, finding_id)
            )

    def update_status(self, finding_id: int, status) -> None:
        """Backward-compat shim used by old API endpoints."""
        try:
            rs = RemediationStatus(status.value if hasattr(status, "value") else status)
        except ValueError:
            rs = RemediationStatus.OPEN
        self.update_remediation(finding_id, rs)

    # ---- attack chains ----

    def save_chain(self, chain: AttackChain) -> int:
        with self._connect() as conn:
            cur = conn.execute("""
                INSERT INTO attack_chains
                (app_name, chain_name, risk_score, exploitation_difficulty,
                 preconditions, attack_flow, business_impact, mitigations, finding_ids)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                chain.app_name, chain.chain_name, chain.risk_score,
                chain.exploitation_difficulty, chain.preconditions,
                chain.attack_flow, chain.business_impact, chain.mitigations,
                json.dumps(chain.finding_ids),
            ))
            return cur.lastrowid

    def chains(self, app_name: Optional[str] = None) -> List[sqlite3.Row]:
        q = "SELECT * FROM attack_chains"
        p: tuple = ()
        if app_name:
            q += " WHERE app_name = ?"
            p = (app_name,)
        q += " ORDER BY risk_score DESC"
        with self._connect() as conn:
            return conn.execute(q, p).fetchall()

    def delete_chains_for_app(self, app_name: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM attack_chains WHERE app_name = ?", (app_name,))

    def scan_comparison(self, app_name: str, since_iso: str) -> dict:
        """Compare current open findings to a point in time."""
        with self._connect() as conn:
            new = conn.execute(
                "SELECT COUNT(*) c FROM findings WHERE app_name=? AND created_at > ?",
                (app_name, since_iso)
            ).fetchone()["c"]
            remediated = conn.execute(
                "SELECT COUNT(*) c FROM findings WHERE app_name=? AND remediated_at > ?",
                (app_name, since_iso)
            ).fetchone()["c"]
            reopened = conn.execute(
                "SELECT COUNT(*) c FROM findings WHERE app_name=? AND remediation_status='reopened' AND updated_at > ?",
                (app_name, since_iso)
            ).fetchone()["c"]
        return {"new": new, "remediated": remediated, "reopened": reopened}
