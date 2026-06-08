"""
Shared SQLite database — single source of truth for all gunicorn workers.

WAL mode is enabled so concurrent reads never block writers and vice versa.
Each function opens and closes its own connection (thread-safe for multi-process).
"""

import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "devops_agent.db")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # concurrent readers + writer
    conn.execute("PRAGMA synchronous=NORMAL") # safe + faster than FULL
    return conn


def init_db() -> None:
    """Create tables on first run. Safe to call on every worker startup."""
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id                INTEGER  PRIMARY KEY AUTOINCREMENT,
                created_at        TEXT     NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                analysis_type     TEXT     NOT NULL,
                filename          TEXT,
                severity          TEXT,
                confidence_score  REAL,
                secrets_found     INTEGER  NOT NULL DEFAULT 0,
                resolved          INTEGER  NOT NULL DEFAULT 0,
                resolved_at       TEXT,
                root_cause_preview TEXT
            )
        """)
        conn.commit()


# ── Write ─────────────────────────────────────────────────────────────────────

def record_analysis(
    analysis_type: str,
    filename: str,
    severity: str,
    confidence_score: float,
    secrets_found: int,
    root_cause_preview: str,
) -> int:
    """Insert a new analysis record and return its ID."""
    with _connect() as conn:
        cur = conn.execute(
            """INSERT INTO analyses
               (analysis_type, filename, severity, confidence_score, secrets_found, root_cause_preview)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                analysis_type,
                filename or "unknown",
                severity or "UNKNOWN",
                round(float(confidence_score or 0), 4),
                int(secrets_found or 0),
                (root_cause_preview or "")[:300],
            ),
        )
        conn.commit()
        return cur.lastrowid


def resolve_analysis(analysis_id: int) -> bool:
    """Mark an analysis as resolved. Returns True if the row existed."""
    with _connect() as conn:
        cur = conn.execute(
            "UPDATE analyses SET resolved = 1, resolved_at = ? WHERE id = ? AND resolved = 0",
            (datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), analysis_id),
        )
        conn.commit()
        return cur.rowcount > 0


# ── Read ──────────────────────────────────────────────────────────────────────

def get_stats() -> Dict[str, Any]:
    """Aggregate stats from the shared DB — consistent across all workers."""
    with _connect() as conn:
        total     = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        resolved  = conn.execute("SELECT COUNT(*) FROM analyses WHERE resolved = 1").fetchone()[0]
        pending   = total - resolved

        by_type = {
            row["analysis_type"]: row["cnt"]
            for row in conn.execute(
                "SELECT analysis_type, COUNT(*) AS cnt FROM analyses GROUP BY analysis_type"
            ).fetchall()
        }

        by_severity = {
            row["severity"]: row["cnt"]
            for row in conn.execute(
                "SELECT severity, COUNT(*) AS cnt FROM analyses "
                "WHERE severity IS NOT NULL GROUP BY severity"
            ).fetchall()
        }

        recent = [
            dict(row)
            for row in conn.execute(
                """SELECT id, created_at, analysis_type, filename, severity, resolved
                   FROM analyses ORDER BY created_at DESC LIMIT 10"""
            ).fetchall()
        ]

    return {
        "total_analyses":   total,
        "resolved":         resolved,
        "pending":          pending,
        "resolution_rate":  round(resolved / total * 100, 1) if total else 0.0,
        "by_type":          by_type,
        "by_severity":      by_severity,
        "recent":           recent,
    }


def get_recent_analyses(limit: int = 20) -> List[Dict]:
    with _connect() as conn:
        return [
            dict(row)
            for row in conn.execute(
                """SELECT id, created_at, analysis_type, filename, severity,
                          confidence_score, secrets_found, resolved, resolved_at,
                          root_cause_preview
                   FROM analyses ORDER BY created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        ]


def get_analysis(analysis_id: int) -> Optional[Dict]:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM analyses WHERE id = ?", (analysis_id,)
        ).fetchone()
        return dict(row) if row else None
