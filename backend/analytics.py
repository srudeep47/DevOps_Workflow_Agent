"""
Analytics queries — aggregates from SQLite for the dashboard charts.
All functions return plain dicts/lists ready for JSON serialisation.
"""

import os
import sqlite3
from typing import Any, Dict, List

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "devops_agent.db")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def get_analytics() -> Dict[str, Any]:
    with _connect() as conn:

        # ── Analyses per day (last 30 days) ───────────────────────────────────
        daily_rows = conn.execute("""
            SELECT
                date(created_at) AS day,
                COUNT(*)         AS total,
                SUM(resolved)    AS resolved
            FROM analyses
            WHERE created_at >= date('now', '-30 days')
            GROUP BY day
            ORDER BY day ASC
        """).fetchall()
        daily = [
            {"day": r["day"], "total": r["total"], "resolved": r["resolved"] or 0}
            for r in daily_rows
        ]

        # ── Severity distribution ─────────────────────────────────────────────
        sev_rows = conn.execute("""
            SELECT severity, COUNT(*) AS cnt
            FROM analyses
            WHERE severity IS NOT NULL
            GROUP BY severity
        """).fetchall()
        severity_dist = {r["severity"]: r["cnt"] for r in sev_rows}

        # ── Analysis type distribution ────────────────────────────────────────
        type_rows = conn.execute("""
            SELECT analysis_type, COUNT(*) AS cnt
            FROM analyses
            GROUP BY analysis_type
        """).fetchall()
        type_dist = {r["analysis_type"]: r["cnt"] for r in type_rows}

        # ── Average confidence by type ────────────────────────────────────────
        conf_rows = conn.execute("""
            SELECT analysis_type, ROUND(AVG(confidence_score), 3) AS avg_conf
            FROM analyses
            WHERE confidence_score IS NOT NULL
            GROUP BY analysis_type
        """).fetchall()
        avg_confidence = {r["analysis_type"]: r["avg_conf"] for r in conf_rows}

        # ── Secrets masked over time ──────────────────────────────────────────
        secrets_rows = conn.execute("""
            SELECT date(created_at) AS day, SUM(secrets_found) AS masked
            FROM analyses
            WHERE created_at >= date('now', '-30 days')
            GROUP BY day
            ORDER BY day ASC
        """).fetchall()
        secrets_trend = [{"day": r["day"], "masked": r["masked"] or 0} for r in secrets_rows]

        # ── Resolution time (avg hours between created_at and resolved_at) ────
        res_time_rows = conn.execute("""
            SELECT
                ROUND(
                    AVG(
                        (julianday(resolved_at) - julianday(created_at)) * 24
                    ), 2
                ) AS avg_hours
            FROM analyses
            WHERE resolved = 1 AND resolved_at IS NOT NULL
        """).fetchone()
        avg_resolution_hours = res_time_rows["avg_hours"] if res_time_rows else None

        # ── Weekly resolution rate trend ──────────────────────────────────────
        weekly_rows = conn.execute("""
            SELECT
                strftime('%Y-W%W', created_at) AS week,
                COUNT(*) AS total,
                SUM(resolved) AS resolved
            FROM analyses
            WHERE created_at >= date('now', '-84 days')
            GROUP BY week
            ORDER BY week ASC
        """).fetchall()
        weekly = [
            {
                "week": r["week"],
                "total": r["total"],
                "resolved": r["resolved"] or 0,
                "rate": round((r["resolved"] or 0) / r["total"] * 100, 1) if r["total"] else 0,
            }
            for r in weekly_rows
        ]

        # ── Top filenames analyzed ────────────────────────────────────────────
        top_files_rows = conn.execute("""
            SELECT filename, COUNT(*) AS cnt
            FROM analyses
            GROUP BY filename
            ORDER BY cnt DESC
            LIMIT 5
        """).fetchall()
        top_files = [{"filename": r["filename"], "count": r["cnt"]} for r in top_files_rows]

    return {
        "daily_trend":         daily,
        "severity_dist":       severity_dist,
        "type_dist":           type_dist,
        "avg_confidence":      avg_confidence,
        "secrets_trend":       secrets_trend,
        "avg_resolution_hours": avg_resolution_hours,
        "weekly_resolution":   weekly,
        "top_files":           top_files,
    }
