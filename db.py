"""
db.py — SQLite persistence layer for AI Guardrail.

Uses plain stdlib sqlite3 (no ORM) to keep the dependency footprint
tiny. Swap DB_PATH for a networked path or migrate to Postgres later
without touching the rest of the app — all access goes through the
functions in this file.
"""

import sqlite3
import os
import json
import time
from contextlib import contextmanager

DB_PATH = os.environ.get("GUARDRAIL_DB_PATH", "guardrail.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    input_text TEXT NOT NULL,
    profile TEXT NOT NULL,
    risk TEXT NOT NULL,
    score REAL NOT NULL,
    matched_categories TEXT NOT NULL,   -- JSON array
    signals TEXT NOT NULL,              -- JSON object
    blocked INTEGER NOT NULL,
    client_id TEXT
);

CREATE TABLE IF NOT EXISTS test_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    mode TEXT NOT NULL,                 -- 'mock' | 'api'
    model TEXT,
    profile TEXT,
    firewall_enabled INTEGER NOT NULL,
    total_cases INTEGER NOT NULL,
    bypassed_cases INTEGER NOT NULL,
    blocked_cases INTEGER NOT NULL,
    bypass_rate REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS test_case_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    case_id TEXT NOT NULL,
    category TEXT NOT NULL,
    blocked_by_firewall INTEGER NOT NULL,
    bypassed INTEGER NOT NULL,
    response TEXT,
    FOREIGN KEY (run_id) REFERENCES test_runs (id)
);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at);
CREATE INDEX IF NOT EXISTS idx_scans_risk ON scans (risk);
CREATE INDEX IF NOT EXISTS idx_test_runs_created_at ON test_runs (created_at);
CREATE INDEX IF NOT EXISTS idx_case_results_run_id ON test_case_results (run_id);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def record_scan(input_text: str, profile: str, scan_result: dict, blocked: bool, client_id: str = None) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO scans
               (created_at, input_text, profile, risk, score, matched_categories, signals, blocked, client_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                time.time(),
                input_text,
                profile,
                scan_result["risk"],
                scan_result["score"],
                json.dumps(scan_result["matched_categories"]),
                json.dumps(scan_result["signals"]),
                int(blocked),
                client_id,
            ),
        )
        return cur.lastrowid


def record_test_run(mode: str, model: str, profile: str, firewall_enabled: bool, results: list) -> int:
    total = len(results)
    bypassed = sum(1 for r in results if r.get("bypassed"))
    blocked = sum(1 for r in results if r.get("blocked_by_firewall"))
    bypass_rate = round(100 * bypassed / total, 2) if total else 0.0

    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO test_runs
               (created_at, mode, model, profile, firewall_enabled, total_cases, bypassed_cases, blocked_cases, bypass_rate)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (time.time(), mode, model, profile, int(firewall_enabled), total, bypassed, blocked, bypass_rate),
        )
        run_id = cur.lastrowid

        for r in results:
            conn.execute(
                """INSERT INTO test_case_results
                   (run_id, case_id, category, blocked_by_firewall, bypassed, response)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    r["id"],
                    r["category"],
                    int(r.get("blocked_by_firewall", False)),
                    int(r.get("bypassed", False)),
                    r.get("response"),
                ),
            )
        return run_id


def get_scan_stats(since: float = None) -> dict:
    query = "SELECT risk, COUNT(*) as count FROM scans"
    params = ()
    if since:
        query += " WHERE created_at >= ?"
        params = (since,)
    query += " GROUP BY risk"

    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
        return {row["risk"]: row["count"] for row in rows}


def list_scans(limit: int = 50, offset: int = 0) -> list:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [dict(row) for row in rows]


def list_test_runs(limit: int = 50) -> list:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM test_runs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_test_run(run_id: int) -> dict:
    with get_conn() as conn:
        run = conn.execute("SELECT * FROM test_runs WHERE id = ?", (run_id,)).fetchone()
        if not run:
            return None
        cases = conn.execute(
            "SELECT * FROM test_case_results WHERE run_id = ?", (run_id,)
        ).fetchall()
        result = dict(run)
        result["cases"] = [dict(c) for c in cases]
        return result


def get_bypass_trend(limit: int = 30) -> list:
    """Bypass rate over recent test runs, most recent last — good for charting."""
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT created_at, profile, firewall_enabled, bypass_rate
               FROM test_runs ORDER BY created_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return list(reversed([dict(row) for row in rows]))
