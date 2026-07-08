"""
store.py
--------
Persistence layer for SCANN3R, backed by SQLite.

SQLite is chosen deliberately: it's a single portable file, needs no server
to stand up, is queryable with standard SQL, and handles historical records
cleanly. That fits an enterprise SOC context where you want an auditable
history of scans without provisioning a database.

Two tables:
  - scans:        one row per scan run (target, ip, timestamp)
  - port_results: one row per port per scan (state at that point in time)

This normalized layout lets us reconstruct the exact port state of any target
at any past scan, which is what the diff engine compares against.
"""

import sqlite3
from datetime import datetime, timezone


# Default database file. Created automatically on first run.
DEFAULT_DB = "scann3r.db"


def init_db(db_path=DEFAULT_DB):
    """
    Create the database schema if it doesn't already exist.

    Safe to call on every startup: CREATE TABLE IF NOT EXISTS is idempotent.
    Returns an open sqlite3 connection with row access by column name enabled.
    """
    conn = sqlite3.connect(db_path)
    # Return rows as dict-like objects so we can access columns by name.
    conn.row_factory = sqlite3.Row

    conn.executescript("""
        -- One row per scan run.
        CREATE TABLE IF NOT EXISTS scans (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            target    TEXT NOT NULL,        -- original hostname/IP as entered
            ip        TEXT NOT NULL,        -- resolved IP at scan time
            timestamp TEXT NOT NULL         -- ISO 8601 UTC
        );

        -- One row per port per scan.
        CREATE TABLE IF NOT EXISTS port_results (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,       -- FK -> scans.id
            port    INTEGER NOT NULL,
            state   TEXT NOT NULL,          -- 'open' | 'closed' | 'filtered'
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        -- Index to speed up "most recent scan for this target" lookups.
        CREATE INDEX IF NOT EXISTS idx_scans_target
            ON scans(target, timestamp);
    """)
    conn.commit()
    return conn


def save_scan(conn, scan_result):
    """
    Persist a scan result (as returned by scanner.scan_target) to the database.

    Writes one scans row and one port_results row per scanned port, all inside
    a single transaction so a partial scan never leaves half-written data.

    Returns the new scan's id.
    """
    cur = conn.cursor()

    # Insert the parent scan record.
    cur.execute(
        "INSERT INTO scans (target, ip, timestamp) VALUES (?, ?, ?)",
        (scan_result["target"], scan_result["ip"], scan_result["timestamp"]),
    )
    scan_id = cur.lastrowid

    # Bulk-insert every port result for this scan.
    cur.executemany(
        "INSERT INTO port_results (scan_id, port, state) VALUES (?, ?, ?)",
        [(scan_id, port, state) for port, state in scan_result["ports"].items()],
    )

    conn.commit()
    return scan_id


def get_last_scan(conn, target):
    """
    Fetch the most recent *previous* scan for a target, as a port->state dict.

    Returns None if the target has never been scanned before (first run, so
    there's nothing to diff against). Otherwise returns:
        { port_number: state, ... }
    """
    cur = conn.cursor()

    # Most recent scan row for this target.
    row = cur.execute(
        "SELECT id FROM scans WHERE target = ? ORDER BY timestamp DESC LIMIT 1",
        (target,),
    ).fetchone()

    if row is None:
        return None

    scan_id = row["id"]

    # Pull all port results for that scan into a plain dict.
    port_rows = cur.execute(
        "SELECT port, state FROM port_results WHERE scan_id = ?",
        (scan_id,),
    ).fetchall()

    return {r["port"]: r["state"] for r in port_rows}


def get_history(conn, target, limit=10):
    """
    Return recent scan metadata for a target, newest first.

    Used by the CLI 'history' command. Does not pull full port results,
    just the scan-level summary (id, timestamp, ip).
    """
    cur = conn.cursor()
    rows = cur.execute(
        """
        SELECT id, ip, timestamp
        FROM scans
        WHERE target = ?
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (target, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def list_targets(conn):
    """
    Return every distinct target that has ever been scanned, with a count
    of how many scans exist for each. Powers the CLI 'targets' command.
    """
    cur = conn.cursor()
    rows = cur.execute(
        """
        SELECT target, COUNT(*) AS scan_count, MAX(timestamp) AS last_scan
        FROM scans
        GROUP BY target
        ORDER BY last_scan DESC
        """
    ).fetchall()
    return [dict(r) for r in rows]
