# Built into Python (no install needed):
import hashlib                      # SHA-256 hashing - the integrity mechanism
import os                           # walking through folders
import sqlite3                      # the SQLite database engine
from contextlib import contextmanager    # lets us write "with db() as conn:"
from datetime import datetime, timezone   # timestamps
from pathlib import Path            # safe, cross-platform file paths

# Installed with pip (see requirements.txt):
from fastapi import FastAPI, HTTPException
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field


# SECTION 1 - SETTINGS

HOST = "127.0.0.1"   # localhost ONLY. Never change to "0.0.0.0": the app has
                     # no login, so that would expose your file names/hashes
                     # to anyone on the same Wi-Fi.
PORT = 8000

# The database file is created next to this script.
DB_PATH = Path(__file__).with_name("fileguard.db")

MAX_FILES = 5000            # refuse huge folders so a scan can't hang forever
CHUNK_SIZE = 64 * 1024      # read files 64 KB at a time (big files won't eat RAM)

# Severity rules. Executables/scripts/configs are what attackers tamper with
# (persistence, backdoors, changed settings), so changes to them rank higher.
HIGH_RISK_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".msi", ".scr",            # Windows binaries
    ".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh",  # scripts
    ".ini", ".conf", ".cfg", ".config", ".xml", ".json",  # configuration
    ".reg", ".lnk", ".hta",                            # registry, shortcuts
}

# SECTION 2 - DATABASE (SQLite)
# =============================================================================
# SQLite = a whole database stored in ONE file (fileguard.db). 
#
#   settings  - which folder is monitored and when baseline was set
#   baseline  - the trusted fingerprint of every file
#   events    - every change detected by a scan 

@contextmanager
def db():
    """
    Open the database, hand it to the "with" block, then save (commit) and
    CLOSE it. If anything crashes inside the block, changes are rolled back,
    so the database is never left half-written.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row   # lets us read columns by name: row["path"]
    try:
        _create_tables(conn)
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _create_tables(conn: sqlite3.Connection):
    """Make sure the tables exist (safe to run every time)."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS baseline (
            path   TEXT PRIMARY KEY,   -- path relative to the monitored folder
            sha256 TEXT NOT NULL,      -- the file's fingerprint
            size   INTEGER NOT NULL    -- size in bytes
        );
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            detected_at TEXT NOT NULL,   -- UTC timestamp (ISO 8601)
            baseline_id TEXT NOT NULL,   -- which baseline this event belongs to
            folder      TEXT NOT NULL,
            path        TEXT NOT NULL,
            change_type TEXT NOT NULL,   -- ADDED / MODIFIED / DELETED
            severity    TEXT NOT NULL,   -- LOW / MEDIUM / HIGH
            old_hash    TEXT,
            new_hash    TEXT
        );
    """)


def get_setting(conn, key):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_setting(conn, key, value):
    # "?" placeholders = PARAMETERIZED QUERY. The value is sent separately from
    # the SQL text, so a malicious file name can never become SQL code.
    # This is how you prevent SQL injection.
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def now_utc() -> str:
    """Current time in UTC. Logs should use one timezone so events line up."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")