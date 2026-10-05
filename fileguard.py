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