r"""
===============================================================================
 FileGuard - File Integrity Monitoring (FIM) Dashboard
===============================================================================

WHAT THIS IS
  A small, single-file prototype that detects when files in a folder are
  ADDED, MODIFIED, or DELETED, by comparing SHA-256 fingerprints against a
  trusted "baseline". Results are shown on a web dashboard.

SECURITY CONCEPTS
  - Integrity (the "I" in the CIA triad): we detect unauthorized changes.
  - Detective control: FIM does NOT stop tampering, it detects it after the fact.
  - Compliance: PCI DSS v4.0 requirement 11.5.2 calls for a change-detection
    mechanism (e.g. FIM) on critical files.

HOW TO RUN (Windows, VS Code -> Terminal -> PowerShell, inside the project folder)
  1. python -m venv .venv                 (create a virtual environment)
  2. .\.venv\Scripts\Activate.ps1         (turn it on)
  3. pip install -r requirements.txt      (install FastAPI + uvicorn + pytest)
  4. python fileguard.py                  (start the app)
  5. Open http://127.0.0.1:8000 in your browser

KNOWN LIMITATIONS (be honest about these in interviews)
  - On-demand scans, not real-time monitoring.
  - Single machine, single monitored folder at a time.
  - Local trust: the baseline database lives on the same machine it protects.
    An attacker with write access could also edit fileguard.db.
  - No authentication. Compensating control: the server only listens on
    127.0.0.1 (this machine), never on the network.

FILE LAYOUT (search for these banners to jump around)
  SECTION 1 - SETTINGS        (tweak limits, severity rules, port)
  SECTION 2 - DATABASE        (SQLite tables + helpers)
  SECTION 3 - SCAN ENGINE     (hashing, comparing, severity)
  SECTION 4 - WEB API         (FastAPI endpoints)
  SECTION 5 - DASHBOARD       (HTML + CSS + JavaScript, embedded as a string)
  SECTION 6 - START SERVER
===============================================================================
"""

# --- Imports: pulling in code other people already wrote ---------------------
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


# =============================================================================
# SECTION 1 - SETTINGS
# =============================================================================

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


# =============================================================================
# SECTION 2 - DATABASE (SQLite)
# =============================================================================
# SQLite = a whole database stored in ONE file (fileguard.db). No server needed.
#
# Tables:
#   settings  - key/value pairs: which folder is monitored, when baseline was set
#   baseline  - the trusted "known good" fingerprint of every file
#   events    - every change detected by a scan (the alert log)

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


# =============================================================================
# SECTION 3 - SCAN ENGINE (the actual security logic)
# =============================================================================

def validate_folder(raw_path: str) -> Path:
    """
    INPUT VALIDATION. Never trust what the user (or an attacker) sends.
    Turns the typed text into a real, absolute folder path, or raises ValueError.
    """
    raw_path = (raw_path or "").strip().strip('"')   # remove spaces/quotes from copy-paste
    if not raw_path:
        raise ValueError("Please enter a folder path.")

    try:
        # resolve() turns relative paths and ".." tricks into the real absolute path
        folder = Path(raw_path).expanduser().resolve(strict=True)
    except (FileNotFoundError, OSError):
        raise ValueError(f"Folder not found: {raw_path}")

    if not folder.is_dir():
        raise ValueError("That path is a file, not a folder.")
    if folder.parent == folder:
        raise ValueError("Refusing to monitor a whole drive (e.g. C:\\). Pick a specific folder.")
    return folder


def sha256_file(file_path: Path) -> str:
    """
    Compute the SHA-256 fingerprint of a file.
    Change even ONE byte and the hash becomes completely different.
    We read in chunks so a 4 GB file doesn't need 4 GB of RAM.
    """
    h = hashlib.sha256()
    with open(file_path, "rb") as f:           # "rb" = read raw bytes
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def collect_hashes(folder: Path) -> tuple[dict, list]:
    """
    Walk every file in the folder (and subfolders) and hash it.
    Returns:
      hashes  -> {"relative/path.txt": {"sha256": "...", "size": 123}, ...}
      skipped -> list of files we couldn't read (locked, no permission...)
    """
    hashes, skipped = {}, []
    db_files = {DB_PATH.resolve(), Path(str(DB_PATH) + "-journal").resolve()}

    # os.walk does NOT follow symbolic links by default, so a link inside the
    # folder can't trick us into scanning somewhere else on the disk.
    for root, _dirs, files in os.walk(folder):
        for name in files:
            full = Path(root) / name
            if full.is_symlink() or full.resolve() in db_files:
                continue                       # skip links + our own database
            rel = full.relative_to(folder).as_posix()   # "sub/file.txt" style
            try:
                hashes[rel] = {"sha256": sha256_file(full), "size": full.stat().st_size}
            except OSError as err:              # locked / permission denied
                skipped.append(f"{rel} ({err.strerror})")
            if len(hashes) > MAX_FILES:
                raise ValueError(f"Folder has more than {MAX_FILES} files. Pick a smaller folder.")
    return hashes, skipped


def compare(baseline: dict, current: dict) -> list[dict]:
    """
    THE DETECTION LOGIC. Compare the trusted baseline with what's on disk now.
      in current but not baseline      -> ADDED
      in baseline but not current      -> DELETED
      in both, but hash is different   -> MODIFIED
    baseline/current are {path: sha256} dictionaries.
    """
    changes = []
    for path in sorted(current.keys() - baseline.keys()):
        changes.append({"path": path, "change_type": "ADDED",
                        "old_hash": None, "new_hash": current[path]})
    for path in sorted(baseline.keys() - current.keys()):
        changes.append({"path": path, "change_type": "DELETED",
                        "old_hash": baseline[path], "new_hash": None})
    for path in sorted(baseline.keys() & current.keys()):
        if baseline[path] != current[path]:
            changes.append({"path": path, "change_type": "MODIFIED",
                            "old_hash": baseline[path], "new_hash": current[path]})
    return changes


def severity_for(path: str, change_type: str) -> str:
    """
    Triage rule: how worried should an analyst be?
      Any change to an executable/script/config file -> HIGH
      Other file deleted   -> MEDIUM (possible evidence destruction / data loss)
      Other file modified  -> MEDIUM
      Other file added     -> LOW
    """
    if Path(path).suffix.lower() in HIGH_RISK_EXTENSIONS:
        return "HIGH"
    if change_type in ("DELETED", "MODIFIED"):
        return "MEDIUM"
    return "LOW"


# =============================================================================
# SECTION 4 - WEB API (FastAPI)
# =============================================================================
# The backend. The browser sends HTTP requests to these "endpoints" and gets
# JSON back. All security logic lives HERE, not in the browser.

app = FastAPI(title="FileGuard", version="1.0")

# DNS-rebinding protection: only answer requests addressed to localhost.
# Without this, a malicious website could trick your browser into calling
# this API. One line, real attack, good interview point.
app.add_middleware(TrustedHostMiddleware,
                   allowed_hosts=["127.0.0.1", "localhost"])


class FolderRequest(BaseModel):
    """Shape of the JSON body the dashboard sends: {"path": "C:\\..."}"""
    path: str = Field(..., max_length=500)   # cap length: basic input validation


@app.get("/", response_class=HTMLResponse)
def dashboard():
    """Serve the dashboard page (SECTION 5)."""
    return HTMLResponse(DASHBOARD_HTML, headers={
        "X-Content-Type-Options": "nosniff",   # browser must not guess file types
        "X-Frame-Options": "DENY",             # page can't be embedded (clickjacking)
    })


@app.post("/api/baseline")
def set_baseline(req: FolderRequest):
    """Hash every file and store it as the trusted 'known good' state."""
    try:
        folder = validate_folder(req.path)
        hashes, skipped = collect_hashes(folder)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))

    baseline_id = now_utc()
    with db() as conn:                           # opens, saves, closes for us
        conn.execute("DELETE FROM baseline")     # new baseline replaces the old one
        conn.executemany(
            "INSERT INTO baseline (path, sha256, size) VALUES (?, ?, ?)",
            [(p, h["sha256"], h["size"]) for p, h in hashes.items()],
        )
        set_setting(conn, "folder", str(folder))
        set_setting(conn, "baseline_id", baseline_id)
        set_setting(conn, "last_scan", None)
    return {"message": f"Baseline set: {len(hashes)} files fingerprinted.",
            "folder": str(folder), "files": len(hashes), "skipped": skipped}


@app.post("/api/scan")
def scan():
    """Re-hash the monitored folder, compare to baseline, record change events."""
    with db() as conn:
        folder_str = get_setting(conn, "folder")
        baseline_id = get_setting(conn, "baseline_id")
        if not folder_str or not baseline_id:
            raise HTTPException(400, "No baseline yet. Set a baseline first.")
        baseline = {r["path"]: r["sha256"] for r in conn.execute("SELECT path, sha256 FROM baseline")}

    try:
        folder = validate_folder(folder_str)
        current_full, skipped = collect_hashes(folder)
    except ValueError as err:
        raise HTTPException(400, f"Scan failed: {err}")
    current = {p: h["sha256"] for p, h in current_full.items()}

    changes = compare(baseline, current)
    detected_at, new_events = now_utc(), 0
    with db() as conn:
        for c in changes:
            # De-duplication: the baseline stays the same until YOU reset it, so
            # the same change would be re-reported on every scan. Only log it
            # once per baseline -> less alert fatigue for the analyst.
            already = conn.execute(
                "SELECT 1 FROM events WHERE baseline_id = ? AND path = ? "
                "AND change_type = ? AND new_hash IS ?",
                (baseline_id, c["path"], c["change_type"], c["new_hash"]),
            ).fetchone()
            if already:
                continue
            conn.execute(
                "INSERT INTO events (detected_at, baseline_id, folder, path, change_type,"
                " severity, old_hash, new_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (detected_at, baseline_id, str(folder), c["path"], c["change_type"],
                 severity_for(c["path"], c["change_type"]), c["old_hash"], c["new_hash"]),
            )
            new_events += 1
        set_setting(conn, "last_scan", detected_at)

    return {"message": f"Scan complete: {len(changes)} difference(s) from baseline, "
                       f"{new_events} new event(s).",
            "differences": len(changes), "new_events": new_events, "skipped": skipped}


@app.get("/api/status")
def status():
    """Numbers for the stat cards at the top of the dashboard."""
    with db() as conn:
        baseline_id = get_setting(conn, "baseline_id")
        counts = {r["severity"]: r["n"] for r in conn.execute(
            "SELECT severity, COUNT(*) AS n FROM events WHERE baseline_id = ? GROUP BY severity",
            (baseline_id,))}
        return {
            "folder": get_setting(conn, "folder"),
            "baseline_set_at": baseline_id,
            "last_scan": get_setting(conn, "last_scan"),
            "files_tracked": conn.execute("SELECT COUNT(*) FROM baseline").fetchone()[0],
            "events": {s: counts.get(s, 0) for s in ("HIGH", "MEDIUM", "LOW")},
        }


@app.get("/api/events")
def list_events(severity: str | None = None, limit: int = 200):
    """Change events for the current baseline, newest first. Optional ?severity=HIGH"""
    if severity and severity.upper() not in ("HIGH", "MEDIUM", "LOW"):
        raise HTTPException(400, "severity must be HIGH, MEDIUM or LOW")
    limit = max(1, min(limit, 1000))
    query = "SELECT * FROM events WHERE baseline_id = (SELECT value FROM settings WHERE key='baseline_id')"
    params = []
    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with db() as conn:
        return [dict(r) for r in conn.execute(query, params)]


@app.get("/api/files")
def list_files():
    """Every file in the current baseline with its fingerprint."""
    with db() as conn:
        return [dict(r) for r in conn.execute("SELECT path, sha256, size FROM baseline ORDER BY path")]


# =============================================================================
# SECTION 5 - DASHBOARD (HTML + CSS + JavaScript)
# =============================================================================
# Everything the browser shows. Three parts inside this one string:
#   <style>   CSS  -> colors & layout   (look for "THEME COLORS")
#   <body>    HTML -> the page structure
#   <script>  JS   -> behaviour: buttons, calling the API, filling tables
#
# SECURITY NOTE (XSS): file names come from disk and could contain HTML.
# We ALWAYS insert them with .textContent (treated as plain text), NEVER with
# .innerHTML (which would execute any <script> hidden in a file name).

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FileGuard - File Integrity Monitor</title>
<style>
  /* ===== THEME COLORS - change these to restyle the whole dashboard ===== */
  :root {
    --bg:        #0b1120;   /* page background            */
    --panel:     #111a2e;   /* cards / panels             */
    --border:    #1f2a44;   /* lines between things       */
    --text:      #e2e8f0;   /* main text                  */
    --muted:     #8b98b4;   /* secondary text             */
    --accent:    #22d3ee;   /* buttons, highlights (cyan) */
    --high:      #f43f5e;   /* HIGH severity   (red)      */
    --medium:    #f59e0b;   /* MEDIUM severity (amber)    */
    --low:       #38bdf8;   /* LOW severity    (blue)     */
    --ok:        #10b981;   /* success messages (green)   */
  }

  /* ===== BASE LAYOUT ===== */
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
         font: 14px/1.5 "Segoe UI", system-ui, sans-serif; }
  .wrap { max-width: 1150px; margin: 0 auto; padding: 24px 16px 48px; }
  code, .mono { font-family: Consolas, "Cascadia Mono", monospace; }

  /* ===== HEADER ===== */
  header { display: flex; align-items: center; gap: 12px; margin-bottom: 20px; }
  .logo { width: 38px; height: 38px; border-radius: 9px; display: grid; place-items: center;
          background: rgba(34,211,238,.12); border: 1px solid var(--accent); color: var(--accent);
          font-weight: 700; }
  header h1 { margin: 0; font-size: 20px; }
  header p  { margin: 0; color: var(--muted); font-size: 13px; }

  /* ===== PANELS / CARDS ===== */
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
           padding: 18px; margin-bottom: 18px; }
  .panel h2 { margin: 0 0 12px; font-size: 13px; text-transform: uppercase;
              letter-spacing: .08em; color: var(--muted); }

  /* ===== FOLDER INPUT + BUTTONS ===== */
  .controls { display: flex; gap: 10px; flex-wrap: wrap; }
  .controls input { flex: 1 1 320px; padding: 10px 12px; border-radius: 8px;
                    border: 1px solid var(--border); background: var(--bg); color: var(--text);
                    font-family: Consolas, monospace; }
  button { padding: 10px 16px; border-radius: 8px; border: 1px solid var(--accent);
           background: transparent; color: var(--accent); font-weight: 600; cursor: pointer; }
  button.primary { background: var(--accent); color: #04121a; }
  button:disabled { opacity: .5; cursor: wait; }
  .meta { margin-top: 10px; color: var(--muted); font-size: 12.5px; }
  #message { margin-top: 10px; min-height: 20px; font-size: 13px; }
  #message.ok { color: var(--ok); }  #message.err { color: var(--high); }

  /* ===== STAT CARDS ===== */
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 18px; }
  .stat { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 14px; }
  .stat .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
  .stat .value { font-size: 28px; font-weight: 700; margin-top: 4px; }
  .stat.high   .value { color: var(--high); }
  .stat.medium .value { color: var(--medium); }
  .stat.low    .value { color: var(--low); }
  @media (max-width: 700px) { .stats { grid-template-columns: repeat(2, 1fr); } }

  /* ===== TABLES ===== */
  .table-head { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
  select { padding: 6px 10px; border-radius: 8px; background: var(--bg); color: var(--text);
           border: 1px solid var(--border); }
  .scroll { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; color: var(--muted); font-weight: 600; padding: 8px;
       border-bottom: 1px solid var(--border); white-space: nowrap; }
  td { padding: 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  td.hash { color: var(--muted); font-size: 12px; }
  .empty { color: var(--muted); text-align: center; padding: 20px; }

  /* ===== SEVERITY + CHANGE-TYPE BADGES ===== */
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11.5px;
           font-weight: 700; border: 1px solid currentColor; }
  .badge.HIGH { color: var(--high); }  .badge.MEDIUM { color: var(--medium); }
  .badge.LOW  { color: var(--low); }
  .type { font-weight: 600; }
  .type.ADDED { color: var(--ok); } .type.MODIFIED { color: var(--medium); }
  .type.DELETED { color: var(--high); }
</style>
</head>
<body>
<div class="wrap">

  <!-- ===== HEADER ===== -->
  <header>
    <div class="logo">FG</div>
    <div>
      <h1>FileGuard</h1>
      <p>File Integrity Monitoring &middot; SHA-256 &middot; detective control</p>
    </div>
  </header>

  <!-- ===== CONTROLS: folder path + action buttons ===== -->
  <section class="panel">
    <h2>Monitored folder</h2>
    <div class="controls">
      <input id="folder" placeholder="C:\Users\you\fileguard-test" autocomplete="off">
      <button id="btn-baseline">Set Baseline</button>
      <button id="btn-scan" class="primary">Scan Now</button>
    </div>
    <div class="meta" id="meta">No baseline set yet.</div>
    <div id="message"></div>
  </section>

  <!-- ===== STAT CARDS ===== -->
  <section class="stats">
    <div class="stat"><div class="label">Files tracked</div><div class="value" id="s-files">0</div></div>
    <div class="stat high"><div class="label">High</div><div class="value" id="s-high">0</div></div>
    <div class="stat medium"><div class="label">Medium</div><div class="value" id="s-medium">0</div></div>
    <div class="stat low"><div class="label">Low</div><div class="value" id="s-low">0</div></div>
  </section>

  <!-- ===== CHANGE EVENTS TABLE ===== -->
  <section class="panel">
    <div class="table-head">
      <h2>Change events</h2>
      <select id="filter">
        <option value="">All severities</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th>Detected</th><th>Severity</th><th>Change</th><th>File</th><th>Old hash</th><th>New hash</th></tr></thead>
        <tbody id="events"></tbody>
      </table>
    </div>
  </section>

  <!-- ===== TRACKED FILES TABLE ===== -->
  <section class="panel">
    <h2>Baseline (trusted state)</h2>
    <div class="scroll">
      <table>
        <thead><tr><th>File</th><th>Size</th><th>SHA-256</th></tr></thead>
        <tbody id="files"></tbody>
      </table>
    </div>
  </section>
</div>

<script>
// ===== HELPERS ===============================================================

// Call the backend API and return the JSON. Throws an Error with the
// server's message if something goes wrong (e.g. 400 Bad Request).
async function api(method, url, body) {
  const options = { method, headers: {} };
  if (body) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const res = await fetch(url, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || "Request failed (" + res.status + ")");
  return data;
}

// Show a green (ok) or red (err) message under the buttons.
function say(text, kind) {
  const el = document.getElementById("message");
  el.textContent = text;
  el.className = kind;
}

// Format a UTC timestamp into the viewer's local time.
function fmtTime(iso) {
  return iso ? new Date(iso).toLocaleString() : "never";
}

// Shorten a long hash for display: "a1b2c3d4...9f8e"
function shortHash(h) {
  return h ? h.slice(0, 10) + "..." + h.slice(-6) : "-";
}

// Build one table cell SAFELY. textContent = plain text, no HTML executed (XSS-safe).
function cell(text, className) {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

// A cell that holds a colored badge (severity / change type).
function badgeCell(text, className) {
  const td = document.createElement("td");
  const span = document.createElement("span");
  span.textContent = text;
  span.className = className;
  td.appendChild(span);
  return td;
}

function emptyRow(tbody, cols, text) {
  const tr = document.createElement("tr");
  const td = cell(text, "empty");
  td.colSpan = cols;
  tr.appendChild(td);
  tbody.appendChild(tr);
}

// ===== LOADING DATA FROM THE API =============================================

async function loadStatus() {
  const s = await api("GET", "/api/status");
  document.getElementById("s-files").textContent  = s.files_tracked;
  document.getElementById("s-high").textContent   = s.events.HIGH;
  document.getElementById("s-medium").textContent = s.events.MEDIUM;
  document.getElementById("s-low").textContent    = s.events.LOW;
  const input = document.getElementById("folder");
  if (s.folder && !input.value) input.value = s.folder;
  document.getElementById("meta").textContent = s.baseline_set_at
    ? "Baseline: " + fmtTime(s.baseline_set_at) + "   |   Last scan: " + fmtTime(s.last_scan)
    : "No baseline set yet.";
}

async function loadEvents() {
  const sev = document.getElementById("filter").value;
  const events = await api("GET", "/api/events" + (sev ? "?severity=" + sev : ""));
  const tbody = document.getElementById("events");
  tbody.replaceChildren();
  if (events.length === 0) return emptyRow(tbody, 6, "No changes detected. All files match the baseline.");
  for (const e of events) {
    const tr = document.createElement("tr");
    tr.append(
      cell(fmtTime(e.detected_at)),
      badgeCell(e.severity, "badge " + e.severity),
      badgeCell(e.change_type, "type " + e.change_type),
      cell(e.path, "mono"),
      cell(shortHash(e.old_hash), "hash mono"),
      cell(shortHash(e.new_hash), "hash mono"),
    );
    tbody.appendChild(tr);
  }
}

async function loadFiles() {
  const files = await api("GET", "/api/files");
  const tbody = document.getElementById("files");
  tbody.replaceChildren();
  if (files.length === 0) return emptyRow(tbody, 3, "No baseline yet.");
  for (const f of files) {
    const tr = document.createElement("tr");
    tr.append(cell(f.path, "mono"), cell(f.size + " B"), cell(f.sha256, "hash mono"));
    tbody.appendChild(tr);
  }
}

async function refresh() {
  try { await Promise.all([loadStatus(), loadEvents(), loadFiles()]); }
  catch (err) { say(err.message, "err"); }
}

// ===== BUTTON ACTIONS ========================================================

// Disable buttons while a request runs so nobody double-clicks.
async function run(action) {
  const buttons = document.querySelectorAll("button");
  buttons.forEach(b => b.disabled = true);
  try { await action(); }
  catch (err) { say(err.message, "err"); }
  finally { buttons.forEach(b => b.disabled = false); }
}

document.getElementById("btn-baseline").addEventListener("click", () => run(async () => {
  const path = document.getElementById("folder").value;
  if (!confirm("Set a NEW baseline? The current state of the folder becomes the trusted state.")) return;
  const r = await api("POST", "/api/baseline", { path });
  say(r.message + (r.skipped.length ? " Skipped: " + r.skipped.join(", ") : ""), "ok");
  await refresh();
}));

document.getElementById("btn-scan").addEventListener("click", () => run(async () => {
  const r = await api("POST", "/api/scan");
  say(r.message, r.differences ? "err" : "ok");
  await refresh();
}));

document.getElementById("filter").addEventListener("change", () => loadEvents().catch(e => say(e.message, "err")));

// Load everything when the page opens.
refresh();
</script>
</body>
</html>
"""


# =============================================================================
# SECTION 6 - START SERVER
# =============================================================================
# This block only runs when you start the file directly (python fileguard.py),
# not when the tests import it.

if __name__ == "__main__":
    import uvicorn   # the web server that actually listens for HTTP requests
    print(f"FileGuard running -> open http://{HOST}:{PORT}  (Ctrl+C to stop)")
    uvicorn.run(app, host=HOST, port=PORT)
