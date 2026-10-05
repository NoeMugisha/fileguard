"""
Automated tests for FileGuard.

Run them from the project folder (VS Code -> Terminal -> PowerShell, venv active):
    pytest -v

Each test builds a throwaway folder + database in a temporary directory
(pytest's "tmp_path"), so your real files and fileguard.db are never touched.
"""

import pytest
from fastapi.testclient import TestClient

import fileguard


# ---------- Fixtures: setup code that tests can ask for by name -------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    """A fake browser that talks to the API, using a temporary database."""
    monkeypatch.setattr(fileguard, "DB_PATH", tmp_path / "test.db")
    # base_url = localhost, because the app only accepts localhost (DNS-rebinding defence)
    return TestClient(fileguard.app, base_url="http://127.0.0.1")


@pytest.fixture
def folder(tmp_path):
    """A small folder to monitor, with two harmless files."""
    d = tmp_path / "monitored"
    d.mkdir()
    (d / "notes.txt").write_text("hello")
    (d / "settings.ini").write_text("debug=false")
    return d


# ---------- Unit tests: the scan engine on its own --------------------------

def test_sha256_known_value(tmp_path):
    """SHA-256 of 'hello' is a published, fixed value. Proves hashing is correct."""
    f = tmp_path / "a.txt"
    f.write_text("hello")
    assert fileguard.sha256_file(f) == (
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")


def test_compare_detects_all_three_change_types():
    baseline = {"keep.txt": "aaa", "edit.txt": "bbb", "gone.txt": "ccc"}
    current  = {"keep.txt": "aaa", "edit.txt": "XXX", "new.txt": "ddd"}
    found = {(c["path"], c["change_type"]) for c in fileguard.compare(baseline, current)}
    assert found == {("edit.txt", "MODIFIED"), ("gone.txt", "DELETED"), ("new.txt", "ADDED")}


def test_no_changes_means_no_events():
    same = {"a.txt": "111", "b.txt": "222"}
    assert fileguard.compare(same, dict(same)) == []


@pytest.mark.parametrize("path, change, expected", [
    ("payload.EXE", "ADDED",    "HIGH"),    # extension check is case-insensitive
    ("run.ps1",     "MODIFIED", "HIGH"),
    ("photo.jpg",   "DELETED",  "MEDIUM"),
    ("report.docx", "MODIFIED", "MEDIUM"),
    ("report.docx", "ADDED",    "LOW"),
])
def test_severity_rules(path, change, expected):
    assert fileguard.severity_for(path, change) == expected


# ---------- Input validation tests ------------------------------------------

def test_rejects_missing_folder(tmp_path):
    with pytest.raises(ValueError):
        fileguard.validate_folder(str(tmp_path / "does-not-exist"))


def test_rejects_file_instead_of_folder(folder):
    with pytest.raises(ValueError):
        fileguard.validate_folder(str(folder / "notes.txt"))


def test_rejects_empty_input():
    with pytest.raises(ValueError):
        fileguard.validate_folder("   ")


# ---------- API tests: the full flow, like the dashboard does it ------------

def test_full_flow_detects_tampering(client, folder):
    r = client.post("/api/baseline", json={"path": str(folder)})
    assert r.status_code == 200
    assert r.json()["files"] == 2

    # Simulate an attacker: edit a config, drop a script, delete a note.
    (folder / "settings.ini").write_text("debug=true")
    (folder / "backdoor.ps1").write_text("Write-Host pwned")
    (folder / "notes.txt").unlink()

    r = client.post("/api/scan")
    assert r.status_code == 200
    assert r.json()["new_events"] == 3

    events = {e["path"]: (e["change_type"], e["severity"]) for e in client.get("/api/events").json()}
    assert events == {
        "settings.ini": ("MODIFIED", "HIGH"),
        "backdoor.ps1": ("ADDED",    "HIGH"),
        "notes.txt":    ("DELETED",  "MEDIUM"),
    }
    assert client.get("/api/status").json()["events"] == {"HIGH": 2, "MEDIUM": 1, "LOW": 0}


def test_rescan_does_not_duplicate_events(client, folder):
    client.post("/api/baseline", json={"path": str(folder)})
    (folder / "notes.txt").write_text("changed")
    assert client.post("/api/scan").json()["new_events"] == 1
    assert client.post("/api/scan").json()["new_events"] == 0   # same change, no new alert


def test_scan_without_baseline_is_rejected(client):
    r = client.post("/api/scan")
    assert r.status_code == 400


def test_baseline_rejects_bad_path(client, tmp_path):
    r = client.post("/api/baseline", json={"path": str(tmp_path / "nope")})
    assert r.status_code == 400
    assert "not found" in r.json()["detail"].lower()


def test_severity_filter_rejects_garbage(client):
    r = client.get("/api/events?severity=DROP TABLE events")
    assert r.status_code == 400


def test_non_localhost_host_header_is_blocked(tmp_path, monkeypatch):
    """DNS-rebinding defence: requests addressed to another host name get refused."""
    monkeypatch.setattr(fileguard, "DB_PATH", tmp_path / "test.db")
    evil = TestClient(fileguard.app, base_url="http://evil.example.com")
    assert evil.get("/api/status").status_code == 400
