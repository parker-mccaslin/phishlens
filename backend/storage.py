"""SQLite history stored under the XDG data directory."""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path


def database_path() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "phishlens" / "history.sqlite3"


def connect() -> sqlite3.Connection:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    connection = sqlite3.connect(path)
    path.chmod(0o600)
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE IF NOT EXISTS analyses (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, text TEXT NOT NULL, report TEXT NOT NULL)")
    connection.commit()
    return connection


def save_analysis(item_id: str, created_at: str, text: str, report: dict) -> None:
    with connect() as db:
        db.execute("INSERT INTO analyses VALUES (?, ?, ?, ?)", (item_id, created_at, text, json.dumps(report)))


def list_analyses() -> list[dict]:
    with connect() as db:
        rows = db.execute("SELECT id, created_at, text, report FROM analyses ORDER BY created_at DESC LIMIT 500").fetchall()
    return [{"id": row["id"], "created_at": row["created_at"], "text": row["text"], "report": json.loads(row["report"])} for row in rows]


def delete_history() -> None:
    with connect() as db:
        db.execute("DELETE FROM analyses")
