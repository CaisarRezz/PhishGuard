import json
import sqlite3
from datetime import datetime, timezone


def get_connection(db_path):
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path):
    with get_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                hostname TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()


def save_scan(db_path, result):
    created_at = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    with get_connection(db_path) as conn:
        cursor = conn.execute("""
            INSERT INTO scans
            (url, hostname, risk_score, risk_level, recommendation, findings_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            result["url"], result["hostname"], result["risk_score"],
            result["risk_level"], result["recommendation"],
            json.dumps(result["findings"]), created_at
        ))
        conn.commit()
        return cursor.lastrowid


def row_to_dict(row):
    if row is None:
        return None
    data = dict(row)
    data["findings"] = json.loads(data.pop("findings_json"))
    return data


def get_scan(db_path, scan_id):
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return row_to_dict(row)


def get_recent_scans(db_path, limit=100):
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [row_to_dict(row) for row in rows]
