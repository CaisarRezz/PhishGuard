"""PhishGuard Database Management Module.
Uses SQLite to store scans and threat watchlist entries.
"""
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "instance" / "phishguard.db"


def get_db(db_path=None):
    """Return an active SQLite connection with row factory enabled."""
    path = db_path or DB_PATH
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=None):
    """Initialize SQLite database tables for scans and watchlist."""
    conn = get_db(db_path)
    cursor = conn.cursor()

    # Table 1: Scans
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    
    
    # Check and migrate existing scans table
    cursor.execute("PRAGMA table_info(scans)")
    existing_columns = {
        row["name"] for row in cursor.fetchall()
}

    if "scan_type" not in existing_columns:
        cursor.execute("""
            ALTER TABLE scans
            ADD COLUMN scan_type TEXT NOT NULL DEFAULT 'Unknown'
        """)


    # Table 2: Watchlist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # Seed initial watchlist if empty
    cursor.execute("SELECT COUNT(*) FROM watchlist")
    if cursor.fetchone()[0] == 0:
        now = datetime.now().isoformat()
        initial_domains = [
            ("phishing-bank-login.com", "Known fake banking portal", now),
            ("apple-id-verify.top", "Apple ID spoofing landing page", now),
            ("paypal-security-update.com", "Deceptive financial phishing site", now),
        ]
        cursor.executemany(
            "INSERT INTO watchlist (domain, description, created_at) VALUES (?, ?, ?)",
            initial_domains
        )

    conn.commit()
    conn.close()


def save_scan(scan_type: str, target: str, risk_score: int, risk_level: str, db_path=None) -> int:
    """Save a scan record into the database."""
    conn = get_db(db_path)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO scans (scan_type, target, risk_score, risk_level, created_at) VALUES (?, ?, ?, ?, ?)",
        (scan_type, target, risk_score, risk_level, now)
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_scans(limit=100, db_path=None):
    """Retrieve recent scans ordered by ID descending."""
    conn = get_db(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, scan_type, target, risk_score, risk_level, created_at FROM scans ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_dashboard_stats(db_path=None):
    """Calculate aggregate statistics for the dashboard."""
    conn = get_db(db_path)
    cursor = conn.cursor()

    total_scans = cursor.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    high_risk = cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'High'").fetchone()[0]
    medium_risk = cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'Medium'").fetchone()[0]
    low_risk = cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'Low'").fetchone()[0]
    watchlist_count = cursor.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0]

    cursor.execute(
        "SELECT id, scan_type, target, risk_score, risk_level, created_at FROM scans ORDER BY id DESC LIMIT 5"
    )
    recent_scans = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return {
        "total_scans": total_scans,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk,
        "watchlist_count": watchlist_count,
        "recent_scans": recent_scans
    }


def get_watchlist(db_path=None):
    """Retrieve all entries from threat watchlist."""
    conn = get_db(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, domain, description, created_at FROM watchlist ORDER BY id DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def add_watchlist_entry(domain: str, description: str = "", db_path=None):
    """Add a new domain to the threat watchlist."""
    conn = get_db(db_path)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    clean_domain = domain.strip().lower()
    cursor.execute(
        "INSERT INTO watchlist (domain, description, created_at) VALUES (?, ?, ?)",
        (clean_domain, description.strip(), now)
    )
    entry_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return {"id": entry_id, "domain": clean_domain, "description": description.strip(), "created_at": now}


def delete_watchlist_entry(entry_id: int, db_path=None) -> bool:
    """Delete a watchlist entry by ID."""
    conn = get_db(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM watchlist WHERE id = ?", (entry_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def check_watchlist(target_or_domain: str, db_path=None) -> bool:
    """Check if a domain or URL hostname is in the watchlist."""
    conn = get_db(db_path)
    cursor = conn.cursor()
    clean_target = (target_or_domain or "").strip().lower()
    cursor.execute("SELECT domain FROM watchlist")
    domains = [r["domain"].lower() for r in cursor.fetchall()]
    conn.close()

    for d in domains:
        if d in clean_target:
            return True
    return False
