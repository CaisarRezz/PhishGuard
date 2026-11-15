import json
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path


def get_connection(db_path):
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        # 1. Base scans table (preserve existing schema)
        cursor.execute("""
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

        # Additive migration: check if scan_type, target, details_json exist
        cursor.execute("PRAGMA table_info(scans)")
        columns = [row["name"] for row in cursor.fetchall()]

        if "scan_type" not in columns:
            cursor.execute("ALTER TABLE scans ADD COLUMN scan_type TEXT DEFAULT 'url'")
        if "target" not in columns:
            cursor.execute("ALTER TABLE scans ADD COLUMN target TEXT")
        if "details_json" not in columns:
            cursor.execute("ALTER TABLE scans ADD COLUMN details_json TEXT")

        # Backfill existing records if scan_type or target is null
        cursor.execute("UPDATE scans SET scan_type = 'url' WHERE scan_type IS NULL")
        cursor.execute("UPDATE scans SET target = url WHERE target IS NULL")

        # Create indexes on scans table
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_scan_type ON scans(scan_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans(risk_level)")

        # 2. Watchlist table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS watchlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL UNIQUE,
                threat_category TEXT NOT NULL,
                description TEXT,
                source TEXT,
                date_added TEXT NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_watchlist_target ON watchlist(target)")

        # 3. File Hashes table (known malicious threat intelligence)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256 TEXT NOT NULL UNIQUE,
                threat_name TEXT NOT NULL,
                description TEXT,
                source TEXT,
                date_added TEXT NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_hashes_sha256 ON file_hashes(sha256)")

        # 4. Email Analyses table (store analysis metadata without raw email body)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS email_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                subject TEXT,
                sender TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                suspicious_keywords_json TEXT,
                extracted_urls_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_analyses_scan_id ON email_analyses(scan_id)")

        # Seed initial Threat Watchlist if empty
        cursor.execute("SELECT COUNT(*) AS count FROM watchlist")
        if cursor.fetchone()["count"] == 0:
            now_iso = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
            initial_watchlist = [
                ("phishing-bank-login.com", "Credential Harvesting", "Known fake banking credential harvesting domain", "PhishGuard Threat Intel", now_iso),
                ("apple-id-verify.top", "Phishing", "Spoofed Apple ID verification landing page", "PhishGuard Threat Intel", now_iso),
                ("paypal-security-update.com", "Phishing", "Deceptive financial institution phishing portal", "PhishGuard Threat Intel", now_iso)
            ]
            cursor.executemany("""
                INSERT INTO watchlist (target, threat_category, description, source, date_added)
                VALUES (?, ?, ?, ?, ?)
            """, initial_watchlist)

        # Seed initial File Hashes if empty
        cursor.execute("SELECT COUNT(*) AS count FROM file_hashes")
        if cursor.fetchone()["count"] == 0:
            now_iso = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
            initial_hashes = [
                # EICAR standard antivirus test pattern
                ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Standard-AV-Test-File", "Standard antivirus test signature simulating malicious payload", "EICAR / PhishGuard", now_iso),
                # WannaCry dropper hash
                ("ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", "WannaCry.Ransomware.Dropper", "Known ransomware payload hash", "Threat Intel Feed", now_iso),
                # Emotet banking trojan
                ("38f3f88f240ba6512bc5566fcf8ff9f929bb0840b2b8c3ac29237ec6891eb6a3", "Emotet.BankingTrojan", "Known banking trojan binary hash", "Threat Intel Feed", now_iso)
            ]
            cursor.executemany("""
                INSERT INTO file_hashes (sha256, threat_name, description, source, date_added)
                VALUES (?, ?, ?, ?, ?)
            """, initial_hashes)

        conn.commit()


def row_to_dict(row):
    if row is None:
        return None
    data = dict(row)
    if "findings_json" in data and data["findings_json"]:
        try:
            data["findings"] = json.loads(data.pop("findings_json"))
        except Exception:
            data["findings"] = []
    elif "findings_json" in data:
        data.pop("findings_json")
        data["findings"] = []

    if "details_json" in data and data["details_json"]:
        try:
            data["details"] = json.loads(data.pop("details_json"))
        except Exception:
            data["details"] = None
    elif "details_json" in data:
        data.pop("details_json")
        data["details"] = None

    return data


def save_scan(db_path, result, scan_type="url", target=None, details=None):
    created_at = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    url_val = result.get("url") or target or ""
    hostname_val = result.get("hostname") or ""
    target_val = target or result.get("url") or result.get("target") or ""
    findings = result.get("findings", [])

    with get_connection(db_path) as conn:
        cursor = conn.execute("""
            INSERT INTO scans
            (url, hostname, risk_score, risk_level, recommendation, findings_json, scan_type, target, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            url_val,
            hostname_val,
            result.get("risk_score", 0),
            result.get("risk_level", "Low"),
            result.get("recommendation", ""),
            json.dumps(findings),
            scan_type,
            target_val,
            json.dumps(details) if details else None,
            created_at
        ))
        conn.commit()
        return cursor.lastrowid


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


def get_history(db_path, scan_type=None, risk_level=None, search=None, page=1, per_page=10):
    page = max(1, int(page))
    per_page = max(1, min(100, int(per_page)))
    offset = (page - 1) * per_page

    query_conditions = []
    params = []

    if scan_type and scan_type.lower() != "all":
        query_conditions.append("scan_type = ?")
        params.append(scan_type.lower())

    if risk_level and risk_level.lower() != "all":
        query_conditions.append("LOWER(risk_level) = ?")
        params.append(risk_level.lower())

    if search and search.strip():
        search_pattern = f"%{search.strip()}%"
        query_conditions.append("(target LIKE ? OR hostname LIKE ? OR recommendation LIKE ?)")
        params.extend([search_pattern, search_pattern, search_pattern])

    where_clause = ""
    if query_conditions:
        where_clause = "WHERE " + " AND ".join(query_conditions)

    with get_connection(db_path) as conn:
        # Count total items matching filter
        count_cursor = conn.execute(f"SELECT COUNT(*) AS total FROM scans {where_clause}", params)
        total_items = count_cursor.fetchone()["total"]

        # Fetch paginated items
        fetch_params = params + [per_page, offset]
        rows = conn.execute(
            f"SELECT * FROM scans {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            fetch_params
        ).fetchall()

    items = [row_to_dict(row) for row in rows]
    total_pages = (total_items + per_page - 1) // per_page if total_items > 0 else 1

    pagination = {
        "page": page,
        "per_page": per_page,
        "total_items": total_items,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1
    }

    return items, pagination


# Watchlist Operations
def get_watchlist(db_path, search=None):
    with get_connection(db_path) as conn:
        if search and search.strip():
            pat = f"%{search.strip()}%"
            rows = conn.execute(
                "SELECT * FROM watchlist WHERE target LIKE ? OR threat_category LIKE ? OR description LIKE ? ORDER BY id DESC",
                (pat, pat, pat)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM watchlist ORDER BY id DESC").fetchall()
    return [dict(row) for row in rows]


def get_watchlist_match(db_path, target_or_host):
    if not target_or_host:
        return None
    target_clean = target_or_host.strip().lower()
    with get_connection(db_path) as conn:
        # Exact match on target (domain, hostname, or full url)
        row = conn.execute(
            "SELECT * FROM watchlist WHERE LOWER(target) = ? LIMIT 1",
            (target_clean,)
        ).fetchone()
        if row:
            return dict(row)
        # Check if target ends with the watchlist domain (e.g. sub.domain.com matching domain.com)
        row = conn.execute(
            "SELECT * FROM watchlist WHERE ? LIKE '%' || LOWER(target) LIMIT 1",
            (target_clean,)
        ).fetchone()
        return dict(row) if row else None


def add_watchlist_entry(db_path, target, threat_category, description="", source="Manual"):
    date_added = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    target_clean = target.strip().lower()
    with get_connection(db_path) as conn:
        cursor = conn.execute("""
            INSERT INTO watchlist (target, threat_category, description, source, date_added)
            VALUES (?, ?, ?, ?, ?)
        """, (target_clean, threat_category.strip(), description.strip(), source.strip(), date_added))
        conn.commit()
        return cursor.lastrowid


def delete_watchlist_entry(db_path, entry_id):
    with get_connection(db_path) as conn:
        cursor = conn.execute("DELETE FROM watchlist WHERE id = ?", (entry_id,))
        conn.commit()
        return cursor.rowcount > 0


# File Hashes Operations
def get_file_hash_match(db_path, sha256_hash):
    if not sha256_hash:
        return None
    hash_clean = sha256_hash.strip().lower()
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM file_hashes WHERE LOWER(sha256) = ? LIMIT 1", (hash_clean,)).fetchone()
        return dict(row) if row else None


def add_file_hash(db_path, sha256, threat_name, description="", source="Manual"):
    date_added = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    with get_connection(db_path) as conn:
        cursor = conn.execute("""
            INSERT INTO file_hashes (sha256, threat_name, description, source, date_added)
            VALUES (?, ?, ?, ?, ?)
        """, (sha256.strip().lower(), threat_name.strip(), description.strip(), source.strip(), date_added))
        conn.commit()
        return cursor.lastrowid


def get_file_hashes_count(db_path):
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT COUNT(*) AS total FROM file_hashes").fetchone()
        return row["total"] if row else 0


# Email Analysis Operations
def save_email_analysis(db_path, scan_id, subject, sender, risk_score, risk_level, keywords, extracted_urls):
    created_at = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    with get_connection(db_path) as conn:
        cursor = conn.execute("""
            INSERT INTO email_analyses (scan_id, subject, sender, risk_score, risk_level, suspicious_keywords_json, extracted_urls_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            subject,
            sender or "",
            risk_score,
            risk_level,
            json.dumps(keywords),
            json.dumps(extracted_urls),
            created_at
        ))
        conn.commit()
        return cursor.lastrowid


# Dashboard Statistics Operations
def get_dashboard_stats(db_path):
    with get_connection(db_path) as conn:
        # Total scans
        total_scans_row = conn.execute("SELECT COUNT(*) AS total FROM scans").fetchone()
        total_scans = total_scans_row["total"] if total_scans_row else 0

        # Risk level counts
        risk_rows = conn.execute("""
            SELECT risk_level, COUNT(*) AS count
            FROM scans
            GROUP BY risk_level
        """).fetchall()

        risk_counts = {"High": 0, "Medium": 0, "Low": 0}
        for r in risk_rows:
            level = r["risk_level"]
            if level in risk_counts:
                risk_counts[level] = r["count"]

        # Watchlist matches count (count scans that found a watchlist match)
        wl_row = conn.execute("""
            SELECT COUNT(*) AS count FROM scans
            WHERE findings_json LIKE '%watchlist%' OR findings_json LIKE '%Watchlist%'
        """).fetchone()
        watchlist_matches = wl_row["count"] if wl_row else 0

        # Scans by type
        type_rows = conn.execute("""
            SELECT scan_type, COUNT(*) AS count
            FROM scans
            GROUP BY scan_type
        """).fetchall()

        scans_by_type = {"url": 0, "qr": 0, "email": 0, "file": 0}
        for t in type_rows:
            stype = t["scan_type"] or "url"
            scans_by_type[stype] = scans_by_type.get(stype, 0) + t["count"]

        # Suspicious URL count (URL scans with risk_score >= 30)
        suspicious_row = conn.execute("""
            SELECT COUNT(*) AS count FROM scans
            WHERE scan_type = 'url' AND risk_score >= 30
        """).fetchone()
        suspicious_urls = suspicious_row["count"] if suspicious_row else 0

        # Risk distribution with percentages
        risk_distribution = []
        for level in ["High", "Medium", "Low"]:
            cnt = risk_counts[level]
            pct = round((cnt / total_scans * 100), 1) if total_scans > 0 else 0.0
            risk_distribution.append({
                "level": level,
                "count": cnt,
                "percentage": pct
            })

        # Recent alerts (High risk items)
        alert_rows = conn.execute("""
            SELECT id, scan_type, target, risk_score, risk_level, created_at
            FROM scans
            WHERE risk_level = 'High'
            ORDER BY id DESC LIMIT 5
        """).fetchall()
        recent_alerts = [dict(row) for row in alert_rows]

        # Recent activities (Latest 10 items)
        activity_rows = conn.execute("""
            SELECT id, scan_type, target, risk_score, risk_level, created_at
            FROM scans
            ORDER BY id DESC LIMIT 10
        """).fetchall()
        recent_activities = [dict(row) for row in activity_rows]

    return {
        "summary": {
            "total_scans": total_scans,
            "high_risk_count": risk_counts["High"],
            "medium_risk_count": risk_counts["Medium"],
            "low_risk_count": risk_counts["Low"],
            "suspicious_url_count": suspicious_urls,
            "watchlist_matches": watchlist_matches
        },
        "scans_by_type": scans_by_type,
        "risk_distribution": risk_distribution,
        "recent_alerts": recent_alerts,
        "recent_activities": recent_activities
    }


def get_dashboard_activity(db_path, period="7d"):
    days = 30 if period == "30d" else 7
    now = datetime.now(timezone.utc).astimezone()
    # Generate list of dates in YYYY-MM-DD
    date_list = [(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days - 1, -1, -1)]

    with get_connection(db_path) as conn:
        start_date = date_list[0] + "T00:00:00"
        rows = conn.execute("""
            SELECT substr(created_at, 1, 10) AS scan_date, risk_level, COUNT(*) AS count
            FROM scans
            WHERE created_at >= ?
            GROUP BY scan_date, risk_level
        """, (start_date,)).fetchall()

    # Aggregate by date
    daily_data = {d: {"date": d, "total": 0, "high": 0, "medium": 0, "low": 0} for d in date_list}
    for row in rows:
        d = row["scan_date"]
        if d in daily_data:
            cnt = row["count"]
            rlevel = row["risk_level"]
            daily_data[d]["total"] += cnt
            if rlevel == "High":
                daily_data[d]["high"] += cnt
            elif rlevel == "Medium":
                daily_data[d]["medium"] += cnt
            elif rlevel == "Low":
                daily_data[d]["low"] += cnt

    timeline = [daily_data[d] for d in date_list]
    return {
        "period": f"{days}d",
        "timeline": timeline
    }
