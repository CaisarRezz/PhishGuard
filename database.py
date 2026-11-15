"""Database interface bridge.
Maintains backward compatibility with legacy calls while delegating to backend.database.
"""
from backend.database import (
    get_connection,
    init_db,
    save_scan,
    row_to_dict,
    get_scan,
    get_recent_scans,
    get_history,
    get_watchlist,
    get_watchlist_match,
    add_watchlist_entry,
    delete_watchlist_entry,
    get_file_hash_match,
    add_file_hash,
    get_file_hashes_count,
    save_email_analysis,
    get_dashboard_stats,
    get_dashboard_activity
)

__all__ = [
    "get_connection",
    "init_db",
    "save_scan",
    "row_to_dict",
    "get_scan",
    "get_recent_scans",
    "get_history",
    "get_watchlist",
    "get_watchlist_match",
    "add_watchlist_entry",
    "delete_watchlist_entry",
    "get_file_hash_match",
    "add_file_hash",
    "get_file_hashes_count",
    "save_email_analysis",
    "get_dashboard_stats",
    "get_dashboard_activity"
]
