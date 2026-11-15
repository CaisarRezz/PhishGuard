import sqlite3
from flask import Blueprint, request, current_app
from backend.utils.responses import api_success, api_error
from backend.utils.validators import validate_watchlist_input
from backend.database import get_watchlist, add_watchlist_entry, delete_watchlist_entry

watchlist_bp = Blueprint("watchlist", __name__)


@watchlist_bp.route("/watchlist", methods=["GET"])
def list_watchlist():
    search = request.args.get("search", "").strip()
    db_path = current_app.config.get("DATABASE")
    items = get_watchlist(db_path, search=search)
    return api_success(
        data={"total": len(items), "items": items},
        message="Watchlist retrieved successfully",
        status_code=200
    )


@watchlist_bp.route("/watchlist", methods=["POST"])
def create_watchlist():
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return api_error(message="Request body harus berupa JSON object.", status_code=400)

    is_valid, err_msg = validate_watchlist_input(data)
    if not is_valid:
        return api_error(message=err_msg, status_code=400)

    target = data.get("target", "").strip()
    threat_category = data.get("threat_category", "").strip()
    description = data.get("description", "").strip()
    source = data.get("source", "Manual Entry").strip()

    db_path = current_app.config.get("DATABASE")
    try:
        entry_id = add_watchlist_entry(
            db_path=db_path,
            target=target,
            threat_category=threat_category,
            description=description,
            source=source
        )
    except sqlite3.IntegrityError:
        return api_error(message="Target ini sudah terdaftar dalam watchlist.", status_code=409)
    except Exception as e:
        return api_error(message=f"Gagal menambahkan entri watchlist: {str(e)}", status_code=500)

    from backend.database import get_connection
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM watchlist WHERE id = ?", (entry_id,)).fetchone()
        created_entry = dict(row) if row else {"id": entry_id, "target": target}

    return api_success(data=created_entry, message="Watchlist entry created successfully", status_code=201)


@watchlist_bp.route("/watchlist/<int:entry_id>", methods=["DELETE"])
def remove_watchlist(entry_id: int):
    db_path = current_app.config.get("DATABASE")
    deleted = delete_watchlist_entry(db_path, entry_id)

    if not deleted:
        return api_error(message=f"Entry watchlist dengan ID {entry_id} tidak ditemukan.", status_code=404)

    return api_success(data={"deleted_id": entry_id}, message="Watchlist entry deleted successfully", status_code=200)
