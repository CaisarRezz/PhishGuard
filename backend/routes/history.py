from flask import Blueprint, request, current_app
from backend.utils.responses import api_success, api_error
from backend.database import get_history, get_scan

history_bp = Blueprint("history", __name__)


@history_bp.route("/history", methods=["GET"])
def list_history():
    scan_type = request.args.get("type", "all").strip()
    risk = request.args.get("risk", "all").strip()
    search = request.args.get("search", "").strip()

    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        page = 1

    try:
        per_page = int(request.args.get("per_page", 10))
    except ValueError:
        per_page = 10

    db_path = current_app.config.get("DATABASE")
    try:
        items, pagination = get_history(
            db_path=db_path,
            scan_type=scan_type,
            risk_level=risk,
            search=search,
            page=page,
            per_page=per_page
        )
        return api_success(
            data={"items": items, "pagination": pagination},
            message="Scan history retrieved successfully",
            status_code=200
        )
    except Exception as e:
        return api_error(message=f"Gagal mengambil riwayat scan: {str(e)}", status_code=500)


@history_bp.route("/history/<int:scan_id>", methods=["GET"])
def get_history_detail(scan_id: int):
    db_path = current_app.config.get("DATABASE")
    record = get_scan(db_path, scan_id)

    if not record:
        return api_error(message=f"Riwayat pemeriksaan dengan ID {scan_id} tidak ditemukan.", status_code=404)

    return api_success(data=record, message="Scan record retrieved successfully", status_code=200)
