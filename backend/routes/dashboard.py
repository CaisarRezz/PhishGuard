from flask import Blueprint, request, current_app
from backend.utils.responses import api_success, api_error
from backend.database import get_dashboard_stats, get_dashboard_activity

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard/stats", methods=["GET"])
def dashboard_stats():
    db_path = current_app.config.get("DATABASE")
    try:
        stats = get_dashboard_stats(db_path)
        return api_success(data=stats, message="Dashboard statistics retrieved successfully", status_code=200)
    except Exception as e:
        return api_error(message=f"Gagal mengambil statistik dashboard: {str(e)}", status_code=500)


@dashboard_bp.route("/dashboard/activity", methods=["GET"])
def dashboard_activity():
    period = request.args.get("period", "7d").lower()
    if period not in ("7d", "30d"):
        period = "7d"

    db_path = current_app.config.get("DATABASE")
    try:
        activity_data = get_dashboard_activity(db_path, period=period)
        return api_success(data=activity_data, message="Activity timeline retrieved successfully", status_code=200)
    except Exception as e:
        return api_error(message=f"Gagal mengambil data aktivitas: {str(e)}", status_code=500)
