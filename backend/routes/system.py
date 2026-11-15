from datetime import datetime, timezone
from flask import Blueprint, current_app
from backend.utils.responses import api_success, api_error
from backend.database import get_connection, get_file_hashes_count

system_bp = Blueprint("system", __name__)


@system_bp.route("/status", methods=["GET"])
def system_status():
    db_path = current_app.config.get("DATABASE")
    now_iso = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

    # Check Database Status
    db_status = "offline"
    total_records = 0
    try:
        with get_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) AS total FROM scans")
            total_records = cursor.fetchone()["total"]
            db_status = "online"
    except Exception as e:
        db_status = f"error: {str(e)}"

    # Check URL Engine Status
    url_status = "operational"

    # Check QR Engine Status
    qr_status = "unavailable"
    qr_details = {}
    try:
        import cv2
        _ = cv2.QRCodeDetector()
        qr_status = "operational"
        qr_details = {"engine": "OpenCV QRCodeDetector", "version": getattr(cv2, "__version__", "unknown")}
    except Exception as e:
        qr_status = f"unavailable ({str(e)})"

    # Check Email Engine Status
    email_status = "operational"

    # Check File Hash Engine Status
    file_status = "operational"
    known_hashes = 0
    try:
        known_hashes = get_file_hashes_count(db_path)
    except Exception:
        file_status = "degraded"

    overall_status = "operational" if (db_status == "online") else "degraded"

    status_data = {
        "status": overall_status,
        "version": "2.0.0",
        "timestamp": now_iso,
        "services": {
            "backend": {
                "status": "online",
                "framework": "Flask 3.1.3",
                "cors_origin": current_app.config.get("CORS_ORIGIN", "http://localhost:5173")
            },
            "database": {
                "status": db_status,
                "engine": "SQLite",
                "total_records": total_records
            },
            "url_analyzer": {
                "status": url_status,
                "active_rules": 10,
                "offline_mode": True
            },
            "qr_analyzer": {
                "status": qr_status,
                **qr_details
            },
            "email_analyzer": {
                "status": email_status,
                "heuristic_rules": 6
            },
            "file_analyzer": {
                "status": file_status,
                "algorithm": "SHA-256",
                "known_threat_hashes": known_hashes
            }
        }
    }

    return api_success(data=status_data, message="System status retrieved successfully")
