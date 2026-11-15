from flask import Blueprint, request, current_app
from backend.utils.responses import api_success, api_error
from backend.utils.validators import validate_url
from backend.services.url_analyzer import analyze_url
from backend.database import save_scan

url_scanner_bp = Blueprint("url_scanner", __name__)


@url_scanner_bp.route("/url/scan", methods=["POST"])
@url_scanner_bp.route("/scan", methods=["POST"])
def scan_url():
    # Support both JSON payload and Form Data
    if request.is_json:
        data = request.get_json(silent=True) or {}
        raw_url = data.get("url", "")
    else:
        raw_url = request.form.get("url", "")

    is_valid, err_msg = validate_url(raw_url)
    if not is_valid:
        return api_error(message=err_msg, status_code=400)

    db_path = current_app.config.get("DATABASE")
    result = analyze_url(raw_url, db_path=db_path)

    if result.get("error"):
        return api_error(message=result["error"], status_code=400)

    scan_id = save_scan(db_path, result, scan_type="url", target=result["url"])
    result["id"] = scan_id

    return api_success(data=result, message="URL analysis completed successfully", status_code=200)
