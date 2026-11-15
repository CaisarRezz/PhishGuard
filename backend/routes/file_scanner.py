from flask import Blueprint, request, current_app
from backend.utils.responses import api_success, api_error
from backend.utils.validators import validate_file_upload
from backend.services.file_analyzer import analyze_file
from backend.database import save_scan
from backend.config import MAX_FILE_SCAN_SIZE

file_scanner_bp = Blueprint("file_scanner", __name__)


@file_scanner_bp.route("/file/scan", methods=["POST"])
def scan_file():
    file_obj = request.files.get("file")

    if not file_obj or file_obj.filename == "":
        return api_error(message="File tidak ditemukan dalam request upload.", status_code=400)

    # Validate file size (max 10MB)
    is_valid, err_msg = validate_file_upload(file_obj, MAX_FILE_SCAN_SIZE)
    if not is_valid:
        status_code = 413 if "melebihi batas maksimal" in err_msg else 400
        return api_error(message=err_msg, status_code=status_code)

    filename = file_obj.filename
    db_path = current_app.config.get("DATABASE")

    try:
        result = analyze_file(file_obj.stream, filename=filename, db_path=db_path)
    finally:
        # Guarantee closure of file stream and release of memory / temp buffers
        file_obj.close()

    scan_id = save_scan(
        db_path,
        result,
        scan_type="file",
        target=filename,
        details={
            "sha256": result["sha256"],
            "reputation": result["reputation"],
            "file_size": result["file_size"]
        }
    )
    result["id"] = scan_id

    msg = "Malicious signature matched in threat database" if result["reputation"] == "Malicious" else "File hash calculated. No matching threat found in local signature database."
    return api_success(data=result, message=msg, status_code=200)
