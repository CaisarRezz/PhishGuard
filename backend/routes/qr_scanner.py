from flask import Blueprint, request, current_app
from backend.utils.responses import api_success, api_error
from backend.utils.validators import validate_file_upload
from backend.services.qr_analyzer import analyze_qr_code
from backend.database import save_scan
from backend.config import MAX_QR_FILE_SIZE, ALLOWED_IMAGE_EXTENSIONS

qr_scanner_bp = Blueprint("qr_scanner", __name__)


@qr_scanner_bp.route("/qr/scan", methods=["POST"])
def scan_qr():
    # Support both 'file' and 'image' field names
    file_obj = request.files.get("file") or request.files.get("image")

    if not file_obj or file_obj.filename == "":
        return api_error(message="File gambar QR code tidak ditemukan dalam request.", status_code=400)

    # Check extension
    is_valid, err_msg = validate_file_upload(file_obj, MAX_QR_FILE_SIZE, ALLOWED_IMAGE_EXTENSIONS)
    if not is_valid:
        status_code = 413 if "melebihi batas maksimal" in err_msg else 400
        return api_error(message=err_msg, status_code=status_code)

    # Read image bytes safely into memory
    image_bytes = file_obj.read()
    filename = file_obj.filename

    db_path = current_app.config.get("DATABASE")
    result = analyze_qr_code(image_bytes, filename=filename, db_path=db_path)

    if result.get("error"):
        return api_error(message=result["error"], status_code=500)

    if not result.get("decoded"):
        return api_error(message="QR code tidak dapat dideteksi atau gambar tidak terbaca.", status_code=400)

    # Save to unified scan history
    scan_id = save_scan(
        db_path,
        result,
        scan_type="qr",
        target=result.get("content") or filename,
        details={"filename": filename, "decoded": True, "is_url": result.get("is_url", False)}
    )
    result["id"] = scan_id

    msg = "QR code scanned and decoded successfully" if result.get("is_url") else "QR code scanned successfully (non-URL content)"
    return api_success(data=result, message=msg, status_code=200)
