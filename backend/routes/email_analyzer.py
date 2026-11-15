from flask import Blueprint, request, current_app
from backend.utils.responses import api_success, api_error
from backend.utils.validators import validate_email_input
from backend.services.email_analyzer import analyze_email
from backend.database import save_scan, save_email_analysis

email_analyzer_bp = Blueprint("email_analyzer", __name__)


@email_analyzer_bp.route("/email/analyze", methods=["POST"])
def analyze_email_route():
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return api_error(message="Request body harus berupa JSON object dengan properti 'subject' dan 'body'.", status_code=400)

    is_valid, err_msg = validate_email_input(data)
    if not is_valid:
        return api_error(message=err_msg, status_code=400)

    subject = data.get("subject", "").strip()
    body = data.get("body", "").strip()
    sender = data.get("sender", "").strip()

    db_path = current_app.config.get("DATABASE")
    result = analyze_email(subject=subject, body=body, sender=sender, db_path=db_path)

    # Save to unified scans table (DO NOT store raw body for privacy)
    scan_id = save_scan(
        db_path,
        result,
        scan_type="email",
        target=subject[:150],
        details={
            "sender": sender,
            "suspicious_keywords": result.get("suspicious_keywords", []),
            "extracted_urls": result.get("extracted_urls", [])
        }
    )
    result["id"] = scan_id

    # Save to dedicated email_analyses table
    try:
        save_email_analysis(
            db_path=db_path,
            scan_id=scan_id,
            subject=subject[:255],
            sender=sender[:255],
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            keywords=result.get("suspicious_keywords", []),
            extracted_urls=result.get("extracted_urls", [])
        )
    except Exception:
        pass

    return api_success(data=result, message="Email analysis completed successfully", status_code=200)
