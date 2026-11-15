"""PhishGuard - Unified Cybersecurity Threat Detection Platform.
Flask Web Server and REST API.
"""
from pathlib import Path
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from database import (
    init_db,
    save_scan,
    get_scans,
    get_dashboard_stats,
    get_watchlist,
    add_watchlist_entry,
    delete_watchlist_entry,
    DB_PATH
)
from analyzer import analyze_url, scan_qr_from_bytes, analyze_email

# Initialize Flask application
app = Flask(__name__)
app.secret_key = "phishguard-secret-key-security"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # Max 5 MB upload limit
app.config["DATABASE"] = str(DB_PATH)

# Ensure database tables exist
init_db(app.config["DATABASE"])


# ============================================================================
# WEB PAGES (Jinja2 Templates)
# ============================================================================

@app.route("/", methods=["GET"])
def dashboard():
    """Dashboard page showing threat stats and recent scans."""
    stats = get_dashboard_stats(app.config["DATABASE"])
    return render_template("index.html", stats=stats)


@app.route("/url-scanner", methods=["GET", "POST"])
def url_scanner():
    """URL Scanner page: form and visual inspection report."""
    result = None
    url_input = ""
    if request.method == "POST":
        url_input = request.form.get("url", "").strip()
        if not url_input:
            flash("Please enter a URL to analyze.", "error")
        else:
            result = analyze_url(url_input, db_path=app.config["DATABASE"])
            if result.get("valid"):
                save_scan("url", result["url"], result["risk_score"], result["risk_level"], db_path=app.config["DATABASE"])
            else:
                flash(result.get("error", "Invalid URL."), "error")

    return render_template("url_scanner.html", result=result, url_input=url_input)


@app.route("/qr-shield", methods=["GET", "POST"])
def qr_shield():
    """QR Shield page: image upload and QR link analysis."""
    result = None
    if request.method == "POST":
        if "file" not in request.files or not request.files["file"].filename:
            flash("Please choose a QR code image to upload.", "error")
        else:
            file = request.files["file"]
            try:
                # Read bytes in-memory without persisting temp files to disk
                file_bytes = file.read()
                result = scan_qr_from_bytes(file_bytes, db_path=app.config["DATABASE"])
                if result.get("decoded"):
                    save_scan("qr", result["content"], result["risk_score"], result["risk_level"], db_path=app.config["DATABASE"])
                else:
                    flash(result.get("error", "Failed to decode QR code."), "error")
            except Exception as e:
                flash(f"Error processing image: {str(e)}", "error")

    return render_template("qr_shield.html", result=result)


@app.route("/mailguard", methods=["GET", "POST"])
def mailguard():
    """MailGuard page: heuristic email body inspection."""
    result = None
    subject = ""
    body = ""
    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()
        if not body:
            flash("Please enter the email body text to analyze.", "error")
        else:
            result = analyze_email(subject, body, db_path=app.config["DATABASE"])
            target_label = subject or (body[:50] + "...")
            save_scan("email", target_label, result["risk_score"], result["risk_level"], db_path=app.config["DATABASE"])

    return render_template("mailguard.html", result=result, subject=subject, body=body)


@app.route("/watchlist", methods=["GET"])
def watchlist():
    """Threat Watchlist page: displays monitored malicious domains."""
    items = get_watchlist(db_path=app.config["DATABASE"])
    return render_template("watchlist.html", items=items)


@app.route("/watchlist/add", methods=["POST"])
def watchlist_add_form():
    """Handle HTML form submission to add domain to watchlist."""
    domain = request.form.get("domain", "").strip()
    description = request.form.get("description", "").strip()
    if not domain:
        flash("Domain name cannot be empty.", "error")
    else:
        try:
            add_watchlist_entry(domain, description, db_path=app.config["DATABASE"])
            flash(f"Domain '{domain}' added to Threat Watchlist.", "success")
        except Exception as e:
            flash(f"Error adding domain (may already exist): {str(e)}", "error")
    return redirect(url_for("watchlist"))


@app.route("/watchlist/delete/<int:entry_id>", methods=["POST"])
def watchlist_delete_form(entry_id):
    """Handle HTML form deletion of watchlist entry."""
    success = delete_watchlist_entry(entry_id, db_path=app.config["DATABASE"])
    if success:
        flash("Watchlist entry deleted successfully.", "success")
    else:
        flash("Entry not found.", "error")
    return redirect(url_for("watchlist"))


@app.route("/history", methods=["GET"])
def history():
    """Scan History audit trail page."""
    scans = get_scans(limit=100, db_path=app.config["DATABASE"])
    return render_template("history.html", scans=scans)


# ============================================================================
# REST API ENDPOINTS (JSON responses)
# ============================================================================

@app.route("/api/dashboard", methods=["GET"])
def api_dashboard():
    """GET /api/dashboard - Returns system statistics."""
    stats = get_dashboard_stats(app.config["DATABASE"])
    return jsonify({"success": True, "data": stats}), 200


@app.route("/api/scan-url", methods=["POST"])
def api_scan_url():
    """POST /api/scan-url - Analyzes a URL and records the result."""
    data = request.get_json(silent=True) or request.form
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"success": False, "error": "URL parameter is required."}), 400

    result = analyze_url(url, db_path=app.config["DATABASE"])
    if not result.get("valid"):
        return jsonify({"success": False, "error": result.get("error", "Invalid URL")}), 400

    scan_id = save_scan("url", result["url"], result["risk_score"], result["risk_level"], db_path=app.config["DATABASE"])
    result["scan_id"] = scan_id
    return jsonify({"success": True, "data": result}), 200


@app.route("/api/scan-qr", methods=["POST"])
def api_scan_qr():
    """POST /api/scan-qr - Decodes uploaded QR image and analyzes extracted URL."""
    if "file" not in request.files or not request.files["file"].filename:
        return jsonify({"success": False, "error": "Image file is required under key 'file'."}), 400

    file = request.files["file"]
    try:
        file_bytes = file.read()
        result = scan_qr_from_bytes(file_bytes, db_path=app.config["DATABASE"])
        if not result.get("decoded"):
            return jsonify({"success": False, "error": result.get("error", "Failed to decode QR code")}), 400

        scan_id = save_scan("qr", result["content"], result["risk_score"], result["risk_level"], db_path=app.config["DATABASE"])
        result["scan_id"] = scan_id
        return jsonify({"success": True, "data": result}), 200
    except Exception as e:
        return jsonify({"success": False, "error": f"Error scanning QR: {str(e)}"}), 500


@app.route("/api/scan-email", methods=["POST"])
def api_scan_email():
    """POST /api/scan-email - Analyzes email subject and body for phishing."""
    data = request.get_json(silent=True) or request.form
    subject = (data.get("subject") or "").strip()
    body = (data.get("body") or "").strip()

    if not body:
        return jsonify({"success": False, "error": "Email body text is required."}), 400

    result = analyze_email(subject, body, db_path=app.config["DATABASE"])
    target_label = subject or (body[:50] + "...")
    scan_id = save_scan("email", target_label, result["risk_score"], result["risk_level"], db_path=app.config["DATABASE"])
    result["scan_id"] = scan_id
    return jsonify({"success": True, "data": result}), 200


@app.route("/api/watchlist", methods=["GET"])
def api_get_watchlist():
    """GET /api/watchlist - Returns all entries in the threat watchlist."""
    items = get_watchlist(db_path=app.config["DATABASE"])
    return jsonify({"success": True, "data": items}), 200


@app.route("/api/watchlist", methods=["POST"])
def api_add_watchlist():
    """POST /api/watchlist - Adds a domain to the threat watchlist."""
    data = request.get_json(silent=True) or request.form
    domain = (data.get("domain") or "").strip()
    description = (data.get("description") or "").strip()

    if not domain:
        return jsonify({"success": False, "error": "Domain is required."}), 400

    try:
        entry = add_watchlist_entry(domain, description, db_path=app.config["DATABASE"])
        return jsonify({"success": True, "data": entry, "message": "Domain added to watchlist."}), 201
    except Exception as e:
        return jsonify({"success": False, "error": f"Could not add domain: {str(e)}"}), 400


@app.route("/api/watchlist/<int:entry_id>", methods=["DELETE"])
def api_delete_watchlist(entry_id):
    """DELETE /api/watchlist/<id> - Removes a domain from the threat watchlist."""
    deleted = delete_watchlist_entry(entry_id, db_path=app.config["DATABASE"])
    if deleted:
        return jsonify({"success": True, "message": f"Watchlist entry {entry_id} deleted."}), 200
    return jsonify({"success": False, "error": "Watchlist entry not found."}), 404


@app.route("/api/history", methods=["GET"])
def api_history():
    """GET /api/history - Returns recent scan history records."""
    limit = request.args.get("limit", default=100, type=int)
    scans = get_scans(limit=limit, db_path=app.config["DATABASE"])
    return jsonify({"success": True, "data": scans}), 200


# Error Handlers
@app.errorhandler(413)
def request_entity_too_large(error):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Uploaded file exceeds maximum 5 MB limit."}), 413
    flash("Uploaded file exceeds the maximum allowed 5 MB limit.", "error")
    return redirect(request.url)


if __name__ == "__main__":
    # Start the unified local server
    app.run(host="127.0.0.1", port=5000, debug=True)
