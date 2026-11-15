from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_cors import CORS
from werkzeug.exceptions import RequestEntityTooLarge, NotFound, BadRequest

from backend.config import (
    BASE_DIR, INSTANCE_DIR, DATABASE_PATH,
    SECRET_KEY, CORS_ORIGIN, MAX_CONTENT_LENGTH
)
from backend.database import (
    init_db, save_scan, get_recent_scans, get_scan
)
from backend.services.url_analyzer import analyze_url
from backend.utils.responses import api_error

# Import API blueprints
from backend.routes.system import system_bp
from backend.routes.url_scanner import url_scanner_bp
from backend.routes.qr_scanner import qr_scanner_bp
from backend.routes.email_analyzer import email_analyzer_bp
from backend.routes.file_scanner import file_scanner_bp
from backend.routes.watchlist import watchlist_bp
from backend.routes.dashboard import dashboard_bp
from backend.routes.history import history_bp


def create_app():
    app = Flask(
        __name__,
        instance_path=str(INSTANCE_DIR),
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static")
    )

    app.secret_key = SECRET_KEY
    app.config["DATABASE"] = str(DATABASE_PATH)
    app.config["CORS_ORIGIN"] = CORS_ORIGIN
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

    # Configure CORS for modern React frontend (default http://localhost:5173)
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": [
                    CORS_ORIGIN,
                    "http://localhost:5173",
                    "http://127.0.0.1:5173",
                    "http://localhost:3000"
                ]
            }
        },
        supports_credentials=True
    )

    # Ensure instance directory exists and initialize database migrations
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    init_db(app.config["DATABASE"])

    # Register API blueprints under /api
    app.register_blueprint(system_bp, url_prefix="/api/system")
    app.register_blueprint(url_scanner_bp, url_prefix="/api")
    app.register_blueprint(qr_scanner_bp, url_prefix="/api")
    app.register_blueprint(email_analyzer_bp, url_prefix="/api")
    app.register_blueprint(file_scanner_bp, url_prefix="/api")
    app.register_blueprint(watchlist_bp, url_prefix="/api")
    app.register_blueprint(dashboard_bp, url_prefix="/api")
    app.register_blueprint(history_bp, url_prefix="/api")

    # Global Error Handlers for API requests
    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(e):
        if request.path.startswith("/api/"):
            return api_error(message="Ukuran file melebihi batas maksimal yang diizinkan.", status_code=413)
        flash("Ukuran file melebihi batas maksimal.", "error")
        return redirect(url_for("index"))

    @app.errorhandler(400)
    def handle_bad_request(e):
        if request.path.startswith("/api/"):
            return api_error(message="Bad Request: Permintaan tidak valid.", status_code=400)
        return e

    @app.errorhandler(404)
    def handle_not_found(e):
        if request.path.startswith("/api/"):
            return api_error(message=f"Endpoint '{request.path}' tidak ditemukan.", status_code=404)
        return e

    @app.errorhandler(500)
    def handle_internal_error(e):
        if request.path.startswith("/api/"):
            return api_error(message="Terjadi kesalahan internal pada server.", status_code=500)
        return e

    # Preserve legacy HTML routes for backward compatibility
    @app.route("/", methods=["GET"])
    def index():
        return render_template("index.html", recent_scans=get_recent_scans(app.config["DATABASE"], limit=5))

    @app.route("/scan", methods=["POST"])
    def legacy_scan():
        raw_url = request.form.get("url", "").strip()
        if not raw_url:
            flash("Masukkan URL terlebih dahulu.", "error")
            return redirect(url_for("index"))

        result = analyze_url(raw_url, db_path=app.config["DATABASE"])
        if result.get("error"):
            flash(result["error"], "error")
            return redirect(url_for("index"))

        scan_id = save_scan(app.config["DATABASE"], result, scan_type="url", target=result.get("url"))
        return redirect(url_for("result", scan_id=scan_id))

    @app.route("/result/<int:scan_id>")
    def result(scan_id):
        scan_data = get_scan(app.config["DATABASE"], scan_id)
        if scan_data is None:
            flash("Hasil pemeriksaan tidak ditemukan.", "error")
            return redirect(url_for("index"))
        return render_template("result.html", scan=scan_data)

    @app.route("/history", endpoint="history")
    def legacy_history():
        return render_template("history.html", scans=get_recent_scans(app.config["DATABASE"], limit=100))

    @app.route("/health")
    def health():
        return {"status": "ok", "app": "PhishGuard", "mode": "hybrid-api-mvc"}, 200

    return app


app = create_app()

if __name__ == "__main__":
    # Development server
    app.run(host="0.0.0.0", port=5000, debug=True)
