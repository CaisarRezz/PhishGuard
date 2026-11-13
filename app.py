from flask import Flask, render_template, request, redirect, url_for, flash
from pathlib import Path
from analyzer import analyze_url
from database import init_db, save_scan, get_recent_scans, get_scan

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__, instance_path=str(BASE_DIR / "instance"))
app.secret_key = "change-this-secret-before-deployment"
app.config["DATABASE"] = str(BASE_DIR / "instance" / "phishguard.db")

Path(app.instance_path).mkdir(parents=True, exist_ok=True)
init_db(app.config["DATABASE"])


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", recent_scans=get_recent_scans(app.config["DATABASE"], limit=5))


@app.route("/scan", methods=["POST"])
def scan():
    raw_url = request.form.get("url", "").strip()
    if not raw_url:
        flash("Masukkan URL terlebih dahulu.", "error")
        return redirect(url_for("index"))

    result = analyze_url(raw_url)
    if result.get("error"):
        flash(result["error"], "error")
        return redirect(url_for("index"))

    scan_id = save_scan(app.config["DATABASE"], result)
    return redirect(url_for("result", scan_id=scan_id))


@app.route("/result/<int:scan_id>")
def result(scan_id):
    scan_data = get_scan(app.config["DATABASE"], scan_id)
    if scan_data is None:
        flash("Hasil pemeriksaan tidak ditemukan.", "error")
        return redirect(url_for("index"))
    return render_template("result.html", scan=scan_data)


@app.route("/history")
def history():
    return render_template("history.html", scans=get_recent_scans(app.config["DATABASE"], limit=100))


@app.route("/health")
def health():
    return {"status": "ok", "app": "PhishGuard"}, 200


if __name__ == "__main__":
    # Local development only. For public deployment, use a production WSGI server.
    app.run(debug=True)
