"""PhishGuard Backend Main Entry Point.
Runs the unified Flask REST API & Web Server.
"""
from backend.app import app, create_app

if __name__ == "__main__":
    # Local development server
    app.run(host="0.0.0.0", port=5000, debug=True)
