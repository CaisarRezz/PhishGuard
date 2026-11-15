import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"
DATABASE_PATH = INSTANCE_DIR / "phishguard.db"

# Security & App Settings
SECRET_KEY = os.environ.get("SECRET_KEY", "phishguard-dev-secret-key-replace-in-production")
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "http://localhost:5173")

# File Upload Limits
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB flask body cap
MAX_QR_FILE_SIZE = 5 * 1024 * 1024       # 5 MB
MAX_FILE_SCAN_SIZE = 10 * 1024 * 1024   # 10 MB

ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}
