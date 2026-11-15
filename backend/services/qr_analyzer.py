"""QR Code Analyzer Service using OpenCV.
Safely extracts payload from QR image and analyzes URLs with URL Analyzer.
NEVER visits or executes extracted content.
"""
import os
import tempfile
from backend.services.url_analyzer import analyze_url
from backend.utils.validators import validate_url
from backend.config import DATABASE_PATH

try:
    import cv2
    import numpy as np
    CV2_AVAILABLE = True
except ImportError:
    cv2 = None
    np = None
    CV2_AVAILABLE = False


def decode_qr_from_bytes(image_bytes: bytes) -> str | None:
    if not CV2_AVAILABLE:
        raise RuntimeError("OpenCV (cv2) tidak terinstal. Modul QR Scanner memerlukan OpenCV.")

    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return None

        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(img)
        if data and data.strip():
            return data.strip()
        return None
    except Exception:
        return None


def decode_qr_from_file(file_path: str) -> str | None:
    if not CV2_AVAILABLE:
        raise RuntimeError("OpenCV (cv2) tidak terinstal. Modul QR Scanner memerlukan OpenCV.")

    if not os.path.exists(file_path):
        return None

    try:
        img = cv2.imread(file_path)
        if img is None:
            return None

        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(img)
        if data and data.strip():
            return data.strip()
        return None
    except Exception:
        return None


def analyze_qr_code(image_bytes: bytes, filename: str = "qr_image.png", db_path=DATABASE_PATH) -> dict:
    if not CV2_AVAILABLE:
        return {
            "error": "OpenCV (cv2) tidak tersedia di server. QR Scanner dalam mode tidak aktif.",
            "decoded": False
        }

    raw_data = decode_qr_from_bytes(image_bytes)
    file_size = len(image_bytes)

    if not raw_data:
        return {
            "filename": filename,
            "file_size": file_size,
            "decoded": False,
            "content": "",
            "is_url": False,
            "risk_score": 0,
            "risk_level": "Low",
            "recommendation": "QR code tidak dapat dideteksi atau gambar tidak terbaca. Pastikan gambar jelas dan memiliki kontras yang baik.",
            "findings": [
                {
                    "label": "Deteksi Pola QR",
                    "detail": "Modul OpenCV tidak menemukan pola QR code yang valid pada gambar yang diunggah.",
                    "points": 0,
                    "status": "Tidak ditemukan"
                }
            ],
            "url_analysis": None
        }

    # Check if raw_data is a URL
    is_valid_url, _ = validate_url(raw_data)
    # Check if string starts with http://, https://, or common domain pattern
    looks_like_url = is_valid_url or raw_data.lower().startswith(("http://", "https://", "www."))

    if looks_like_url:
        url_analysis = analyze_url(raw_data, db_path=db_path)
        if "error" not in url_analysis:
            risk_score = url_analysis["risk_score"]
            risk_level = url_analysis["risk_level"]
            recommendation = (
                f"QR Code memuat tautan URL ({url_analysis.get('hostname')}). "
                f"{url_analysis.get('recommendation')}"
            )
            findings = [
                {
                    "label": "Muatan URL Terdeteksi",
                    "detail": f"QR code mengarahkan ke URL: {url_analysis.get('normalized_url')}",
                    "points": 10 if risk_score > 0 else 0,
                    "status": "Indikator ditemukan"
                }
            ] + url_analysis.get("findings", [])

            return {
                "filename": filename,
                "file_size": file_size,
                "decoded": True,
                "content": raw_data,
                "is_url": True,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "recommendation": recommendation,
                "findings": findings,
                "url_analysis": url_analysis
            }

    # Plain text QR content
    return {
        "filename": filename,
        "file_size": file_size,
        "decoded": True,
        "content": raw_data,
        "is_url": False,
        "risk_score": 0,
        "risk_level": "Low",
        "recommendation": "QR code berhasil didekode. Konten berupa teks non-URL.",
        "findings": [
            {
                "label": "Teks non-URL",
                "detail": "Konten QR code tidak berupa tautan web, risiko injeksi URL web dinilai rendah.",
                "points": 0,
                "status": "Aman"
            }
        ],
        "url_analysis": None
    }
