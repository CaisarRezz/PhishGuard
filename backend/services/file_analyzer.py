"""FileGuard - File Hash Security Checker.
Calculates SHA-256 cryptographic digest of uploaded files without execution or extraction.
Compares hash against local threat signature database.
"""
import hashlib
import os
from datetime import datetime, timezone
from backend.services.threat_intelligence import check_file_hash
from backend.config import DATABASE_PATH


def calculate_sha256_stream(file_stream, chunk_size: int = 65536) -> tuple[str, int]:
    hasher = hashlib.sha256()
    total_bytes = 0
    file_stream.seek(0)
    while True:
        chunk = file_stream.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
        total_bytes += len(chunk)
    file_stream.seek(0)
    return hasher.hexdigest().lower(), total_bytes


def analyze_file(file_stream, filename: str, db_path=DATABASE_PATH) -> dict:
    sha256_hash, file_size = calculate_sha256_stream(file_stream)
    now_iso = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

    match = check_file_hash(sha256_hash, db_path=db_path)

    if match:
        risk_score = 100
        risk_level = "High"
        reputation = "Malicious"
        recommendation = (
            f"File ini cocok dengan signature ancaman '{match.get('threat_name')}' pada database intelijen lokal. "
            "Segera karantina atau hapus file tersebut dan jangan dijalankan."
        )
        threat_details = {
            "threat_name": match.get("threat_name"),
            "description": match.get("description"),
            "source": match.get("source"),
            "date_added": match.get("date_added")
        }
        findings = [
            {
                "label": "Kecocokan Signature Malware",
                "detail": f"SHA-256 cocok dengan ancaman '{match.get('threat_name')}' ({match.get('description')}).",
                "points": 100,
                "status": "Indikator ditemukan"
            }
        ]
    else:
        risk_score = 0
        risk_level = "Low"
        reputation = "Unknown / Clean in local DB"
        recommendation = (
            "Hash file tidak ditemukan dalam basis data signature malware lokal. "
            "Tetap waspada dan jangan jalankan file dari pengirim atau sumber yang tidak tepercaya."
        )
        threat_details = None
        findings = [
            {
                "label": "Pengecekan Signature Hash",
                "detail": "SHA-256 tidak cocok dengan entri malware yang ada pada database lokal.",
                "points": 0,
                "status": "Tidak ditemukan"
            }
        ]

    return {
        "filename": filename,
        "file_size": file_size,
        "sha256": sha256_hash,
        "reputation": reputation,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "threat_details": threat_details,
        "recommendation": recommendation,
        "findings": findings,
        "scanned_at": now_iso,
        "disclaimer": "Pemeriksaan berdasarkan perbandingan hash SHA-256 lokal tanpa eksekusi file. Tidak adanya kecocokan bukan jaminan absolut bahwa file aman."
    }
