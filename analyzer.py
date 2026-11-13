"""Local URL feature analysis. This module NEVER visits the submitted URL."""
import ipaddress
import re
from urllib.parse import urlsplit

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "account", "secure", "update",
    "signin", "banking", "password", "confirm", "wallet", "bonus"
}


def analyze_url(raw_url: str) -> dict:
    raw_url = (raw_url or "").strip()

    if not raw_url:
        return {"error": "URL tidak boleh kosong."}

    # Accept a URL without a scheme by assuming HTTPS for parsing only.
    candidate = raw_url if "://" in raw_url else "https://" + raw_url

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        # Accessing .port can raise ValueError for malformed ports.
        _ = parsed.port
    except ValueError:
        return {"error": "Format URL atau nomor port tidak valid."}

    if parsed.scheme.lower() not in ("http", "https"):
        return {"error": "Hanya URL dengan protokol HTTP atau HTTPS yang didukung."}
    if not hostname or "." not in hostname and hostname.lower() != "localhost":
        return {"error": "URL tidak valid. Masukkan nama domain yang lengkap."}
    if any(ch.isspace() for ch in raw_url):
        return {"error": "URL tidak boleh mengandung spasi."}

    score = 0
    findings = []

    def add_finding(label, detail, points, detected):
        nonlocal score
        if detected:
            score += points
            findings.append({
                "label": label,
                "detail": detail,
                "points": points,
                "status": "Indikator ditemukan"
            })
        else:
            findings.append({
                "label": label,
                "detail": detail,
                "points": 0,
                "status": "Tidak ditemukan"
            })

    try:
        ipaddress.ip_address(hostname)
        host_is_ip = True
    except ValueError:
        host_is_ip = False

    add_finding(
        "Host berupa alamat IP",
        "Phishing kadang menggunakan alamat IP secara langsung sebagai host.",
        20, host_is_ip
    )

    add_finding(
        "Karakter @ pada URL",
        "Karakter @ dapat membuat bagian sebelum host sebenarnya terlihat seperti identitas tepercaya.",
        15, "@" in candidate
    )

    labels = hostname.split(".")
    subdomain_count = max(0, len(labels) - 2) if not host_is_ip else 0
    add_finding(
        "Jumlah subdomain tidak biasa",
        f"URL memiliki {subdomain_count} subdomain (indikator sederhana: lebih dari 2).",
        10, subdomain_count > 2
    )

    add_finding(
        "Kata kunci sensitif",
        "URL mengandung kata yang sering dipakai dalam umpan login atau verifikasi.",
        10, any(word in candidate.lower() for word in SUSPICIOUS_KEYWORDS)
    )

    add_finding(
        "URL sangat panjang",
        f"Panjang URL adalah {len(candidate)} karakter (ambang prototype: lebih dari 100).",
        5, len(candidate) > 100
    )

    add_finding(
        "Banyak tanda hubung pada hostname",
        "Hostname memiliki lebih dari 3 tanda hubung.",
        5, hostname.count("-") > 3
    )

    add_finding(
        "Hostname menggunakan pola punycode",
        "Awalan xn-- dapat menunjukkan nama domain internasional yang dikodekan.",
        10, "xn--" in hostname.lower()
    )

    add_finding(
        "Tidak menggunakan HTTPS",
        "Koneksi HTTP tidak mengenkripsi komunikasi antara browser dan situs.",
        5, parsed.scheme.lower() != "https"
    )

    score = min(score, 100)
    if score >= 60:
        level, recommendation = "High", "Jangan masukkan informasi pribadi. Verifikasi alamat melalui kanal resmi."
    elif score >= 30:
        level, recommendation = "Medium", "Periksa kembali identitas domain dan sumber tautan sebelum melanjutkan."
    else:
        level, recommendation = "Low", "Tidak banyak indikator mencurigakan ditemukan. Tetap pastikan domain benar."

    return {
        "url": raw_url,
        "normalized_url": candidate,
        "hostname": hostname,
        "risk_score": score,
        "risk_level": level,
        "recommendation": recommendation,
        "findings": findings,
        "disclaimer": "Ini adalah analisis heuristik lokal, bukan jaminan bahwa URL aman atau berbahaya."
    }
