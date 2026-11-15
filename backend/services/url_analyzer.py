"""Local URL feature analysis engine.
NEVER visits, connects to, or fetches the submitted URL.
"""
import ipaddress
import re
from urllib.parse import urlsplit
from backend.services.threat_intelligence import check_watchlist
from backend.config import DATABASE_PATH

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "account", "secure", "update",
    "signin", "banking", "password", "confirm", "wallet", "bonus",
    "alert", "security", "billing", "support", "authenticate", "claim",
    "invoice", "credential", "suspend", "suspended"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click", ".loan"
}


def analyze_url(raw_url: str, db_path=DATABASE_PATH) -> dict:
    raw_url = (raw_url or "").strip()

    if not raw_url:
        return {"error": "URL tidak boleh kosong."}

    if any(ch.isspace() for ch in raw_url):
        return {"error": "URL tidak boleh mengandung spasi."}

    # Accept a URL without a scheme by assuming HTTPS for parsing only.
    has_scheme = "://" in raw_url
    candidate = raw_url if has_scheme else "https://" + raw_url

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        return {"error": "Format URL atau nomor port tidak valid."}

    if parsed.scheme.lower() not in ("http", "https"):
        return {"error": "Hanya URL dengan protokol HTTP atau HTTPS yang didukung."}

    if not hostname or ("." not in hostname and hostname.lower() != "localhost"):
        return {"error": "URL tidak valid. Masukkan nama domain yang lengkap."}

    score = 0
    findings = []
    evaluated_labels = set()

    def add_finding(label, detail, points, detected):
        nonlocal score
        if label in evaluated_labels:
            return
        evaluated_labels.add(label)

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

    # 1. IP address as host
    try:
        ipaddress.ip_address(hostname)
        host_is_ip = True
    except ValueError:
        host_is_ip = False

    add_finding(
        "Host berupa alamat IP",
        "Phishing kadang menggunakan alamat IP secara langsung sebagai host untuk menghindari deteksi domain.",
        25, host_is_ip
    )

    # 2. Suspicious character @
    add_finding(
        "Karakter @ pada URL",
        "Karakter @ dapat mengecoh pembacaan host sebenarnya dan sering digunakan dalam serangan rekayasa sosial.",
        15, "@" in candidate
    )

    # 3. Excessive subdomains
    labels = hostname.split(".")
    subdomain_count = max(0, len(labels) - 2) if not host_is_ip else 0
    add_finding(
        "Jumlah subdomain tidak biasa",
        f"URL memiliki {subdomain_count} subdomain (ambang batas: lebih dari 2 subdomain).",
        10, subdomain_count > 2
    )

    # 4. Sensitive & phishing keywords
    detected_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in candidate.lower()]
    add_finding(
        "Kata kunci sensitif",
        f"URL mengandung kata kunci mencurigakan: {', '.join(detected_keywords[:5])}." if detected_keywords else "URL tidak mengandung kata kunci sensitif umum.",
        15, bool(detected_keywords)
    )

    # 5. Very long URL
    add_finding(
        "URL sangat panjang",
        f"Panjang URL adalah {len(candidate)} karakter (ambang batas: lebih dari 100 karakter).",
        5, len(candidate) > 100
    )

    # 6. Excessive hyphens
    hyphen_count = hostname.count("-")
    add_finding(
        "Banyak tanda hubung pada hostname",
        f"Hostname memiliki {hyphen_count} tanda hubung (ambang batas: lebih dari 3).",
        5, hyphen_count > 3
    )

    # 7. Punycode pattern (homograph attacks)
    add_finding(
        "Hostname menggunakan pola punycode",
        "Awalan 'xn--' mengindikasikan Internationalized Domain Name (IDN) yang kerap dipakai pada homograph attack.",
        15, "xn--" in hostname.lower()
    )

    # 8. Unencrypted HTTP
    is_http = parsed.scheme.lower() == "http"
    add_finding(
        "Tidak menggunakan HTTPS",
        "Koneksi HTTP tidak mengenkripsi komunikasi antara browser dan server.",
        10, is_http
    )

    # 9. Suspicious TLD
    has_suspicious_tld = any(hostname.lower().endswith(tld) for tld in SUSPICIOUS_TLDS)
    add_finding(
        "Top-Level Domain (TLD) berisiko tinggi",
        "Domain menggunakan ekstensi TLD yang sering diidentifikasi dalam kampanye spam atau phishing massal.",
        10, has_suspicious_tld
    )

    # 10. Check threat watchlist
    watchlist_match = None
    try:
        watchlist_match = check_watchlist(hostname, db_path=db_path)
        if not watchlist_match:
            watchlist_match = check_watchlist(candidate, db_path=db_path)
    except Exception:
        watchlist_match = None

    if watchlist_match:
        add_finding(
            "Kecocokan Threat Watchlist",
            f"Target terdaftar dalam database watchlist ancaman lokal. Kategori: {watchlist_match.get('threat_category', 'Malicious')} - {watchlist_match.get('description', '')}",
            50, True
        )
        # Directly raise score significantly for confirmed watchlist items
        score = max(score, 85)
    else:
        add_finding(
            "Kecocokan Threat Watchlist",
            "Domain atau URL tidak terdaftar di database watchlist ancaman lokal.",
            0, False
        )

    score = min(max(score, 0), 100)

    if score >= 60:
        level = "High"
        recommendation = "Jangan masukkan informasi pribadi atau kredensial. Verifikasi alamat melalui kanal resmi organisasi terkait."
    elif score >= 30:
        level = "Medium"
        recommendation = "Periksa kembali identitas domain dan sumber pengirim tautan sebelum berinteraksi lebih lanjut."
    else:
        level = "Low"
        recommendation = "Tidak banyak indikator mencurigakan ditemukan. Tetap pastikan alamat domain tujuan sudah benar."

    return {
        "url": raw_url,
        "normalized_url": candidate,
        "hostname": hostname,
        "risk_score": score,
        "risk_level": level,
        "recommendation": recommendation,
        "findings": findings,
        "watchlist_match": watchlist_match,
        "disclaimer": "Ini adalah analisis heuristik lokal secara offline, bukan jaminan bahwa URL sepenuhnya aman atau berbahaya."
    }
