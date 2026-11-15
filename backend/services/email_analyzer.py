"""MailGuard - Heuristic Email Phishing Analyzer.
Analyzes email text locally for social engineering cues, suspicious sender patterns,
and extracts embedded URLs for threat intelligence screening.
NEVER visits extracted URLs. Does NOT permanently store email bodies.
"""
import re
from urllib.parse import urlsplit
from backend.services.url_analyzer import analyze_url
from backend.config import DATABASE_PATH

# 1. Urgency and threatening language
URGENCY_KEYWORDS = [
    "urgent", "urgently", "immediately", "immediate action", "account suspended",
    "suspend", "action required", "within 24 hours", "unauthorized access",
    "legal action", "final notice", "security alert", "critical alert",
    "temporary suspension", "terminate", "limited time", "compromised",
    "deadline", "penalty", "locked out"
]

# 2. Requests for passwords or credentials
CREDENTIAL_KEYWORDS = [
    "password", "credentials", "verify your account", "verify identity",
    "confirm identity", "enter your password", "reset password", "security questions",
    "login credentials", "pin", "otp", "2fa code", "security token",
    "update your credentials", "re-authenticate"
]

# 3. Suspicious financial requests
FINANCIAL_KEYWORDS = [
    "wire transfer", "gift card", "crypto", "bitcoin", "direct deposit",
    "invoice attached", "tax refund", "overdue payment", "bank transfer",
    "western union", "billing error", "money order", "payout", "unclaimed funds"
]

# 4. Prize or reward manipulation
PRIZE_KEYWORDS = [
    "lottery", "winner", "you have won", "congratulations you won",
    "claim your prize", "exclusive bonus", "free gift", "cash prize",
    "inheritance", "million dollars", "grant approved", "jackpot"
]

# Free email domains often abused for corporate impersonation
FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "mail.com", "protonmail.com"
}

# Brands frequently impersonated
KNOWN_BRANDS = ["paypal", "google", "microsoft", "apple", "netflix", "bank", "amazon", "chase", "bca", "mandiri"]

# Suspicious TLDs
SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click", ".loan"}


def extract_urls(text: str) -> list[str]:
    if not text:
        return []
    # Regex matching URLs (http, https, and www.)
    pattern = r'(https?://[^\s<>"\'\)]+|www\.[^\s<>"\'\)]+)'
    raw_matches = re.findall(pattern, text)
    unique_urls = []
    seen = set()
    for m in raw_matches:
        cleaned = m.rstrip(".,;!?:")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique_urls.append(cleaned)
    return unique_urls


def analyze_sender_pattern(sender: str) -> tuple[int, list[dict]]:
    points = 0
    findings = []
    if not sender or not sender.strip():
        return 0, []

    sender_clean = sender.strip().lower()
    # Extract email domain
    match = re.search(r'[\w\.-]+@([\w\.-]+)', sender_clean)
    if not match:
        findings.append({
            "category": "sender_suspicion",
            "label": "Format alamat pengirim tidak valid",
            "detail": f"Pengirim '{sender}' tidak memiliki format alamat email yang standar.",
            "points": 10,
            "status": "Indikator ditemukan"
        })
        return 10, findings

    domain = match.group(1)
    local_part = sender_clean.split("@")[0]

    # Check suspicious TLD
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        points += 15
        findings.append({
            "category": "sender_suspicion",
            "label": "Domain pengirim menggunakan TLD berisiko",
            "detail": f"Domain pengirim (@{domain}) menggunakan Top-Level Domain yang rentan disalahgunakan.",
            "points": 15,
            "status": "Indikator ditemukan"
        })

    # Check brand impersonation on free email providers
    for brand in KNOWN_BRANDS:
        if brand in local_part and domain in FREE_MAIL_DOMAINS:
            points += 25
            findings.append({
                "category": "sender_suspicion",
                "label": "Indikasi peniruan identitas organisasi (Brand Impersonation)",
                "detail": f"Nama akun mengandung '{brand}' namun dikirim melalui penyedia email publik (@{domain}).",
                "points": 25,
                "status": "Indikator ditemukan"
            })
            break

    # Check typosquatting patterns (e.g. paypa1, micros0ft, goog1e)
    typos = ["paypa1", "micros0ft", "goog1e", "app1e", "amaz0n"]
    for typo in typos:
        if typo in domain:
            points += 30
            findings.append({
                "category": "sender_suspicion",
                "label": "Indikasi Typosquatting domain pengirim",
                "detail": f"Domain pengirim (@{domain}) memuat variasi karakter penipu '{typo}'.",
                "points": 30,
                "status": "Indikator ditemukan"
            })
            break

    return points, findings


def analyze_email(subject: str, body: str, sender: str = "", db_path=DATABASE_PATH) -> dict:
    subject_text = (subject or "").strip()
    body_text = (body or "").strip()
    full_text = f"{subject_text}\n{body_text}".lower()

    score = 0
    findings = []
    found_keywords = []

    # 1. Urgency / threat analysis
    urgency_matches = [k for k in URGENCY_KEYWORDS if k in full_text]
    if urgency_matches:
        pts = min(25, 10 + len(urgency_matches) * 5)
        score += pts
        found_keywords.extend(urgency_matches)
        findings.append({
            "category": "urgency_threats",
            "label": "Bahasa mendesak dan ancaman",
            "detail": f"Ditemukan indikasi urgensi: {', '.join(urgency_matches[:4])}. Pelaku umumnya menekan korban agar bertindak terburu-buru.",
            "points": pts,
            "status": "Indikator ditemukan"
        })

    # 2. Credential harvesting cues
    credential_matches = [k for k in CREDENTIAL_KEYWORDS if k in full_text]
    if credential_matches:
        pts = min(30, 15 + len(credential_matches) * 5)
        score += pts
        found_keywords.extend(credential_matches)
        findings.append({
            "category": "credential_harvesting",
            "label": "Permintaan kredensial dan kata sandi",
            "detail": f"Ditemukan permintaan akses sensitif: {', '.join(credential_matches[:3])}. Lembaga resmi jarang meminta kata sandi via email.",
            "points": pts,
            "status": "Indikator ditemukan"
        })

    # 3. Suspicious financial cues
    financial_matches = [k for k in FINANCIAL_KEYWORDS if k in full_text]
    if financial_matches:
        pts = min(25, 10 + len(financial_matches) * 5)
        score += pts
        found_keywords.extend(financial_matches)
        findings.append({
            "category": "financial_requests",
            "label": "Permintaan transaksi keuangan tidak biasa",
            "detail": f"Ditemukan indikasi transaksi mencurigakan: {', '.join(financial_matches[:3])}.",
            "points": pts,
            "status": "Indikator ditemukan"
        })

    # 4. Prize / reward manipulation
    prize_matches = [k for k in PRIZE_KEYWORDS if k in full_text]
    if prize_matches:
        pts = min(25, 10 + len(prize_matches) * 5)
        score += pts
        found_keywords.extend(prize_matches)
        findings.append({
            "category": "reward_manipulation",
            "label": "Umpan hadiah atau klaim dana (Lottery/Prize lure)",
            "detail": f"Ditemukan klaim hadiah atau undian: {', '.join(prize_matches[:3])}.",
            "points": pts,
            "status": "Indikator ditemukan"
        })

    # 5. Sender analysis
    if sender:
        sender_pts, sender_findings = analyze_sender_pattern(sender)
        score += sender_pts
        findings.extend(sender_findings)

    # 6. Extract URLs and analyze each
    extracted_urls = extract_urls(f"{subject_text} {body_text}")
    url_analyses = []
    max_url_score = 0

    for url in extracted_urls:
        res = analyze_url(url, db_path=db_path)
        if "error" not in res:
            url_analyses.append({
                "url": res["url"],
                "hostname": res["hostname"],
                "risk_score": res["risk_score"],
                "risk_level": res["risk_level"]
            })
            if res["risk_score"] > max_url_score:
                max_url_score = res["risk_score"]

    if extracted_urls:
        if max_url_score >= 60:
            score += 30
            findings.append({
                "category": "embedded_urls",
                "label": "Tautan berisiko tinggi terdeteksi di dalam email",
                "detail": f"{len(extracted_urls)} tautan ditemukan. Setidaknya satu tautan memiliki tingkat risiko TINGGI.",
                "points": 30,
                "status": "Indikator ditemukan"
            })
        elif max_url_score >= 30:
            score += 15
            findings.append({
                "category": "embedded_urls",
                "label": "Tautan berisiko sedang terdeteksi",
                "detail": f"{len(extracted_urls)} tautan ditemukan dengan indikator mencurigakan moderat.",
                "points": 15,
                "status": "Indikator ditemukan"
            })
        else:
            findings.append({
                "category": "embedded_urls",
                "label": "Tautan tersemat dianalisis",
                "detail": f"{len(extracted_urls)} tautan dianalisis dan tidak ditemukan indikator berbahaya signifikan.",
                "points": 0,
                "status": "Tidak ditemukan ancaman spesifik"
            })

    # Calculate final score and level
    score = min(max(score, 0), 100)

    if score >= 60:
        level = "High"
        recommendation = "Email ini sangat dicurigai sebagai upaya phishing atau rekayasa sosial. Jangan klik tautan, unduh lampiran, atau memberikan data pribadi."
    elif score >= 30:
        level = "Medium"
        recommendation = "Email memuat indikator mencurigakan. Pastikan keaslian pengirim melalui kanal resmi sebelum menanggapi."
    else:
        level = "Low"
        recommendation = "Tidak banyak indikator mencurigakan yang terdeteksi. Tetap waspada terhadap instruksi yang tidak biasa."

    # Remove duplicates from found_keywords
    unique_keywords = list(dict.fromkeys(found_keywords))

    return {
        "subject": subject_text,
        "sender": sender or "",
        "risk_score": score,
        "risk_level": level,
        "recommendation": recommendation,
        "suspicious_keywords": unique_keywords,
        "findings": findings,
        "extracted_urls": extracted_urls,
        "url_analyses": url_analyses,
        "disclaimer": "Analisis ini berbasis heuristik konten lokal dan analisis tautan. Tidak memverifikasi catatan DNS SPF/DKIM/DMARC."
    }
