"""PhishGuard Threat Detection Engine.
Includes local heuristics for URLs, QR code decoding, and email phishing detection.
Never visits or fetches remote URLs.
"""
import ipaddress
import re
from urllib.parse import urlsplit
import cv2
import numpy as np
from database import check_watchlist

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "account", "secure", "update",
    "signin", "banking", "password", "confirm", "wallet", "bonus",
    "alert", "security", "billing", "support", "claim", "credential",
    "suspend", "suspended", "urgent", "invoice", "payment", "bank"
]

EMAIL_SUSPICIOUS_PHRASES = [
    "urgent", "immediately", "action required", "verify your account",
    "password", "reset password", "suspended", "bank transfer",
    "wire transfer", "lottery", "winner", "prize", "gift card",
    "invoice", "payment due", "security alert", "confirm your identity"
]


def validate_url(url: str):
    """Validate URL format and extract hostname safely."""
    raw = (url or "").strip()
    if not raw:
        return False, None, "URL cannot be empty."
    if any(c.isspace() for c in raw):
        return False, None, "URL must not contain whitespace."

    candidate = raw if "://" in raw else f"https://{raw}"
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
    except Exception:
        return False, None, "Invalid URL structure."

    if parsed.scheme.lower() not in ("http", "https"):
        return False, None, "Only HTTP and HTTPS protocols are supported."

    if not hostname or ("." not in hostname and hostname.lower() != "localhost"):
        return False, None, "Invalid domain name in URL."

    return True, candidate, hostname


def analyze_url(url: str, db_path=None) -> dict:
    """Analyze a URL using local heuristic security rules."""
    is_valid, parsed_url, hostname = validate_url(url)
    if not is_valid:
        return {
            "valid": False,
            "url": url,
            "error": hostname,  # error message is returned in 3rd param
            "risk_score": 0,
            "risk_level": "Unknown",
            "reasons": [hostname],
            "recommendation": "Please provide a valid, well-formed URL."
        }

    score = 0
    reasons = []

    # Rule 1: IP address as hostname (+25)
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        score += 25
        reasons.append("Hostname is a direct IP address rather than a domain name.")

    # Rule 2: Suspicious keywords in URL (+15)
    url_lower = parsed_url.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if matched_keywords:
        score += 15
        reasons.append(f"Contains sensitive keywords commonly found in phishing: {', '.join(matched_keywords[:4])}.")

    # Rule 3: Unusually long URL (+10)
    if len(parsed_url) > 100:
        score += 10
        reasons.append(f"Unusually long URL ({len(parsed_url)} characters), often used to hide target parameters.")

    # Rule 4: Plaintext HTTP (+10)
    if parsed_url.startswith("http://"):
        score += 10
        reasons.append("Insecure HTTP protocol used instead of encrypted HTTPS.")

    # Rule 5: Threat Watchlist match (+70)
    in_watchlist = check_watchlist(hostname, db_path=db_path)
    if in_watchlist:
        score += 70
        reasons.append(f"Domain '{hostname}' matched an active entry in the Threat Watchlist!")

    # Normalize risk score 0 - 100
    final_score = min(score, 100)

    # Determine risk level
    if final_score >= 70:
        risk_level = "High"
        recommendation = "CRITICAL: Do not visit this URL or submit any credentials. High probability of phishing."
    elif final_score >= 40:
        risk_level = "Medium"
        recommendation = "WARNING: Suspicious indicators detected. Verify domain authenticity before proceeding."
    else:
        risk_level = "Low"
        recommendation = "Low risk detected. No major phishing indicators found. Always verify domain spelling."

    if not reasons:
        reasons.append("Standard domain structure with HTTPS encryption.")

    return {
        "valid": True,
        "url": parsed_url,
        "hostname": hostname,
        "risk_score": final_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "recommendation": recommendation
    }


def scan_qr_from_bytes(file_bytes: bytes, db_path=None) -> dict:
    """Decode QR code image using OpenCV and analyze any embedded URL."""
    try:
        np_arr = np.frombuffer(file_bytes, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        if img is None:
            return {
                "decoded": False,
                "content": "",
                "is_url": False,
                "error": "Could not decode image file format.",
                "risk_score": 0,
                "risk_level": "Unknown",
                "recommendation": "Upload a valid PNG, JPG, or WEBP image."
            }

        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(img)
        if not data or not data.strip():
            return {
                "decoded": False,
                "content": "",
                "is_url": False,
                "error": "No QR code pattern detected in the uploaded image.",
                "risk_score": 0,
                "risk_level": "Unknown",
                "recommendation": "Ensure the QR code is clearly visible, focused, and well-lit."
            }

        extracted_text = data.strip()
        is_url = extracted_text.startswith("http://") or extracted_text.startswith("https://") or ("." in extracted_text and " " not in extracted_text)

        url_result = None
        if is_url:
            url_result = analyze_url(extracted_text, db_path=db_path)
            risk_score = url_result["risk_score"]
            risk_level = url_result["risk_level"]
            reasons = url_result["reasons"]
            recommendation = url_result["recommendation"]
        else:
            risk_score = 0
            risk_level = "Low"
            reasons = ["Plain text QR code without embedded web hyperlink."]
            recommendation = "Plain text content detected. Safe to inspect."

        return {
            "decoded": True,
            "content": extracted_text,
            "is_url": is_url,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "reasons": reasons,
            "recommendation": recommendation,
            "url_analysis": url_result
        }
    except Exception as e:
        return {
            "decoded": False,
            "content": "",
            "is_url": False,
            "error": f"Error scanning QR code: {str(e)}",
            "risk_score": 0,
            "risk_level": "Unknown",
            "recommendation": "Please try another image file."
        }


def extract_urls_from_text(text: str) -> list:
    """Extract all web URLs from arbitrary text using regex."""
    url_pattern = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
    matches = url_pattern.findall(text or "")
    return list(dict.fromkeys(matches))


def analyze_email(subject: str, body: str, db_path=None) -> dict:
    """Analyze email content for phishing language and embedded links."""
    combined_text = f"{(subject or '')} {(body or '')}".lower()

    # 1. Detect suspicious keywords/phrases
    detected_keywords = []
    for phrase in EMAIL_SUSPICIOUS_PHRASES:
        if phrase in combined_text and phrase not in detected_keywords:
            detected_keywords.append(phrase)

    # 2. Extract and analyze embedded URLs
    extracted_urls = extract_urls_from_text(body or "")
    url_analyses = []
    max_url_score = 0

    for u in extracted_urls:
        analysis = analyze_url(u, db_path=db_path)
        url_analyses.append(analysis)
        if analysis["risk_score"] > max_url_score:
            max_url_score = analysis["risk_score"]

    # Calculate overall risk score
    keyword_score = min(len(detected_keywords) * 15, 45)
    total_score = min(keyword_score + max_url_score, 100)

    if total_score >= 70:
        risk_level = "High"
        recommendation = "DANGER: High probability of phishing. Do not click links, reply, or provide credentials."
    elif total_score >= 40:
        risk_level = "Medium"
        recommendation = "CAUTION: Suspicious urgency or unfamiliar links detected. Confirm with sender via another channel."
    else:
        risk_level = "Low"
        recommendation = "No high-risk phishing indicators detected in email body or subject."

    reasons = []
    if detected_keywords:
        reasons.append(f"Detected urgency/phishing phrases: {', '.join(detected_keywords)}.")
    if extracted_urls:
        reasons.append(f"Extracted {len(extracted_urls)} embedded URL(s) for security inspection.")
    if not reasons:
        reasons.append("Email text appears neutral without obvious deceptive language.")

    return {
        "subject": subject or "",
        "risk_score": total_score,
        "risk_level": risk_level,
        "detected_keywords": detected_keywords,
        "extracted_urls": extracted_urls,
        "url_analyses": url_analyses,
        "reasons": reasons,
        "recommendation": recommendation
    }
