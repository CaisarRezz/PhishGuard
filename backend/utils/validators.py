import os
from urllib.parse import urlsplit

def validate_url(raw_url: str) -> tuple[bool, str]:
    if not isinstance(raw_url, str) or not raw_url.strip():
        return False, "URL tidak boleh kosong."

    raw_url = raw_url.strip()
    if any(ch.isspace() for ch in raw_url):
        return False, "URL tidak boleh mengandung spasi."

    candidate = raw_url if "://" in raw_url else "https://" + raw_url

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        return False, "Format URL atau nomor port tidak valid."

    if parsed.scheme.lower() not in ("http", "https"):
        return False, "Hanya URL dengan protokol HTTP atau HTTPS yang didukung."

    if not hostname or ("." not in hostname and hostname.lower() != "localhost"):
        return False, "URL tidak valid. Masukkan nama domain yang lengkap."

    return True, ""


def validate_email_input(data: dict) -> tuple[bool, str]:
    if not isinstance(data, dict):
        return False, "Request body harus berupa JSON object."

    subject = data.get("subject", "")
    body = data.get("body", "")

    if not isinstance(subject, str) or not subject.strip():
        return False, "Subjek email wajib diisi."
    if not isinstance(body, str) or not body.strip():
        return False, "Isi pesan email wajib diisi."

    return True, ""


def validate_file_upload(file_storage, max_size_bytes: int, allowed_extensions: set = None) -> tuple[bool, str]:
    if file_storage is None or file_storage.filename == "":
        return False, "File tidak ditemukan dalam request."

    filename = file_storage.filename.strip()
    if allowed_extensions:
        ext = os.path.splitext(filename)[1].lower()
        if ext not in allowed_extensions:
            return False, f"Format file '{ext}' tidak didukung. Format yang diizinkan: {', '.join(sorted(allowed_extensions))}"

    # Check size by seeking to end
    file_storage.seek(0, os.SEEK_END)
    size = file_storage.tell()
    file_storage.seek(0)

    if size > max_size_bytes:
        max_mb = max_size_bytes // (1024 * 1024)
        return False, f"Ukuran file ({size / (1024*1024):.1f} MB) melebihi batas maksimal {max_mb} MB."

    if size == 0:
        return False, "File yang diunggah kosong."

    return True, ""


def validate_watchlist_input(data: dict) -> tuple[bool, str]:
    if not isinstance(data, dict):
        return False, "Request body harus berupa JSON object."

    target = data.get("target", "").strip()
    threat_category = data.get("threat_category", "").strip()

    if not target:
        return False, "Target domain atau URL wajib diisi."
    if not threat_category:
        return False, "Kategori ancaman (threat_category) wajib diisi."

    return True, ""
