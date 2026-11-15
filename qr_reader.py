"""QR Reader bridge.
Maintains backward compatibility with legacy read_qr function.
"""
from backend.services.qr_analyzer import decode_qr_from_file, decode_qr_from_bytes, analyze_qr_code

def read_qr(image_path: str):
    return decode_qr_from_file(image_path)

__all__ = ["read_qr", "decode_qr_from_file", "decode_qr_from_bytes", "analyze_qr_code"]
