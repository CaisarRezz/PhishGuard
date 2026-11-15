"""PhishGuard QR Reader Bridge.
Provides simple helper functions for QR decoding.
"""
from analyzer import scan_qr_from_bytes


def read_qr_file(file_path: str):
    """Read and decode a QR code from a file path."""
    with open(file_path, "rb") as f:
        data = f.read()
    return scan_qr_from_bytes(data)


__all__ = ["read_qr_file", "scan_qr_from_bytes"]
