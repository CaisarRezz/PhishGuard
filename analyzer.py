"""URL feature analysis bridge.
Maintains backward compatibility while delegating to backend services.
"""
from backend.services.url_analyzer import analyze_url, SUSPICIOUS_KEYWORDS

__all__ = ["analyze_url", "SUSPICIOUS_KEYWORDS"]
