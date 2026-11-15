"""Comprehensive Automated Test Suite for PhishGuard Backend API
Tests all endpoints, security rules, error conditions, and edge cases.
"""
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
import cv2
import numpy as np

from backend.app import create_app
from backend.database import init_db, add_file_hash, add_watchlist_entry, get_dashboard_stats, get_dashboard_activity


def generate_qr_image_bytes(text: str) -> bytes:
    """Helper to generate a valid QR code image in PNG format using OpenCV."""
    encoder = cv2.QRCodeEncoder.create()
    img = encoder.encode(text)
    scaled = cv2.resize(img, (290, 290), interpolation=cv2.INTER_NEAREST)
    bordered = cv2.copyMakeBorder(scaled, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=[255, 255, 255])
    _, buffer = cv2.imencode(".png", bordered)
    return buffer.tobytes()


class PhishGuardApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a temporary database for test isolation
        cls.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.test_db_path = Path(cls.temp_dir.name) / "test_phishguard.db"

        # Initialize test app
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["DATABASE"] = str(cls.test_db_path)
        init_db(str(cls.test_db_path))

        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    # --- 1. SYSTEM STATUS TESTS ---
    def test_system_status(self):
        resp = self.client.get("/api/system/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("services", data["data"])
        self.assertEqual(data["data"]["services"]["backend"]["status"], "online")
        self.assertEqual(data["data"]["services"]["database"]["status"], "online")
        self.assertEqual(data["data"]["services"]["qr_analyzer"]["status"], "operational")

    # --- 2. URL SCANNER TESTS ---
    def test_url_scan_clean(self):
        resp = self.client.post("/api/url/scan", json={"url": "https://google.com"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["risk_level"], "Low")
        self.assertLess(data["data"]["risk_score"], 30)

    def test_url_scan_suspicious(self):
        # IP as hostname, unencrypted http, suspicious keywords
        url = "http://192.168.1.100/login/verify-account-password"
        resp = self.client.post("/api/url/scan", json={"url": url})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn(data["data"]["risk_level"], ("Medium", "High"))
        self.assertGreaterEqual(data["data"]["risk_score"], 30)

    def test_url_scan_watchlist_match(self):
        # Initial seeded watchlist has 'phishing-bank-login.com'
        url = "https://phishing-bank-login.com/portal"
        resp = self.client.post("/api/url/scan", json={"url": url})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["risk_level"], "High")
        self.assertIsNotNone(data["data"]["watchlist_match"])

    def test_url_scan_empty(self):
        resp = self.client.post("/api/url/scan", json={"url": "   "})
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data["success"])

    def test_url_scan_invalid_proto(self):
        resp = self.client.post("/api/url/scan", json={"url": "ftp://files.example.com"})
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data["success"])

    # --- 3. WATCHLIST CRUD TESTS ---
    def test_watchlist_workflow(self):
        # 1. Add new entry
        add_payload = {
            "target": "suspicious-new-test-domain.top",
            "threat_category": "Phishing",
            "description": "Integration test entry",
            "source": "Automated Test"
        }
        resp = self.client.post("/api/watchlist", json=add_payload)
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data["success"])
        new_id = data["data"]["id"]

        # 2. Duplicate prevention
        resp_dup = self.client.post("/api/watchlist", json=add_payload)
        self.assertEqual(resp_dup.status_code, 409)

        # 3. List and search watchlist
        resp_list = self.client.get("/api/watchlist?search=suspicious-new-test")
        self.assertEqual(resp_list.status_code, 200)
        list_data = resp_list.get_json()
        self.assertGreaterEqual(list_data["data"]["total"], 1)

        # 4. Delete entry
        resp_del = self.client.delete(f"/api/watchlist/{new_id}")
        self.assertEqual(resp_del.status_code, 200)

        # 5. Delete non-existent entry
        resp_del_nf = self.client.delete(f"/api/watchlist/{new_id}")
        self.assertEqual(resp_del_nf.status_code, 404)

    # --- 4. EMAIL ANALYZER TESTS ---
    def test_email_analyze_phishing(self):
        payload = {
            "subject": "URGENT: Your bank account is suspended! Verify password now",
            "body": "Dear customer, within 24 hours please enter your password and wire transfer at http://phishing-bank-login.com/login",
            "sender": "security-support@paypa1.com"
        }
        resp = self.client.post("/api/email/analyze", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["risk_level"], "High")
        self.assertGreater(len(data["data"]["suspicious_keywords"]), 0)
        self.assertIn("http://phishing-bank-login.com/login", data["data"]["extracted_urls"])

    def test_email_analyze_clean(self):
        payload = {
            "subject": "Weekly Team Meeting Agenda",
            "body": "Hi team, attached is the presentation for our sprint review on Friday morning. Best regards.",
            "sender": "colleague@company.com"
        }
        resp = self.client.post("/api/email/analyze", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["risk_level"], "Low")
        self.assertEqual(data["data"]["risk_score"], 0)

    def test_email_analyze_missing_fields(self):
        resp = self.client.post("/api/email/analyze", json={"sender": "someone@example.com"})
        self.assertEqual(resp.status_code, 400)

    # --- 5. FILE HASH SCANNER TESTS ---
    def test_file_scan_known_hash_eicar(self):
        # EICAR standard antivirus test string
        eicar_content = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        data = {
            "file": (io.BytesIO(eicar_content), "eicar.com")
        }
        resp = self.client.post("/api/file/scan", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        res = resp.get_json()
        self.assertTrue(res["success"])
        self.assertEqual(res["data"]["reputation"], "Malicious")
        self.assertEqual(res["data"]["risk_level"], "High")
        self.assertEqual(res["data"]["risk_score"], 100)
        self.assertIsNotNone(res["data"]["threat_details"])

    def test_file_scan_unknown_hash_clean(self):
        clean_content = b'Hello world, this is a clean and harmless document file.'
        data = {
            "file": (io.BytesIO(clean_content), "clean_notes.txt")
        }
        resp = self.client.post("/api/file/scan", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        res = resp.get_json()
        self.assertTrue(res["success"])
        self.assertEqual(res["data"]["reputation"], "Unknown / Clean in local DB")
        self.assertEqual(res["data"]["risk_level"], "Low")
        self.assertEqual(res["data"]["risk_score"], 0)

    def test_file_scan_no_file(self):
        resp = self.client.post("/api/file/scan", data={}, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)

    def test_file_scan_oversized(self):
        # Create dummy file > 10MB
        oversized = io.BytesIO(b"A" * (11 * 1024 * 1024))
        data = {"file": (oversized, "huge_file.bin")}
        resp = self.client.post("/api/file/scan", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 413)

    # --- 6. QR SCANNER TESTS ---
    def test_qr_scan_valid_clean_url(self):
        qr_bytes = generate_qr_image_bytes("https://example.com")
        data = {"file": (io.BytesIO(qr_bytes), "clean_qr.png")}
        resp = self.client.post("/api/qr/scan", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        res = resp.get_json()
        self.assertTrue(res["success"])
        self.assertTrue(res["data"]["decoded"])
        self.assertEqual(res["data"]["content"], "https://example.com")
        self.assertTrue(res["data"]["is_url"])
        self.assertEqual(res["data"]["risk_level"], "Low")

    def test_qr_scan_valid_suspicious_url(self):
        qr_bytes = generate_qr_image_bytes("http://192.168.1.1/login")
        data = {"file": (io.BytesIO(qr_bytes), "suspicious_qr.png")}
        resp = self.client.post("/api/qr/scan", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        res = resp.get_json()
        self.assertTrue(res["success"])
        self.assertTrue(res["data"]["decoded"])
        self.assertTrue(res["data"]["is_url"])
        self.assertIn(res["data"]["risk_level"], ("Medium", "High"))

    def test_qr_scan_valid_plain_text(self):
        qr_bytes = generate_qr_image_bytes("WIFI:S:MyNetwork;T:WPA;P:Password123;;")
        data = {"file": (io.BytesIO(qr_bytes), "wifi_qr.png")}
        resp = self.client.post("/api/qr/scan", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        res = resp.get_json()
        self.assertTrue(res["success"])
        self.assertTrue(res["data"]["decoded"])
        self.assertFalse(res["data"]["is_url"])
        self.assertEqual(res["data"]["risk_level"], "Low")

    def test_qr_scan_invalid_image(self):
        # A blank 50x50 white square without a QR code
        blank = np.full((50, 50, 3), 255, dtype=np.uint8)
        _, buffer = cv2.imencode(".png", blank)
        data = {"file": (io.BytesIO(buffer.tobytes()), "blank.png")}
        resp = self.client.post("/api/qr/scan", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)
        res = resp.get_json()
        self.assertFalse(res["success"])
        self.assertIn("QR code tidak dapat dideteksi", res["message"])

    def test_qr_scan_no_file(self):
        resp = self.client.post("/api/qr/scan", data={}, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)

    def test_qr_scan_invalid_format(self):
        bad_file = io.BytesIO(b"not an image text")
        data = {"file": (bad_file, "script.sh")}
        resp = self.client.post("/api/qr/scan", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)

    def test_qr_scan_oversized(self):
        # QR limit is 5MB
        oversized = io.BytesIO(b"A" * (6 * 1024 * 1024))
        data = {"file": (oversized, "huge_qr.png")}
        resp = self.client.post("/api/qr/scan", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 413)

    # --- 7. DASHBOARD & HISTORY TESTS ---
    def test_dashboard_stats(self):
        resp = self.client.get("/api/dashboard/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("summary", data["data"])
        self.assertIn("scans_by_type", data["data"])
        self.assertIn("risk_distribution", data["data"])

    def test_dashboard_activity(self):
        resp_7d = self.client.get("/api/dashboard/activity?period=7d")
        self.assertEqual(resp_7d.status_code, 200)
        d_7d = resp_7d.get_json()
        self.assertEqual(len(d_7d["data"]["timeline"]), 7)

        resp_30d = self.client.get("/api/dashboard/activity?period=30d")
        self.assertEqual(resp_30d.status_code, 200)
        d_30d = resp_30d.get_json()
        self.assertEqual(len(d_30d["data"]["timeline"]), 30)

    def test_empty_dashboard(self):
        # Create isolated empty database
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            empty_db_path = f.name
        try:
            init_db(empty_db_path)
            # Empty scans table
            from backend.database import get_connection
            with get_connection(empty_db_path) as conn:
                conn.execute("DELETE FROM scans")
                conn.commit()

            stats = get_dashboard_stats(empty_db_path)
            self.assertEqual(stats["summary"]["total_scans"], 0)
            self.assertEqual(stats["summary"]["high_risk_count"], 0)
            self.assertEqual(stats["recent_alerts"], [])
            self.assertEqual(stats["recent_activities"], [])

            activity = get_dashboard_activity(empty_db_path, period="7d")
            self.assertEqual(len(activity["timeline"]), 7)
            for day in activity["timeline"]:
                self.assertEqual(day["total"], 0)
        finally:
            import gc
            gc.collect()
            try:
                if os.path.exists(empty_db_path):
                    os.remove(empty_db_path)
            except OSError:
                pass

    def test_history_list_and_filter(self):
        resp = self.client.get("/api/history?type=all&page=1&per_page=10")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("items", data["data"])
        self.assertIn("pagination", data["data"])

        # Fetch first item detail
        if data["data"]["items"]:
            first_id = data["data"]["items"][0]["id"]
            resp_detail = self.client.get(f"/api/history/{first_id}")
            self.assertEqual(resp_detail.status_code, 200)
            self.assertEqual(resp_detail.get_json()["data"]["id"], first_id)

        # 404 on non-existent scan ID
        resp_404 = self.client.get("/api/history/9999999")
        self.assertEqual(resp_404.status_code, 404)


if __name__ == "__main__":
    unittest.main()
