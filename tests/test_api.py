"""Comprehensive unit tests for PhishGuard unified Flask application and APIs.
"""
import unittest
import tempfile
from app import app
from database import init_db


class PhishGuardTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = f"{cls.temp_dir.name}/test_phishguard.db"
        app.config["DATABASE"] = cls.db_path
        app.config["TESTING"] = True
        init_db(cls.db_path)
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_01_dashboard_page_and_api(self):
        # HTML Page
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"PHISHGUARD", res.data)

        # JSON API
        res = self.client.get("/api/dashboard")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("total_scans", data["data"])

    def test_02_url_scanner_api(self):
        # 1. Safe URL
        res = self.client.post("/api/scan-url", json={"url": "https://google.com"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["risk_level"], "Low")

        # 2. Phishing URL (IP hostname + HTTP + login keyword)
        res = self.client.post("/api/scan-url", json={"url": "http://192.168.1.1/login-verify-account"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn(data["data"]["risk_level"], ["Medium", "High"])
        self.assertGreaterEqual(data["data"]["risk_score"], 40)

        # 3. Watchlist hit URL
        res = self.client.post("/api/scan-url", json={"url": "https://phishing-bank-login.com/portal"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["risk_level"], "High")
        self.assertGreaterEqual(data["data"]["risk_score"], 70)

    def test_03_qr_scanner_api(self):
        with open("tests/sample_qr.png", "rb") as f:
            res = self.client.post("/api/scan-qr", data={"file": f}, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["data"]["decoded"])
        self.assertEqual(data["data"]["content"], "https://example.com")

    def test_04_email_analyzer_api(self):
        payload = {
            "subject": "URGENT: Verify your account immediately",
            "body": "Dear customer, your bank transfer is on hold. Please visit http://192.168.1.100/login to confirm your identity."
        }
        res = self.client.post("/api/scan-email", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("urgent", data["data"]["detected_keywords"])
        self.assertEqual(len(data["data"]["extracted_urls"]), 1)
        self.assertGreaterEqual(data["data"]["risk_score"], 50)

    def test_05_watchlist_crud_api(self):
        # 1. Add domain
        res = self.client.post("/api/watchlist", json={
            "domain": "test-malware-feed.net",
            "description": "Added via unit test"
        })
        self.assertEqual(res.status_code, 201)
        entry_id = res.get_json()["data"]["id"]

        # 2. Get list
        res = self.client.get("/api/watchlist")
        self.assertEqual(res.status_code, 200)
        domains = [item["domain"] for item in res.get_json()["data"]]
        self.assertIn("test-malware-feed.net", domains)

        # 3. Delete domain
        res = self.client.delete(f"/api/watchlist/{entry_id}")
        self.assertEqual(res.status_code, 200)

        # 4. Confirm deleted
        res = self.client.get("/api/watchlist")
        domains = [item["domain"] for item in res.get_json()["data"]]
        self.assertNotIn("test-malware-feed.net", domains)

    def test_06_history_api(self):
        res = self.client.get("/api/history")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIsInstance(data["data"], list)
        self.assertGreater(len(data["data"]), 0)

    def test_07_all_web_pages(self):
        pages = ["/", "/url-scanner", "/qr-shield", "/mailguard", "/watchlist", "/history"]
        for path in pages:
            res = self.client.get(path)
            self.assertEqual(res.status_code, 200, f"Page {path} failed to render.")


if __name__ == "__main__":
    unittest.main()
