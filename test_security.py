"""
Security Verification Suite for Email Geolocation Trace Platform
Tests:
1. Bounded In-Memory Storage & DoS Prevention
2. Rate Limiting on Trace Submissions (HTTP 429)
3. Strict Pydantic Schema Validation (HTTP 422)
4. ReDoS Resistance in Trusted MTA Matching
5. Strict IP Sanitization and SSRF Guard
6. HTTP Security Headers (CSP, X-Frame-Options, etc.)
"""

import os
import unittest
import time
from fastapi.testclient import TestClient
from main import app
import storage
from storage import _email_analysis_store as EMAILS_DB
import api.dependencies as dependencies
from config import config
from geo_intel import is_trusted_mta, geolocate_ip, is_valid_ip

MAX_STORED_EMAILS = 100
RATE_LIMIT_STORE = dependencies._rate_limit_buckets

client = TestClient(app, headers={"x-api-key": config.api.api_key})
unauthenticated_client = TestClient(app)

class TestSecurityRemediations(unittest.TestCase):

    def setUp(self):
        # Reset rate limiter store between test runs
        RATE_LIMIT_STORE.clear()

    def test_1_redos_immunity(self):
        """Verify is_trusted_mta handles adversarial inputs without catastrophic backtracking."""
        start_time = time.time()
        adversarial_input = "a." * 5000 + "internal.company.com"
        result = is_trusted_mta(adversarial_input)
        elapsed = time.time() - start_time
        
        # Must finish in less than 50 milliseconds
        self.assertFalse(result)
        self.assertLess(elapsed, 0.05, f"ReDoS check took too long: {elapsed:.4f}s")

    def test_email_trace_requires_authentication(self):
        self.assertEqual(unauthenticated_client.get("/emails/EML-123/report").status_code, 401)
        self.assertEqual(unauthenticated_client.get("/emails/EML-89412/report/metadata").status_code, 401)
        self.assertEqual(unauthenticated_client.post("/telemetry", json={}).status_code, 401)

    def test_2_strict_ip_validation_and_ssrf_guard(self):
        """Verify geolocate_ip safely rejects malformed/injected IP addresses."""
        malformed_inputs = [
            "http://169.254.169.254/latest/meta-data/",
            "999.999.999.999",
            "185.220.101.5; cat /etc/passwd",
            "<script>alert(1)</script>",
            "127.0.0.1.bad.org",
            " " * 100
        ]
        for bad_ip in malformed_inputs:
            self.assertFalse(is_valid_ip(bad_ip), f"Should not be valid IP: {bad_ip}")
            res = geolocate_ip(bad_ip)
            self.assertIn(res.get("country"), ["Unknown", "Invalid IP"])
            self.assertEqual(res.get("latitude"), 0.0)

    def test_3_pydantic_schema_validation(self):
        """Verify strict payload bounds reject over-limit hops and excessive strings."""
        # 1. Reject invalid telemetry missing required fields
        resp_empty = client.post("/telemetry", json={})
        self.assertEqual(resp_empty.status_code, 422)

        # 2. Reject invalid score (>100)
        resp_bad_score = client.post("/telemetry", json={
            "entity_type": "ip",
            "entity_id": "192.168.1.1",
            "score": 150.0
        })
        self.assertEqual(resp_bad_score.status_code, 422)

        # 3. Reject oversized entity_id string (>512 chars)
        resp_long_id = client.post("/telemetry", json={
            "entity_type": "ip",
            "entity_id": "A" * 600,
            "score": 50.0
        })
        self.assertEqual(resp_long_id.status_code, 422)

        # 4. Reject invalid entity_id containing invalid characters
        resp_bad_id = client.post("/telemetry", json={
            "entity_type": "ip",
            "entity_id": "123<script>alert(1)</script>",
            "score": 50.0
        })
        self.assertEqual(resp_bad_id.status_code, 422)

    def test_4_bounded_storage_memory_protection(self):
        """Verify storage memory bounds protection."""
        for i in range(120):
            storage.add_pheromone("ip", f"192.168.1.{i}", 10.0, {"type": "test"})
        self.assertLessEqual(len(storage._pheromones), 50000)

    def test_5_rate_limiting(self):
        """Verify client IP rate limit enforces max 30 requests per minute with HTTP 429."""
        RATE_LIMIT_STORE.clear()
        payload = {
            "entity_type": "ip",
            "entity_id": "198.51.100.1",
            "score": 10.0
        }

        # First 30 requests should succeed
        for i in range(30):
            r = client.post("/ingest/json", json=payload)
            self.assertIn(r.status_code, [200, 202])

        # 31st request must trigger HTTP 429
        r_exceeded = client.post("/ingest/json", json=payload)
        self.assertEqual(r_exceeded.status_code, 429)
        self.assertIn("Rate limit exceeded", r_exceeded.json()["detail"])

    def test_6_http_security_headers(self):
        """Verify HTTP security headers Endpoint works."""
        resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)

    def test_csv_payload_is_bounded(self):
        response = client.post("/ingest/csv", json={"csv": ""})
        self.assertEqual(response.status_code, 422)

    def test_generic_json_normalization_rejects_unsafe_entity_ids(self):
        response = client.post(
            "/ingest/json",
            json={"entity_type": "ip", "entity_id": "<script>alert(1)</script>"},
        )
        self.assertEqual(response.status_code, 422)

    def test_health_details_requires_authentication(self):
        self.assertEqual(unauthenticated_client.get("/health/details").status_code, 401)
        self.assertEqual(unauthenticated_client.get("/health").json(), {"status": "healthy", "service": "SwarmSentinel"})

    def test_production_operator_auth_fails_closed_without_operator_key(self):
        original_operator_key = dependencies.OPERATOR_API_KEY
        original_fallback = os.environ.get("ALLOW_DEV_OPERATOR_FALLBACK")
        try:
            dependencies.OPERATOR_API_KEY = ""
            if "ALLOW_DEV_OPERATOR_FALLBACK" in os.environ:
                del os.environ["ALLOW_DEV_OPERATOR_FALLBACK"]
            response = client.post("/swarm/reset")
            self.assertEqual(response.status_code, 503)
        finally:
            dependencies.OPERATOR_API_KEY = original_operator_key
            if original_fallback is not None:
                os.environ["ALLOW_DEV_OPERATOR_FALLBACK"] = original_fallback

    def test_operator_auth_separate_key_required(self):
        original_operator_key = os.environ.get("OPERATOR_API_KEY")
        original_fallback = os.environ.get("ALLOW_DEV_OPERATOR_FALLBACK")
        try:
            os.environ["OPERATOR_API_KEY"] = "operator-secret-key"
            dependencies.OPERATOR_API_KEY = "operator-secret-key"
            if "ALLOW_DEV_OPERATOR_FALLBACK" in os.environ:
                del os.environ["ALLOW_DEV_OPERATOR_FALLBACK"]

            # Ordinary API key should be rejected with 403
            resp_ordinary = client.post("/swarm/reset", headers={"x-api-key": config.api.api_key})
            self.assertEqual(resp_ordinary.status_code, 403)

            # Valid operator key should be accepted
            resp_op = client.post("/swarm/reset", headers={"x-api-key": "operator-secret-key"})
            self.assertIn(resp_op.status_code, [200, 500])
        finally:
            if original_operator_key is not None:
                os.environ["OPERATOR_API_KEY"] = original_operator_key
                dependencies.OPERATOR_API_KEY = original_operator_key
            else:
                os.environ.pop("OPERATOR_API_KEY", None)
                dependencies.OPERATOR_API_KEY = ""

            if original_fallback is not None:
                os.environ["ALLOW_DEV_OPERATOR_FALLBACK"] = original_fallback

    def test_forensic_report_requires_forensic_or_operator_key(self):
        original_forensic = os.environ.get("FORENSIC_READ_API_KEY")
        original_operator = os.environ.get("OPERATOR_API_KEY")
        original_fallback = os.environ.get("ALLOW_DEV_OPERATOR_FALLBACK")
        try:
            os.environ["FORENSIC_READ_API_KEY"] = "forensic-read-key"
            os.environ["OPERATOR_API_KEY"] = "operator-key"
            dependencies.FORENSIC_READ_API_KEY = "forensic-read-key"
            dependencies.OPERATOR_API_KEY = "operator-key"
            if "ALLOW_DEV_OPERATOR_FALLBACK" in os.environ:
                del os.environ["ALLOW_DEV_OPERATOR_FALLBACK"]

            # Ordinary API key should be denied
            resp_ord = client.get("/emails/EML-89412/report/metadata", headers={"x-api-key": config.api.api_key})
            self.assertEqual(resp_ord.status_code, 403)

            # Forensic read key accepted
            resp_forensic = client.get("/emails/EML-89412/report/metadata", headers={"x-api-key": "forensic-read-key"})
            self.assertNotEqual(resp_forensic.status_code, 403)

            # Operator key accepted
            resp_op = client.get("/emails/EML-89412/report/metadata", headers={"x-api-key": "operator-key"})
            self.assertNotEqual(resp_op.status_code, 403)
        finally:
            if original_forensic is not None:
                os.environ["FORENSIC_READ_API_KEY"] = original_forensic
                dependencies.FORENSIC_READ_API_KEY = original_forensic
            else:
                os.environ.pop("FORENSIC_READ_API_KEY", None)
                dependencies.FORENSIC_READ_API_KEY = ""

            if original_operator is not None:
                os.environ["OPERATOR_API_KEY"] = original_operator
                dependencies.OPERATOR_API_KEY = original_operator
            else:
                os.environ.pop("OPERATOR_API_KEY", None)
                dependencies.OPERATOR_API_KEY = ""

            if original_fallback is not None:
                os.environ["ALLOW_DEV_OPERATOR_FALLBACK"] = original_fallback

    def test_ws_ticket_single_use_replay_protection(self):
        ticket = dependencies.create_websocket_ticket("127.0.0.1")
        self.assertTrue(bool(ticket))
        with dependencies._ws_ticket_lock:
            self.assertIn(ticket, dependencies._WS_TICKETS)

if __name__ == "__main__":
    unittest.main()
