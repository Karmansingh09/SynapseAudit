from __future__ import annotations

import json
import threading
import unittest
from http.client import HTTPConnection

from synapseaudit.web import DashboardServer, analyze_fixture, create_server


class WebApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server: DashboardServer = create_server(0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, path: str, method: str = "GET") -> tuple[int, dict[str, object]]:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request(method, path)
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        connection.close()
        return response.status, payload

    def test_vulnerable_fixture_endpoint_returns_real_report(self) -> None:
        status, payload = self.request("/api/analyze?fixture=vulnerable")

        self.assertEqual(status, 200)
        findings = payload["findings"]
        attack_paths = payload["attack_paths"]
        self.assertEqual(len(findings), 4)
        self.assertEqual(len(attack_paths), 1)
        self.assertIn(
            "EXPOSED_SERVICE_PORT",
            {finding["id"] for finding in findings},
        )

    def test_remediated_fixture_endpoint_returns_empty_report(self) -> None:
        status, payload = self.request("/api/analyze?fixture=remediated")

        self.assertEqual(status, 200)
        self.assertEqual(payload, {"attack_paths": [], "findings": []})

    def test_allowlisted_analyzer_helper_matches_endpoint_shape(self) -> None:
        report = analyze_fixture("vulnerable")

        self.assertEqual(len(report["findings"]), 4)
        self.assertEqual(len(report["attack_paths"]), 1)

    def test_unknown_fixture_is_rejected(self) -> None:
        status, payload = self.request("/api/analyze?fixture=other")

        self.assertEqual(status, 404)
        self.assertIn("Unknown fixture", payload["error"])

    def test_missing_or_repeated_fixture_is_rejected(self) -> None:
        missing_status, missing_payload = self.request("/api/analyze")
        repeated_status, repeated_payload = self.request(
            "/api/analyze?fixture=vulnerable&fixture=remediated"
        )

        self.assertEqual(missing_status, 400)
        self.assertEqual(repeated_status, 400)
        self.assertIn("exactly one fixture", missing_payload["error"])
        self.assertIn("exactly one fixture", repeated_payload["error"])

    def test_non_get_requests_are_rejected(self) -> None:
        status, payload = self.request("/api/analyze?fixture=vulnerable", method="POST")

        self.assertEqual(status, 405)
        self.assertIn("Only GET", payload["error"])

    def test_dashboard_route_serves_html(self) -> None:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request("GET", "/")
        response = connection.getresponse()
        body = response.read().decode("utf-8")
        connection.close()

        self.assertEqual(response.status, 200)
        self.assertIn("SynapseAudit", body)


class WebServerValidationTests(unittest.TestCase):
    def test_server_rejects_invalid_ports(self) -> None:
        with self.assertRaises(ValueError):
            create_server(-1)
        with self.assertRaises(ValueError):
            create_server(65536)
        with self.assertRaises(ValueError):
            create_server(True)

    def test_server_rejects_a_port_that_is_already_bound(self) -> None:
        first_server = create_server(0)
        try:
            occupied_port = first_server.server_address[1]
            with self.assertRaises(OSError):
                create_server(occupied_port)
        finally:
            first_server.server_close()


if __name__ == "__main__":
    unittest.main()
