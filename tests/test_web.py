from __future__ import annotations

import json
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from synapseaudit.web import (
    DashboardServer,
    STATIC_DASHBOARD,
    STATIC_LANDING,
    analyze_fixture,
    create_server,
)


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

    def request_html(self, path: str) -> tuple[int, str]:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read().decode("utf-8")
        connection.close()
        return response.status, body

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

    def test_landing_route_serves_public_page(self) -> None:
        status, body = self.request_html("/")

        self.assertEqual(status, 200)
        self.assertIn("SynapseAudit", body)
        self.assertIn("deterministic local Compose analyzer", body)
        self.assertIn('href="/console"', body)

    def test_console_route_serves_dashboard(self) -> None:
        status, body = self.request_html("/console")

        self.assertEqual(status, 200)
        self.assertIn("Compose configuration audit", body)
        self.assertIn("fetch(`/api/analyze?fixture=", body)


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

    def test_dashboard_contract_has_real_sections_and_safe_rendering(self) -> None:
        dashboard = Path(STATIC_DASHBOARD).read_text(encoding="utf-8")

        for section in ("overview", "findings", "attack-paths", "comparison"):
            self.assertIn(f'id="section-{section}"', dashboard)
            self.assertIn(f'data-section="{section}"', dashboard)
        self.assertIn("fetch(`/api/analyze?fixture=", dashboard)
        self.assertIn("Deterministic correlation", dashboard)
        self.assertIn("textContent", dashboard)
        self.assertNotIn("innerHTML", dashboard)

    def test_landing_contract_describes_scope_and_boundaries(self) -> None:
        landing = Path(STATIC_LANDING).read_text(encoding="utf-8")

        for check_id in (
            "PRIVILEGED_CONTAINER",
            "WRITABLE_HOST_BIND",
            "DANGEROUS_CAPABILITY",
            "EXPOSED_SERVICE_PORT",
        ):
            self.assertIn(check_id, landing)
        self.assertIn("PRIVILEGE_TO_SHARED-DATA", landing)
        self.assertIn("No services started", landing)
        self.assertIn("no Docker socket", landing)

    def test_landing_contract_matches_dashboard_theme_and_motion(self) -> None:
        dashboard = Path(STATIC_DASHBOARD).read_text(encoding="utf-8")
        landing = Path(STATIC_LANDING).read_text(encoding="utf-8")

        for token in (
            "--bg: #14171C;",
            "--surface: #1B1F26;",
            "--surface-raised: #222733;",
            "--border: #2B313C;",
            "--text-primary: #E7E5E0;",
            "--text-secondary: #969CA8;",
            "--text-tertiary: #5F6673;",
            "--accent: #C7742F;",
            "--severity-high: #C1453F;",
            "--severity-medium: #B8872E;",
            "--severity-low: #4C8F6F;",
            "--ui: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif;",
            "--data: \"JetBrains Mono\", \"SFMono-Regular\", Consolas, \"Liberation Mono\", monospace;",
        ):
            self.assertIn(token, dashboard)
            self.assertIn(token, landing)
        for keyframe in (
            "@keyframes hero-reveal",
            "@keyframes preview-scan",
            "@keyframes preview-row-in",
            "@keyframes status-pulse",
        ):
            self.assertIn(keyframe, landing)
        self.assertIn("@media (prefers-reduced-motion: reduce)", landing)
        self.assertIn("animation: none !important", landing)
        self.assertGreaterEqual(landing.count('href="/console"'), 3)
        self.assertNotIn("<script", landing.lower())
        self.assertNotIn("gradient", landing.lower())


if __name__ == "__main__":
    unittest.main()
