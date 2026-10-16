from __future__ import annotations

import json
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from synapseaudit.web import (
    CONTENT_SECURITY_POLICY,
    DashboardServer,
    STATIC_DASHBOARD,
    STATIC_LANDING,
    analyze_fixture,
    create_server,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


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

    def request_raw(self, path: str, method: str = "GET") -> tuple[int, dict[str, str], bytes]:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request(method, path)
        response = connection.getresponse()
        body = response.read()
        headers = {name: value for name, value in response.getheaders()}
        connection.close()
        return response.status, headers, body

    def request(self, path: str, method: str = "GET") -> tuple[int, dict[str, object]]:
        status, _, body = self.request_raw(path, method)
        return status, json.loads(body.decode("utf-8"))

    def request_html(self, path: str) -> tuple[int, str]:
        status, _, body = self.request_raw(path)
        return status, body.decode("utf-8")

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

    def test_security_headers_apply_to_pages_api_and_errors(self) -> None:
        expected_headers = {
            "Cache-Control": "no-store",
            "Content-Security-Policy": CONTENT_SECURITY_POLICY,
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }
        requests = (
            ("/", 200),
            ("/console", 200),
            ("/api/analyze?fixture=vulnerable", 200),
            ("/api/analyze?fixture=other", 404),
            ("/missing", 404),
        )
        for path, expected_status in requests:
            with self.subTest(path=path):
                status, headers, _ = self.request_raw(path)
                self.assertEqual(status, expected_status)
                for name, value in expected_headers.items():
                    self.assertEqual(headers.get(name), value)

        status, headers, body = self.request_raw(
            "/api/analyze?fixture=vulnerable", method="POST"
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET")
        for name, value in expected_headers.items():
            self.assertEqual(headers.get(name), value)
        self.assertIn("Only GET", body.decode("utf-8"))

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
        self.assertIn('<script src="/static/dashboard.js"></script>', body)
        self.assertNotIn("<script>", body)

    def test_dashboard_script_route_serves_external_behavior(self) -> None:
        status, headers, body = self.request_raw("/static/dashboard.js")

        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/javascript; charset=utf-8")
        self.assertIn("fetch(`/api/analyze?fixture=", body.decode("utf-8"))


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
        script = Path(STATIC_DASHBOARD).with_name("dashboard.js").read_text(encoding="utf-8")

        for section in ("overview", "findings", "attack-paths", "comparison"):
            self.assertIn(f'id="section-{section}"', dashboard)
            self.assertIn(f'data-section="{section}"', dashboard)
        for element_id in (
            "fixture-select",
            "analyze-button",
            "retry-button",
            "error-banner",
            "error-message",
            "stat-row",
            "topbar-status",
            "analysis-status",
            "overview-status",
            "current-fixture-label",
            "source-file",
            "metric-total",
            "metric-high",
            "metric-medium",
            "metric-paths",
            "findings-caption",
            "findings-count",
            "findings-table-body",
            "finding-detail",
            "attack-content",
            "comparison-table-body",
        ):
            self.assertIn(f'id="{element_id}"', dashboard)
        self.assertIn('<script src="/static/dashboard.js"></script>', dashboard)
        self.assertIn("fetch(`/api/analyze?fixture=", script)
        self.assertIn("Deterministic correlation", script)
        self.assertIn("textContent", script)
        self.assertNotIn("innerHTML", script)

    def test_dashboard_contract_has_forensic_console_regions_and_motion(self) -> None:
        dashboard = Path(STATIC_DASHBOARD).read_text(encoding="utf-8")

        for console_token in (
            "LOCAL / READ-ONLY",
            "class=\"guardrail\"",
            "class=\"overview-context\"",
            "class=\"risk-panel\"",
            "Evidence inspector",
            "path-card",
            "comparison-board-summary",
            "risk-high-bar",
        ):
            self.assertIn(console_token, dashboard)
        for keyframe in (
            "@keyframes status-pulse",
            "@keyframes stat-reveal",
            "@keyframes evidence-crossfade",
            "@keyframes path-node-in",
            "@keyframes delta-in",
        ):
            self.assertIn(keyframe, dashboard)
        self.assertIn("@media (prefers-reduced-motion: reduce)", dashboard)
        self.assertIn("animation-duration: .001ms !important", dashboard)
        self.assertNotIn("gradient", dashboard.lower())
        self.assertNotIn("purple", dashboard.lower())

    def test_dockerfile_configures_a_dedicated_non_root_user(self) -> None:
        dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

        self.assertIn("addgroup --system --gid 10001 synapseaudit", dockerfile)
        self.assertIn("adduser --system --uid 10001", dockerfile)
        self.assertIn("USER synapseaudit:synapseaudit", dockerfile)
        self.assertNotIn("USER root", dockerfile)

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

    def test_landing_contract_matches_industrial_palette_and_motion(self) -> None:
        landing = Path(STATIC_LANDING).read_text(encoding="utf-8")

        for token in (
            "--ink: #161817;",
            "--paper: #f1e9db;",
            "--orange: #e27a35;",
            "--steel: #718995;",
        ):
            self.assertIn(token, landing)
        for keyframe in (
            "@keyframes scan-sweep",
            "@keyframes resolve-evidence",
            "@keyframes signal-travel",
            "@keyframes status-flicker",
        ):
            self.assertIn(keyframe, landing)
        for board_class in (
            'class="inspection-board"',
            'class="scan-marker"',
            'class="signal-trace"',
            'class="evidence-token"',
        ):
            self.assertIn(board_class, landing)
        self.assertIn("@media (prefers-reduced-motion: reduce)", landing)
        self.assertIn("animation: none !important", landing)
        self.assertGreaterEqual(landing.count('href="/console"'), 3)
        self.assertNotIn("<script", landing.lower())
        self.assertNotIn("gradient", landing.lower())
        self.assertNotIn("purple", landing.lower())


if __name__ == "__main__":
    unittest.main()
