from __future__ import annotations

import base64
import json
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from synapseaudit.web import (
    CONTENT_SECURITY_POLICY,
    DashboardServer,
    GITHUB_SCAN_ENDPOINT,
    MAX_SCAN_REQUEST_BYTES,
    MAX_UPLOAD_BYTES,
    MAX_UPLOAD_REQUEST_BYTES,
    UPLOAD_ENDPOINT,
    UPLOAD_FIELD_NAME,
    STATIC_DASHBOARD,
    STATIC_LANDING,
    analyze_fixture,
    create_server,
    _redact_request_log,
)
from synapseaudit.github import GitHubConfig, GitHubService, RepositoryScanResult, ScanLimits


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

    def request_raw(
        self,
        path: str,
        method: str = "GET",
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> tuple[int, dict[str, str], bytes]:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.request(method, path, body=body, headers=headers or {})
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

    @staticmethod
    def multipart_body(
        content: bytes,
        *,
        filename: str = "compose.yml",
        field_name: str = UPLOAD_FIELD_NAME,
        boundary: str = "----synapseaudit-test-boundary",
    ) -> tuple[bytes, dict[str, str]]:
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
            "Content-Type: application/x-yaml\r\n"
            "\r\n"
        ).encode("utf-8") + content + f"\r\n--{boundary}--\r\n".encode("ascii")
        return body, {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        }

    def upload(self, content: bytes, **kwargs: str) -> tuple[int, dict[str, str], bytes]:
        body, headers = self.multipart_body(content, **kwargs)
        return self.request_raw(UPLOAD_ENDPOINT, method="POST", headers=headers, body=body)

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

    def test_valid_upload_returns_vulnerable_report_schema(self) -> None:
        expected = json.loads(json.dumps(analyze_fixture("vulnerable")))
        status, headers, body = self.upload(
            Path(PROJECT_ROOT / "fixtures" / "compose.vulnerable.yml").read_bytes()
        )
        payload = json.loads(body.decode("utf-8"))

        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(payload, expected)
        self.assertEqual(set(payload), {"findings", "attack_paths"})
        for finding in payload["findings"]:
            for field in ("id", "severity", "title", "explanation", "impact", "evidence", "remediation", "limitations"):
                self.assertTrue(finding[field])
        self.assertEqual(
            payload["attack_paths"][0]["classification"],
            "deterministic_hypothetical_correlation",
        )
        self.assertIn("not proof of exploitation", payload["attack_paths"][0]["limitations"])

    def test_valid_remediated_upload_returns_empty_report(self) -> None:
        status, _, body = self.upload(
            Path(PROJECT_ROOT / "fixtures" / "compose.remediated.yml").read_bytes()
        )

        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body.decode("utf-8")), {"attack_paths": [], "findings": []})

    def test_upload_accepts_all_supported_rule_conditions(self) -> None:
        content = b"""services:
  audit-demo:
    privileged: true
    cap_add: [SYS_ADMIN]
    ports: [\"8080:80\"]
    volumes: [./fixture-data:/app/data:rw]
"""
        status, _, body = self.upload(content)
        payload = json.loads(body.decode("utf-8"))

        self.assertEqual(status, 200)
        self.assertEqual(
            {finding["id"] for finding in payload["findings"]},
            {
                "PRIVILEGED_CONTAINER",
                "DANGEROUS_CAPABILITY",
                "EXPOSED_SERVICE_PORT",
                "WRITABLE_HOST_BIND",
            },
        )

    def test_upload_rejects_missing_empty_invalid_and_non_compose_files(self) -> None:
        cases = (
            (b"", {"field_name": "other", "filename": "compose.yml"}, "field"),
            (b"", {}, "empty"),
            (b"services:\n  broken: [\n", {}, "yaml"),
            (b"\xff\xfe", {}, "utf8"),
            (b"name: not-compose\n", {}, "structure"),
        )
        for content, options, label in cases:
            with self.subTest(label=label):
                if options:
                    body, headers = self.multipart_body(content, **options)
                    status, _, response_body = self.request_raw(
                        UPLOAD_ENDPOINT, method="POST", headers=headers, body=body
                    )
                else:
                    status, _, response_body = self.upload(content)
                self.assertEqual(status, 400)
                self.assertIn("error", json.loads(response_body.decode("utf-8")))

    def test_upload_rejects_oversized_requests_and_malformed_multipart(self) -> None:
        oversized_headers = {
            "Content-Type": "multipart/form-data; boundary=unused",
            "Content-Length": str(MAX_UPLOAD_REQUEST_BYTES + 1),
        }
        status, _, body = self.request_raw(
            UPLOAD_ENDPOINT, method="POST", headers=oversized_headers
        )
        self.assertEqual(status, 413)
        self.assertIn("limit", json.loads(body.decode("utf-8"))["error"])

        malformed_headers = {
            "Content-Type": "multipart/form-data; boundary=broken",
            "Content-Length": "12",
        }
        status, _, body = self.request_raw(
            UPLOAD_ENDPOINT,
            method="POST",
            headers=malformed_headers,
            body=b"not multipart",
        )
        self.assertEqual(status, 400)
        self.assertIn("Multipart", json.loads(body.decode("utf-8"))["error"])

    def test_upload_accepts_max_file_size_and_rejects_oversized_file(self) -> None:
        prefix = b"services:\n  web:\n    image: "
        suffix = b"\n"
        content = prefix + (b"a" * (MAX_UPLOAD_BYTES - len(prefix) - len(suffix))) + suffix

        status, _, body = self.upload(content)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body.decode("utf-8")), {"attack_paths": [], "findings": []})

        status, _, body = self.upload(content + b"a")
        self.assertEqual(status, 413)
        self.assertIn("1 MiB", json.loads(body.decode("utf-8"))["error"])

    def test_upload_rejects_incorrect_content_type_and_wrong_methods(self) -> None:
        headers = {"Content-Type": "application/x-yaml", "Content-Length": "3"}
        status, _, body = self.request_raw(
            UPLOAD_ENDPOINT, method="POST", headers=headers, body=b"a: b"
        )
        self.assertEqual(status, 400)
        self.assertIn("multipart/form-data", json.loads(body.decode("utf-8"))["error"])

        status, headers, body = self.request_raw(UPLOAD_ENDPOINT)
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "POST")
        self.assertIn("Only POST", json.loads(body.decode("utf-8"))["error"])

    def test_upload_filename_is_not_used_as_a_path_and_failure_does_not_break_server(self) -> None:
        fixture_data = PROJECT_ROOT / "fixtures" / "fixture-data"
        before = sorted(path.relative_to(fixture_data).as_posix() for path in fixture_data.rglob("*"))
        status, _, body = self.upload(
            Path(PROJECT_ROOT / "fixtures" / "compose.vulnerable.yml").read_bytes(),
            filename="../../outside.yml",
        )
        after = sorted(path.relative_to(fixture_data).as_posix() for path in fixture_data.rglob("*"))

        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body.decode("utf-8"))["findings"]), 4)
        self.assertEqual(before, after)

        status, _, body = self.upload(
            Path(PROJECT_ROOT / "fixtures" / "compose.vulnerable.yml").read_bytes(),
            filename="compose.txt",
        )
        self.assertEqual(status, 400)
        self.assertIn(".yml", json.loads(body.decode("utf-8"))["error"])

        self.upload(b"not: [valid")
        status, _, body = self.upload(
            Path(PROJECT_ROOT / "fixtures" / "compose.remediated.yml").read_bytes()
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body.decode("utf-8")), {"attack_paths": [], "findings": []})

    def test_repeated_uploads_replace_the_report_without_server_state_leakage(self) -> None:
        vulnerable_status, _, vulnerable_body = self.upload(
            Path(PROJECT_ROOT / "fixtures" / "compose.vulnerable.yml").read_bytes()
        )
        remediated_status, _, remediated_body = self.upload(
            Path(PROJECT_ROOT / "fixtures" / "compose.remediated.yml").read_bytes()
        )

        vulnerable_payload = json.loads(vulnerable_body.decode("utf-8"))
        remediated_payload = json.loads(remediated_body.decode("utf-8"))
        self.assertEqual(vulnerable_status, 200)
        self.assertEqual(remediated_status, 200)
        self.assertEqual(len(vulnerable_payload["findings"]), 4)
        self.assertEqual(len(vulnerable_payload["attack_paths"]), 1)
        self.assertEqual(remediated_payload, {"attack_paths": [], "findings": []})

    def test_upload_responses_keep_security_headers(self) -> None:
        body, headers = self.multipart_body(
            Path(PROJECT_ROOT / "fixtures" / "compose.remediated.yml").read_bytes()
        )
        status, response_headers, _ = self.request_raw(
            UPLOAD_ENDPOINT, method="POST", headers=headers, body=body
        )

        self.assertEqual(status, 200)
        for name, value in {
            "Cache-Control": "no-store",
            "Content-Security-Policy": CONTENT_SECURITY_POLICY,
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }.items():
            self.assertEqual(response_headers.get(name), value)

        error_status, error_headers, _ = self.request_raw(
            UPLOAD_ENDPOINT,
            method="POST",
            headers={"Content-Type": "application/x-yaml", "Content-Length": "3"},
            body=b"bad",
        )
        self.assertEqual(error_status, 400)
        for name, value in {
            "Cache-Control": "no-store",
            "Content-Security-Policy": CONTENT_SECURITY_POLICY,
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }.items():
            self.assertEqual(error_headers.get(name), value)

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
            ("/api/github/status", 200),
            ("/api/github/connect", 503),
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


class GitHubLocalOnlyWebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = create_server(0, github_service=GitHubService(None))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request_raw(
        self,
        path: str,
        method: str = "GET",
        *,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        body = response.read()
        response_headers = {name: value for name, value in response.getheaders()}
        connection.close()
        return response.status, response_headers, body

    def test_local_only_status_is_safe_and_fixture_api_remains_available(self) -> None:
        status, headers, body = self.request_raw("/api/github/status")
        payload = json.loads(body.decode("utf-8"))

        self.assertEqual(status, 200)
        self.assertFalse(payload["configured"])
        self.assertFalse(payload["connected"])
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Lax", headers["Set-Cookie"])

        fixture_status, _, fixture_body = self.request_raw("/api/analyze?fixture=remediated")
        self.assertEqual(fixture_status, 200)
        self.assertEqual(json.loads(fixture_body.decode("utf-8")), {"attack_paths": [], "findings": []})

    def test_local_only_github_routes_fail_without_attempting_external_access(self) -> None:
        connect_status, _, connect_body = self.request_raw("/api/github/connect")
        repositories_status, _, repositories_body = self.request_raw("/api/github/repositories")

        self.assertEqual(connect_status, 503)
        self.assertIn("not configured", json.loads(connect_body.decode("utf-8"))["error"])
        self.assertEqual(repositories_status, 401)
        self.assertIn("authorization is required", json.loads(repositories_body.decode("utf-8"))["error"])

    def test_local_only_scan_requires_authorization(self) -> None:
        body = json.dumps({"owner": "octo", "repository": "allowed", "branch": "main"}).encode("utf-8")
        status, _, response_body = self.request_raw(
            GITHUB_SCAN_ENDPOINT,
            method="POST",
            headers={"Content-Length": str(len(body)), "Content-Type": "application/json"},
        )

        self.assertEqual(status, 401)
        self.assertIn("authorization is required", json.loads(response_body.decode("utf-8"))["error"])

    def test_scan_request_body_is_bounded(self) -> None:
        from synapseaudit.github import GitHubConfig

        service = GitHubService(
            GitHubConfig(
                app_id=1,
                app_slug="synapseaudit",
                private_key_path=PROJECT_ROOT / "not-used.pem",
                callback_url="https://audit.example.test/api/github/callback",
            ),
            client=object(),
        )
        session, _ = service.ensure_session(None)
        service.sessions.set_connection(session, 1, "server-side-token", 4_102_444_800.0)
        server = create_server(0, github_service=service, dashboard_password="test-password")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        body = b"{}"
        auth_header = "Basic " + base64.b64encode(b"admin:test-password").decode("ascii")
        try:
            connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
            connection.request(
                "POST",
                GITHUB_SCAN_ENDPOINT,
                body=body,
                headers={
                    "Authorization": auth_header,
                    "Cookie": f"synapseaudit_session={session.session_id}",
                    "Content-Length": str(MAX_SCAN_REQUEST_BYTES + 1),
                    "Content-Type": "application/json",
                    "X-CSRF-Token": session.csrf_token,
                },
            )
            response = connection.getresponse()
            response_body = response.read()
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(response.status, 413)
        self.assertIn("bounded request", json.loads(response_body.decode("utf-8"))["error"])

    def test_authenticated_scan_route_requires_csrf_and_returns_integrity_envelope(self) -> None:
        class ScanClient:
            def scan_repository(self, token, owner, repository, branch, *, limits, budget):
                self.arguments = (token, owner, repository, branch, limits, budget)
                return RepositoryScanResult(
                    repository=f"{owner}/{repository}",
                    branch=branch,
                    commit_sha="a" * 40,
                    status="complete",
                    files=(),
                    skipped=(),
                    skipped_counts={},
                    limited_reasons=(),
                    limits=limits.to_dict(),
                    usage=budget.usage(),
                )

        client = ScanClient()
        service = GitHubService(
            GitHubConfig(
                app_id=1,
                app_slug="synapseaudit",
                private_key_path=PROJECT_ROOT / "not-used.pem",
                callback_url="https://audit.example.test/api/github/callback",
            ),
            client=client,
            scan_limits=ScanLimits(max_api_requests=3),
        )
        session, _ = service.ensure_session(None)
        service.sessions.set_connection(session, 1, "server-side-token", 4_102_444_800.0)
        server = create_server(0, github_service=service, dashboard_password="test-password")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        body = json.dumps({"owner": "octo", "repository": "allowed", "branch": "main"}).encode("utf-8")
        auth_header = "Basic " + base64.b64encode(b"admin:test-password").decode("ascii")
        try:
            connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
            headers = {
                "Authorization": auth_header,
                "Cookie": f"synapseaudit_session={session.session_id}",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "X-CSRF-Token": "wrong",
            }
            connection.request("POST", GITHUB_SCAN_ENDPOINT, body=body, headers=headers)
            rejected = connection.getresponse()
            rejected_body = rejected.read()
            connection.close()

            connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
            headers["X-CSRF-Token"] = session.csrf_token
            connection.request("POST", GITHUB_SCAN_ENDPOINT, body=body, headers=headers)
            accepted = connection.getresponse()
            accepted_body = accepted.read()
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(rejected.status, 403)
        self.assertEqual(accepted.status, 200)
        payload = json.loads(accepted_body.decode("utf-8"))
        self.assertEqual(payload["commit_sha"], "a" * 40)
        self.assertEqual(payload["status"], "complete")
        self.assertNotIn("server-side-token", accepted_body.decode("utf-8"))
        self.assertEqual(client.arguments[:4], ("server-side-token", "octo", "allowed", "main"))

    def test_github_unsupported_method_is_rejected(self) -> None:
        status, headers, body = self.request_raw("/api/github/status", method="PUT")

        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "GET, POST")
        self.assertIn("not supported", json.loads(body.decode("utf-8"))["error"])

        status, headers, body = self.request_raw(GITHUB_SCAN_ENDPOINT)
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "GET, POST")
        self.assertIn("not supported", json.loads(body.decode("utf-8"))["error"])

    def test_github_callback_log_redacts_sensitive_query_parameters(self) -> None:
        message = (
            '"GET /api/github/callback?state=secret-state&installation_id=42&setup_action=install '
            'HTTP/1.1" 400 -'
        )

        redacted = _redact_request_log(message)

        self.assertNotIn("secret-state", redacted)
        self.assertNotIn("installation_id=42", redacted)
        self.assertNotIn("setup_action=install", redacted)
        self.assertIn("/api/github/callback?[redacted]", redacted)


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
            "compose-file",
            "upload-button",
            "upload-filename",
            "retry-button",
            "error-banner",
            "error-message",
            "stat-row",
            "topbar-status",
            "analysis-status",
            "overview-status",
            "summary-copy",
            "current-fixture-label",
            "source-file",
            "metric-total",
            "metric-high",
            "metric-medium",
            "metric-paths",
            "findings-count",
            "findings-table-body",
            "finding-detail",
            "attack-content",
            "comparison-note",
            "comparison-table-body",
            "github-connect-button",
            "github-disconnect-button",
            "github-status",
            "github-panel",
            "github-selection",
            "github-repository-select",
            "github-branch-select",
            "start-scan-button",
            "github-scope",
            "github-scan-result",
        ):
            self.assertIn(f'id="{element_id}"', dashboard)
        self.assertIn('<script src="/static/dashboard.js"></script>', dashboard)
        self.assertIn("fetch(`/api/analyze?fixture=", script)
        self.assertIn("/api/analyze-upload", script)
        self.assertIn("FormData", script)
        self.assertIn('method: "POST"', script)
        self.assertIn("compose_file", script)
        self.assertIn("MAX_UPLOAD_BYTES", script)
        self.assertIn("clearDisplayedReport", script)
        self.assertIn("clearFixtures: false", script)
        self.assertIn("fetchFixtureReports", script)
        self.assertIn("reports = await fetchFixtureReports()", script)
        self.assertIn("const renderedReport = currentReport", script)
        self.assertIn("Upload rejected", script)
        self.assertIn("No uploaded report is displayed", script)
        self.assertIn("Fixture baseline unavailable", script)
        self.assertIn("Built-in fixtures:", script)
        self.assertIn("reportSource = \"upload\"", script)
        self.assertIn("file.name", script)
        self.assertIn("Uploaded YAML", script)
        self.assertIn("What the configuration does", script)
        self.assertIn("Potential impact", script)
        self.assertIn("Limitations & assumptions", script)
        self.assertIn("deterministic_hypothetical_correlation", script)
        self.assertIn("Uploaded results are shown separately", script)
        self.assertIn("Built-in fixture baseline only", dashboard)
        self.assertIn("Connect GitHub", dashboard)
        self.assertIn("Start security scan", dashboard)
        self.assertIn("Phase 2 scope", dashboard)
        self.assertIn("Unsupported files are skipped", dashboard)
        self.assertIn("/api/github/status", script)
        self.assertIn("/api/github/connect", script)
        self.assertIn("/api/github/repositories", script)
        self.assertIn("/api/github/scan", script)
        self.assertIn("immutable commit SHA", script)
        self.assertIn("commit_sha", script)
        self.assertIn("file_path", script)
        self.assertIn("no_supported_files", script)
        self.assertIn("not a clean repository assessment", script)
        self.assertIn("Skipped files:", script)
        self.assertIn("githubScanGeneration", script)
        self.assertIn("generation !== githubScanGeneration", script)
        self.assertIn("githubScanInProgress", script)
        self.assertIn("X-CSRF-Token", script)
        self.assertIn("startScanButton.disabled = true", script)
        self.assertNotIn("Fixture pair required", script)
        self.assertIn("Deterministic correlation", script)
        self.assertIn("textContent", script)
        self.assertNotIn("innerHTML", script)

    def test_dashboard_contract_has_forensic_console_regions_and_motion(self) -> None:
        dashboard = Path(STATIC_DASHBOARD).read_text(encoding="utf-8")

        for console_token in (
            "LOCAL / READ-ONLY",
            "class=\"risk-panel\"",
            "Evidence",
            "path-card",
            "comparison-board-summary",
            "risk-high-bar",
            "LOCAL STATIC ANALYSIS",
            "Deterministic correlation; not a generalized graph.",
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
        self.assertNotIn("Case context", dashboard)
        self.assertNotIn("Review posture", dashboard)
        self.assertNotIn("SELECTED FINDING", dashboard)
        self.assertNotIn("ANALYSIS GUARDRAILS", dashboard)

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
        self.assertIn("GitHub API", landing)
        self.assertIn("bounded supported Compose blobs", landing)

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
