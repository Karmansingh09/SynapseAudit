from __future__ import annotations

import base64
import ipaddress
import json
import threading
import unittest
from http.client import HTTPConnection
from http.cookies import SimpleCookie
from pathlib import Path

from synapseaudit.github import (
    GitHubConfig,
    GitHubService,
    SessionStore,
    is_trusted_proxy,
    parse_trusted_proxies,
    resolve_client_ip,
)
from synapseaudit.web import (
    AuthRateLimiter,
    DashboardServer,
    create_server,
)


class WebAuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.password = "secure-test-pass-12345"
        cls.auth_header = "Basic " + base64.b64encode(f"admin:{cls.password}".encode("utf-8")).decode("ascii")
        cls.server: DashboardServer = create_server(0, dashboard_password=cls.password)
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
        resp_body = response.read()
        resp_headers = {name.lower(): value for name, value in response.getheaders()}
        connection.close()
        return response.status, resp_headers, resp_body

    def test_protected_routes_without_credentials_return_401(self) -> None:
        protected_get_paths = (
            "/console",
            "/api/github/status",
            "/api/github/connect",
            "/api/github/repositories",
            "/api/github/repositories/owner/repo/branches",
            "/api/analyze?fixture=vulnerable",
        )
        for path in protected_get_paths:
            with self.subTest(path=path):
                status, headers, body = self.request_raw(path)
                self.assertEqual(status, 401)
                self.assertIn("basic realm", headers.get("www-authenticate", "").lower())
                payload = json.loads(body.decode("utf-8"))
                self.assertIn("authentication required", payload["error"].lower())

        status, headers, body = self.request_raw("/api/analyze-upload", method="POST")
        self.assertEqual(status, 401)
        self.assertIn("basic realm", headers.get("www-authenticate", "").lower())

        status, headers, body = self.request_raw("/api/github/scan", method="POST")
        self.assertEqual(status, 401)

        status, headers, body = self.request_raw("/api/github/disconnect", method="POST")
        self.assertEqual(status, 401)

    def test_public_routes_succeed_without_credentials(self) -> None:
        status, _, body = self.request_raw("/")
        self.assertEqual(status, 200)
        self.assertIn("<!doctype html>", body.decode("utf-8").lower())

        status, _, body = self.request_raw("/static/dashboard.js")
        self.assertEqual(status, 200)
        self.assertIn("use strict", body.decode("utf-8"))

    def test_valid_and_invalid_basic_auth_credentials(self) -> None:
        # Valid credentials
        status, _, body = self.request_raw(
            "/console",
            headers={"Authorization": self.auth_header},
        )
        self.assertEqual(status, 200)
        self.assertIn("<!doctype html>", body.decode("utf-8").lower())

        # Invalid password
        bad_auth = "Basic " + base64.b64encode(b"admin:wrong-password").decode("ascii")
        status, headers, body = self.request_raw(
            "/console",
            headers={"Authorization": bad_auth},
        )
        self.assertEqual(status, 401)
        self.assertIn("basic realm", headers.get("www-authenticate", "").lower())

        # Malformed Authorization header
        status, headers, body = self.request_raw(
            "/console",
            headers={"Authorization": "Bearer some-token"},
        )
        self.assertEqual(status, 401)

        status, headers, body = self.request_raw(
            "/console",
            headers={"Authorization": "Basic not-valid-base64-!!!"},
        )
        self.assertEqual(status, 401)

    def test_direct_loopback_cannot_bypass_authentication(self) -> None:
        # Directly connecting to 127.0.0.1:<port> without auth must be blocked
        status, _, _ = self.request_raw("/console")
        self.assertEqual(status, 401)

        status, _, _ = self.request_raw("/api/analyze?fixture=vulnerable")
        self.assertEqual(status, 401)

        # Forged reverse-proxy headers cannot bypass authentication
        spoofed_headers = {
            "Host": "localhost",
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "audit.example.test",
        }
        status, _, _ = self.request_raw("/console", headers=spoofed_headers)
        self.assertEqual(status, 401)

    def test_no_credentials_appear_in_error_messages_or_responses(self) -> None:
        bad_auth = "Basic " + base64.b64encode(b"admin:super-secret-user-input").decode("ascii")
        status, _, body = self.request_raw("/console", headers={"Authorization": bad_auth})
        self.assertEqual(status, 401)
        decoded_body = body.decode("utf-8")
        self.assertNotIn("super-secret-user-input", decoded_body)
        self.assertNotIn(self.password, decoded_body)
        self.assertNotIn(bad_auth, decoded_body)

    def test_unknown_routes_and_unsupported_methods_fail_closed(self) -> None:
        # Unauthenticated calls to unknown routes fail closed as 401
        status, _, _ = self.request_raw("/unmapped-secret-path")
        self.assertEqual(status, 401)

        # Authenticated calls to unknown routes return 404
        status, _, _ = self.request_raw(
            "/unmapped-secret-path",
            headers={"Authorization": self.auth_header},
        )
        self.assertEqual(status, 404)

        # Unsupported methods return 401 unauthenticated, 405 authenticated
        status, _, _ = self.request_raw("/console", method="PUT")
        self.assertEqual(status, 401)

        status, headers, _ = self.request_raw(
            "/console",
            method="PUT",
            headers={"Authorization": self.auth_header},
        )
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("allow"), "GET")


class LocalOnlyAndGitHubConfigEnforcementTests(unittest.TestCase):
    def test_local_only_mode_allows_unauthenticated_requests_when_password_is_unset(self) -> None:
        server = create_server(0, dashboard_password=None, environ={})
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            connection = HTTPConnection("127.0.0.1", port, timeout=5)
            connection.request("GET", "/console")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_create_server_requires_password_when_github_service_configured(self) -> None:
        config = GitHubConfig(
            app_id=123,
            app_slug="synapseaudit",
            private_key_path=Path("/tmp/fake-key.pem"),
            callback_url="https://audit.example.test/api/github/callback",
            dashboard_password="test-password",
        )
        fake_service = GitHubService(config)

        # Password explicitly provided -> succeeds
        server = create_server(0, github_service=fake_service, dashboard_password="test-password")
        server.server_close()

        # Password omitted -> fails safely
        with self.assertRaisesRegex(ValueError, "SYNAPSEAUDIT_DASHBOARD_PASSWORD"):
            create_server(0, github_service=fake_service, dashboard_password=None, environ={})


class RateLimiterAndCallbackIntegrationTests(unittest.TestCase):
    def test_authentication_rate_limiter_unit_behavior(self) -> None:
        now = [1000.0]
        limiter = AuthRateLimiter(
            max_failures=3,
            window_seconds=60.0,
            lockout_seconds=120.0,
            max_tracked_clients=2,
            clock=lambda: now[0],
        )

        ip = "127.0.0.1"
        self.assertEqual(limiter.record_failure(ip), (False, 0))
        self.assertEqual(limiter.record_failure(ip), (False, 0))
        # Third failure triggers lockout
        locked, retry = limiter.record_failure(ip)
        self.assertTrue(locked)
        self.assertEqual(retry, 120)

        # While locked, is_locked returns True
        is_l, rem = limiter.is_locked(ip)
        self.assertTrue(is_l)
        self.assertEqual(rem, 120)

        # After lockout expires
        now[0] += 121.0
        self.assertEqual(limiter.is_locked(ip), (False, 0))

        # Success clears history
        limiter.record_failure(ip)
        limiter.record_success(ip)
        self.assertEqual(limiter.is_locked(ip), (False, 0))

        # Bounded client eviction
        limiter.record_failure("10.0.0.1")
        limiter.record_failure("10.0.0.2")
        limiter.record_failure("10.0.0.3")  # Exceeds max_tracked_clients=2
        self.assertLessEqual(len(limiter._clients), 2)

    def test_live_rate_limiting_returns_429(self) -> None:
        now = [1000.0]
        test_limiter = AuthRateLimiter(
            max_failures=2,
            window_seconds=60.0,
            lockout_seconds=60.0,
            clock=lambda: now[0],
        )
        server = create_server(
            0,
            dashboard_password="correct-password",
            auth_rate_limiter=test_limiter,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]

        try:
            bad_auth = "Basic " + base64.b64encode(b"admin:wrong").decode("ascii")
            connection = HTTPConnection("127.0.0.1", port, timeout=5)

            # Failure 1
            connection.request("GET", "/console", headers={"Authorization": bad_auth})
            resp = connection.getresponse()
            self.assertEqual(resp.status, 401)
            resp.read()

            # Failure 2 -> locks out
            connection.request("GET", "/console", headers={"Authorization": bad_auth})
            resp = connection.getresponse()
            self.assertEqual(resp.status, 429)
            self.assertEqual(resp.getheader("Retry-After"), "60")
            body = resp.read()
            self.assertIn("too many failed", json.loads(body.decode("utf-8"))["error"].lower())

            # Subsequent requests are immediately blocked
            connection.request("GET", "/console", headers={"Authorization": bad_auth})
            resp = connection.getresponse()
            self.assertEqual(resp.status, 429)
            resp.read()

            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_callback_without_basic_auth_preserves_session_state_and_rotates(self) -> None:
        # GitHub callback does not need Basic Auth, but requires valid session and state
        now = [1000.0]
        store = SessionStore(clock=lambda: now[0])
        session, _ = store.get_or_create(None)
        state = store.issue_state(session)

        # We construct a mock client to simulate token issuance
        class FakeClient:
            def create_installation_token(self, installation_id: int):
                from collections import namedtuple
                Token = namedtuple("Token", ["token", "expires_at"])
                return Token("ghs_synthetic_token", now[0] + 3600)

        config = GitHubConfig(
            app_id=123,
            app_slug="synapseaudit",
            private_key_path=Path("/tmp/fake-key.pem"),
            callback_url="https://audit.example.test/api/github/callback",
            dashboard_password="test-password",
        )
        service = GitHubService(config, client=FakeClient())
        service.sessions = store

        server = create_server(
            0,
            github_service=service,
            dashboard_password="test-password",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]

        try:
            connection = HTTPConnection("127.0.0.1", port, timeout=5)

            # 1. Missing cookie -> 401
            connection.request("GET", f"/api/github/callback?installation_id=456&setup_action=install&state={state}")
            resp = connection.getresponse()
            self.assertEqual(resp.status, 401)
            resp.read()

            # 2. Valid cookie + valid state -> 303/302 Redirect with rotated session cookie
            cookie_header = f"synapseaudit_session={session.session_id}"
            connection.request(
                "GET",
                f"/api/github/callback?installation_id=456&setup_action=install&state={state}",
                headers={"Cookie": cookie_header},
            )
            resp = connection.getresponse()
            self.assertEqual(resp.status, 303)
            set_cookie = resp.getheader("Set-Cookie", "")
            self.assertIn("synapseaudit_session=", set_cookie)
            self.assertIn("HttpOnly", set_cookie)
            self.assertIn("SameSite=Lax", set_cookie)
            self.assertIn("Secure", set_cookie)
            # Must NOT be the old session ID
            self.assertNotIn(session.session_id, set_cookie)
            resp.read()

            cookies = SimpleCookie()
            cookies.load(set_cookie)
            rotated_cookie = cookies["synapseaudit_session"].value

            # 3. Old session cookie replay -> 401 (session invalidated upon rotation)
            connection.request(
                "GET",
                f"/api/github/callback?installation_id=456&setup_action=install&state={state}",
                headers={"Cookie": cookie_header},
            )
            resp = connection.getresponse()
            self.assertEqual(resp.status, 401)
            resp.read()

            # 4. Rotated session with already-used state -> 400 (replayed state)
            connection.request(
                "GET",
                f"/api/github/callback?installation_id=456&setup_action=install&state={state}",
                headers={"Cookie": f"synapseaudit_session={rotated_cookie}"},
            )
            resp = connection.getresponse()
            self.assertEqual(resp.status, 400)
            resp.read()

            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class TrustedProxyUnitTests(unittest.TestCase):
    def test_parse_trusted_proxies(self) -> None:
        self.assertEqual(parse_trusted_proxies(None), ())
        self.assertEqual(parse_trusted_proxies(""), ())
        self.assertEqual(parse_trusted_proxies("   "), ())
        self.assertEqual(parse_trusted_proxies([]), ())

        parsed = parse_trusted_proxies("127.0.0.1, ::1, 10.0.0.0/8")
        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[0], ipaddress.ip_network("127.0.0.1/32"))
        self.assertEqual(parsed[1], ipaddress.ip_network("::1/128"))
        self.assertEqual(parsed[2], ipaddress.ip_network("10.0.0.0/8"))

        net = ipaddress.ip_network("192.168.1.0/24")
        self.assertEqual(parse_trusted_proxies([net]), (net,))

        with self.assertRaises(ValueError):
            parse_trusted_proxies("127.0.0.1, not-an-ip")
        with self.assertRaises(ValueError):
            parse_trusted_proxies("127.0.0.1,,::1")
        with self.assertRaises(ValueError):
            parse_trusted_proxies(["127.0.0.1", ""])

    def test_resolve_client_ip_direct_connection_ignores_forwarded(self) -> None:
        untrusted_peer = "192.168.1.50"
        self.assertEqual(
            resolve_client_ip(untrusted_peer, "203.0.113.195", ()),
            "192.168.1.50",
        )
        self.assertEqual(
            resolve_client_ip("127.0.0.1", "203.0.113.195", ()),
            "127.0.0.1",
        )
        trusted = parse_trusted_proxies("10.0.0.1")
        self.assertEqual(
            resolve_client_ip("127.0.0.1", "203.0.113.195", trusted),
            "127.0.0.1",
        )

    def test_resolve_client_ip_trusted_proxy_right_to_left(self) -> None:
        trusted = parse_trusted_proxies("127.0.0.1, 10.0.0.2")

        self.assertEqual(
            resolve_client_ip("127.0.0.1", "203.0.113.195", trusted),
            "203.0.113.195",
        )

        # Attacker spoofed leftmost entry 1.1.1.1; reverse proxy appended 203.0.113.195
        self.assertEqual(
            resolve_client_ip("127.0.0.1", "1.1.1.1, 203.0.113.195", trusted),
            "203.0.113.195",
        )

        # Multi-hop proxy chain
        self.assertEqual(
            resolve_client_ip("127.0.0.1", "198.51.100.1, 10.0.0.2", trusted),
            "198.51.100.1",
        )

        # Multiple X-Forwarded-For header values
        self.assertEqual(
            resolve_client_ip("127.0.0.1", ["198.51.100.1", "10.0.0.2"], trusted),
            "198.51.100.1",
        )

    def test_resolve_client_ip_safe_fallbacks(self) -> None:
        trusted = parse_trusted_proxies("127.0.0.1")

        self.assertEqual(resolve_client_ip("127.0.0.1", None, trusted), "127.0.0.1")
        self.assertEqual(resolve_client_ip("127.0.0.1", "", trusted), "127.0.0.1")
        self.assertEqual(resolve_client_ip("127.0.0.1", "   ", trusted), "127.0.0.1")

        self.assertEqual(resolve_client_ip("127.0.0.1", "127.0.0.1", trusted), "127.0.0.1")

        self.assertEqual(resolve_client_ip("127.0.0.1", "not-an-ip", trusted), "127.0.0.1")
        self.assertEqual(resolve_client_ip("127.0.0.1", "203.0.113.1, ", trusted), "127.0.0.1")
        self.assertEqual(
            resolve_client_ip("127.0.0.1", "203.0.113.1; DROP TABLE", trusted),
            "127.0.0.1",
        )

        self.assertEqual(
            resolve_client_ip("127.0.0.1", "[2001:db8::1]", trusted),
            "2001:db8::1",
        )


class TrustedProxyLiveServerTests(unittest.TestCase):
    def test_rate_limiter_lockout_isolation_behind_trusted_proxy(self) -> None:
        now = [1000.0]
        limiter = AuthRateLimiter(
            max_failures=2,
            window_seconds=60.0,
            lockout_seconds=120.0,
            clock=lambda: now[0],
        )
        server = create_server(
            0,
            dashboard_password="secret-password-xyz",
            auth_rate_limiter=limiter,
            trusted_proxies=["127.0.0.1"],
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]

        try:
            bad_auth = "Basic " + base64.b64encode(b"admin:wrong").decode("ascii")
            good_auth = "Basic " + base64.b64encode(b"admin:secret-password-xyz").decode("ascii")

            conn = HTTPConnection("127.0.0.1", port, timeout=5)

            # Client A (203.0.113.10) fails twice
            conn.request(
                "GET",
                "/console",
                headers={"Authorization": bad_auth, "X-Forwarded-For": "203.0.113.10"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 401)
            resp.read()

            conn.request(
                "GET",
                "/console",
                headers={"Authorization": bad_auth, "X-Forwarded-For": "203.0.113.10"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 429)
            resp.read()

            # Client A is now locked out
            conn.request(
                "GET",
                "/console",
                headers={"Authorization": good_auth, "X-Forwarded-For": "203.0.113.10"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 429)
            resp.read()

            # Client B (203.0.113.20) connects from same socket peer (127.0.0.1) -> NOT locked out!
            conn.request(
                "GET",
                "/console",
                headers={"Authorization": good_auth, "X-Forwarded-For": "203.0.113.20"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            resp.read()

            conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_untrusted_proxy_ignores_forwarded_for_and_locks_socket_peer(self) -> None:
        now = [1000.0]
        limiter = AuthRateLimiter(
            max_failures=2,
            window_seconds=60.0,
            lockout_seconds=120.0,
            clock=lambda: now[0],
        )
        server = create_server(
            0,
            dashboard_password="secret-password-xyz",
            auth_rate_limiter=limiter,
            trusted_proxies=None,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]

        try:
            bad_auth = "Basic " + base64.b64encode(b"admin:wrong").decode("ascii")

            conn = HTTPConnection("127.0.0.1", port, timeout=5)

            conn.request(
                "GET",
                "/console",
                headers={"Authorization": bad_auth, "X-Forwarded-For": "203.0.113.99"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 401)
            resp.read()

            conn.request(
                "GET",
                "/console",
                headers={"Authorization": bad_auth, "X-Forwarded-For": "203.0.113.99"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 429)
            resp.read()

            self.assertTrue(limiter.is_locked("127.0.0.1")[0])
            self.assertFalse(limiter.is_locked("203.0.113.99")[0])

            conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_create_server_trusted_proxies_from_environ_and_validation(self) -> None:
        server = create_server(
            0,
            dashboard_password=None,
            environ={"SYNAPSEAUDIT_TRUSTED_PROXIES": "127.0.0.1, ::1"},
        )
        self.assertEqual(len(server.trusted_proxies), 2)
        server.server_close()

        with self.assertRaises(ValueError):
            create_server(
                0,
                dashboard_password=None,
                environ={"SYNAPSEAUDIT_TRUSTED_PROXIES": "invalid-ip-entry"},
            )


if __name__ == "__main__":
    unittest.main()
