from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http import HTTPStatus
from http.client import HTTPConnection
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from synapseaudit.github import (
    GitHubApiError,
    GitHubClient,
    GitHubConfig,
    GitHubService,
    GitHubServiceError,
    RepositoryScanResult,
    ScanLimits,
    SessionStore,
)
from synapseaudit.web import (
    DashboardServer,
    create_server,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VULNERABLE_COMPOSE = (PROJECT_ROOT / "fixtures" / "compose.vulnerable.yml").read_bytes()
REMEDIATED_COMPOSE = (PROJECT_ROOT / "fixtures" / "compose.remediated.yml").read_bytes()


def generate_rsa_key_file(directory: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = directory / "app.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    return key_path


def git_blob_sha(content: bytes) -> str:
    return hashlib.sha1(f"blob {len(content)}\0".encode("ascii") + content).hexdigest()


class JsonResponse:
    def __init__(self, payload: object, url: str = "https://api.github.com", headers: dict[str, str] | None = None) -> None:
        self._body = json.dumps(payload).encode("utf-8")
        self._url = url
        self.headers = {"Content-Type": "application/json", **(headers or {})}

    def read(self, limit: int = -1) -> bytes:
        if limit < 0 or limit >= len(self._body):
            return self._body
        return self._body[:limit]

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> JsonResponse:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        pass


class MockGitHubBackend:
    """Deterministic simulated GitHub REST API backend."""

    def __init__(self) -> None:
        self.installation_token = "ghs_SYNTHETIC_INSTALLATION_SECRET_TOKEN_99999"
        self.commit_sha = "a" * 40
        self.tree_sha = "b" * 40
        self.repositories = [
            {
                "id": 101,
                "name": "allowed",
                "full_name": "octo/allowed",
                "private": True,
                "default_branch": "main",
            }
        ]
        self.branches = [
            {"name": "main", "protected": True},
            {"name": "feature/audit-test", "protected": False},
            {"name": "release/v1.0", "protected": True},
        ]
        self.tree_entries: list[dict[str, object]] = []
        self.tree_truncated = False
        self.blobs: dict[str, bytes] = {}
        self.custom_error: HTTPError | None = None
        self.requests_received: list[Request] = []

    def opener(self, request: Request, *, timeout: float) -> JsonResponse:
        self.requests_received.append(request)
        if self.custom_error is not None:
            err = self.custom_error
            self.custom_error = None
            raise err

        parsed = urlsplit(request.full_url)
        path = parsed.path

        if path.startswith("/app/installations/") and path.endswith("/access_tokens"):
            return JsonResponse({"token": self.installation_token, "expires_at": "2030-01-01T00:00:00Z"})

        if path == "/installation/repositories":
            return JsonResponse({"total_count": len(self.repositories), "repositories": self.repositories})

        if path == "/repos/octo/allowed/branches":
            return JsonResponse(self.branches)

        if path.startswith("/repos/octo/allowed/branches/"):
            branch_name = path[len("/repos/octo/allowed/branches/") :]
            matching = [b for b in self.branches if b["name"] == branch_name]
            if matching or branch_name in {"main", "feature%2Faudit-test", "feature/audit-test", "release%2Fv1.0", "release/v1.0"}:
                return JsonResponse({"name": branch_name, "commit": {"sha": self.commit_sha}})
            raise HTTPError(request.full_url, 404, "Branch not found", {}, None)

        if path == f"/repos/octo/allowed/git/commits/{self.commit_sha}":
            return JsonResponse({"sha": self.commit_sha, "tree": {"sha": self.tree_sha}})

        if path == f"/repos/octo/allowed/git/trees/{self.tree_sha}":
            return JsonResponse({
                "sha": self.tree_sha,
                "truncated": self.tree_truncated,
                "tree": self.tree_entries,
            })

        if path.startswith("/repos/octo/allowed/git/blobs/"):
            blob_sha = path.rsplit("/", 1)[-1]
            if blob_sha in self.blobs:
                content = self.blobs[blob_sha]
                return JsonResponse({
                    "sha": blob_sha,
                    "encoding": "base64",
                    "size": len(content),
                    "content": base64.b64encode(content).decode("ascii"),
                })
            raise HTTPError(request.full_url, 404, "Blob not found", {}, None)

        raise HTTPError(request.full_url, 404, "Not Found", {}, None)


class RealWorldGitHubBaseTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.key_path = generate_rsa_key_file(Path(self.temp_dir.name))
        self.dashboard_password = "test-dashboard-secret-pass-42"
        self.auth_header = "Basic " + base64.b64encode(f"admin:{self.dashboard_password}".encode("utf-8")).decode("ascii")

        self.github_backend = MockGitHubBackend()
        self.config = GitHubConfig(
            app_id=12345,
            app_slug="synapseaudit-app",
            private_key_path=self.key_path,
            callback_url="https://audit.example.test/api/github/callback",
            dashboard_password=self.dashboard_password,
        )
        self.client = GitHubClient(self.config, opener=self.github_backend.opener)
        self.service = GitHubService(self.config, client=self.client)
        self.server: DashboardServer = create_server(
            0,
            github_service=self.service,
            dashboard_password=self.dashboard_password,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp_dir.cleanup()

    def request(
        self,
        method: str,
        path: str,
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


class Scenario1_InstallationAndCallbackTests(RealWorldGitHubBaseTestCase):
    """Scenario 1: Successful installation and callback handling."""

    def test_successful_installation_and_callback_flow(self) -> None:
        # 1. Start authorization at /api/github/connect
        status, headers, body = self.request(
            "GET",
            "/api/github/connect",
            headers={"Authorization": self.auth_header},
        )
        self.assertEqual(status, 200)
        connect_data = json.loads(body.decode("utf-8"))
        self.assertEqual(connect_data["status"], "authorization_pending")
        auth_url = connect_data["authorization_url"]
        self.assertIn("https://github.com/apps/synapseaudit-app/installations/new", auth_url)

        # Extract session cookie and state
        set_cookie = headers.get("set-cookie", "")
        self.assertIn("synapseaudit_session=", set_cookie)
        cookie = SimpleCookie()
        cookie.load(set_cookie)
        session_id = cookie["synapseaudit_session"].value

        parsed_url = urlsplit(auth_url)
        state = parse_qs(parsed_url.query)["state"][0]

        # 2. Simulate GitHub redirecting back to callback endpoint
        callback_path = f"/api/github/callback?installation_id=98765&setup_action=install&state={state}"
        cb_status, cb_headers, cb_body = self.request(
            "GET",
            callback_path,
            headers={"Cookie": f"synapseaudit_session={session_id}"},
        )
        self.assertEqual(cb_status, 303)
        self.assertEqual(cb_headers["location"], "/console?github=connected")

        # Session cookie was rotated
        new_set_cookie = cb_headers.get("set-cookie", "")
        self.assertIn("synapseaudit_session=", new_set_cookie)
        new_cookie = SimpleCookie()
        new_cookie.load(new_set_cookie)
        rotated_session_id = new_cookie["synapseaudit_session"].value
        self.assertNotEqual(session_id, rotated_session_id)

        # Status check shows connected
        st_status, _, st_body = self.request(
            "GET",
            "/api/github/status",
            headers={
                "Authorization": self.auth_header,
                "Cookie": f"synapseaudit_session={rotated_session_id}",
            },
        )
        self.assertEqual(st_status, 200)
        status_data = json.loads(st_body.decode("utf-8"))
        self.assertTrue(status_data["configured"])
        self.assertTrue(status_data["connected"])

    def test_successful_update_callback_flow(self) -> None:
        session, _ = self.service.ensure_session(None)
        state = self.service.sessions.issue_state(session)
        callback_path = f"/api/github/callback?installation_id=98765&setup_action=update&state={state}"
        cb_status, cb_headers, _ = self.request(
            "GET",
            callback_path,
            headers={"Cookie": f"synapseaudit_session={session.session_id}"},
        )
        self.assertEqual(cb_status, 303)
        self.assertEqual(cb_headers["location"], "/console?github=connected")

    def test_callback_user_denied_or_canceled(self) -> None:
        session, _ = self.service.ensure_session(None)
        state = self.service.sessions.issue_state(session)
        # GitHub sends error=access_denied&error_description=...
        callback_path = f"/api/github/callback?error=access_denied&error_description=SensitiveInternalError123&state={state}"
        status, _, body = self.request(
            "GET",
            callback_path,
            headers={"Cookie": f"synapseaudit_session={session.session_id}"},
        )
        self.assertEqual(status, 400)
        payload = json.loads(body.decode("utf-8"))
        self.assertIn("denied or canceled", payload["error"])
        # Sensitive error_description must not be reflected
        self.assertNotIn("SensitiveInternalError123", body.decode("utf-8"))

    def test_callback_organization_request_submitted(self) -> None:
        session, _ = self.service.ensure_session(None)
        state = self.service.sessions.issue_state(session)
        callback_path = f"/api/github/callback?setup_action=request&state={state}"
        status, _, body = self.request(
            "GET",
            callback_path,
            headers={"Cookie": f"synapseaudit_session={session.session_id}"},
        )
        self.assertEqual(status, 400)
        payload = json.loads(body.decode("utf-8"))
        self.assertIn("administrator approval", payload["error"])

    def test_callback_error_and_request_require_valid_state_and_cannot_replay(self) -> None:
        session, _ = self.service.ensure_session(None)
        state = self.service.sessions.issue_state(session)

        # 1. Missing state with error=access_denied fails closed
        status, _, body = self.request(
            "GET",
            "/api/github/callback?error=access_denied",
            headers={"Cookie": f"synapseaudit_session={session.session_id}"},
        )
        self.assertEqual(status, 400)
        self.assertIn("incomplete", json.loads(body.decode("utf-8"))["error"])

        # 2. Invalid state with error=access_denied fails state validation
        status, _, body = self.request(
            "GET",
            "/api/github/callback?error=access_denied&state=invalid_token",
            headers={"Cookie": f"synapseaudit_session={session.session_id}"},
        )
        self.assertEqual(status, 400)
        self.assertIn("invalid or expired", json.loads(body.decode("utf-8"))["error"])

        # 3. Missing state with setup_action=request fails closed
        status, _, body = self.request(
            "GET",
            "/api/github/callback?setup_action=request",
            headers={"Cookie": f"synapseaudit_session={session.session_id}"},
        )
        self.assertEqual(status, 400)
        self.assertIn("incomplete", json.loads(body.decode("utf-8"))["error"])

        # 4. Valid state consumes cleanly on error=access_denied
        status, _, body = self.request(
            "GET",
            f"/api/github/callback?error=access_denied&state={state}",
            headers={"Cookie": f"synapseaudit_session={session.session_id}"},
        )
        self.assertEqual(status, 400)
        self.assertIn("denied or canceled", json.loads(body.decode("utf-8"))["error"])

        # 5. Replaying the consumed state fails state validation
        status, _, body = self.request(
            "GET",
            f"/api/github/callback?error=access_denied&state={state}",
            headers={"Cookie": f"synapseaudit_session={session.session_id}"},
        )
        self.assertEqual(status, 400)
        self.assertIn("invalid or expired", json.loads(body.decode("utf-8"))["error"])

        # 6. Cross-session state reuse fails state validation
        other_session, _ = self.service.ensure_session(None)
        other_state = self.service.sessions.issue_state(other_session)
        status, _, body = self.request(
            "GET",
            f"/api/github/callback?setup_action=request&state={other_state}",
            headers={"Cookie": f"synapseaudit_session={session.session_id}"},
        )
        self.assertEqual(status, 400)
        self.assertIn("invalid or expired", json.loads(body.decode("utf-8"))["error"])

        # Confirm session is still unconnected
        st_status, _, st_body = self.request(
            "GET",
            "/api/github/status",
            headers={"Cookie": f"synapseaudit_session={session.session_id}", "Authorization": self.auth_header},
        )
        self.assertEqual(st_status, 200)
        self.assertFalse(json.loads(st_body.decode("utf-8"))["connected"])

    def test_callback_duplicate_parameters_fail_closed(self) -> None:
        session, _ = self.service.ensure_session(None)
        state = self.service.sessions.issue_state(session)

        # Duplicate state
        dup_state_path = f"/api/github/callback?installation_id=123&setup_action=install&state={state}&state=second_state"
        status, _, body = self.request(
            "GET",
            dup_state_path,
            headers={"Cookie": f"synapseaudit_session={session.session_id}"},
        )
        self.assertEqual(status, 400)
        self.assertIn("incomplete", json.loads(body.decode("utf-8"))["error"])

        # Duplicate error
        dup_error_path = f"/api/github/callback?error=access_denied&error=other_err&state={state}"
        status, _, body = self.request(
            "GET",
            dup_error_path,
            headers={"Cookie": f"synapseaudit_session={session.session_id}"},
        )
        self.assertEqual(status, 400)
        self.assertIn("incomplete", json.loads(body.decode("utf-8"))["error"])


class Scenario2_OAuthStateAndSessionSecurityTests(RealWorldGitHubBaseTestCase):
    """Scenario 2: Correct handling of OAuth/installation state, sessions, and CSRF."""

    def test_state_replay_and_tampering_are_rejected(self) -> None:
        session, _ = self.service.ensure_session(None)
        state = self.service.sessions.issue_state(session)

        # First consumption succeeds
        cb_path = f"/api/github/callback?installation_id=98765&setup_action=install&state={state}"
        status, headers, _ = self.request("GET", cb_path, headers={"Cookie": f"synapseaudit_session={session.session_id}"})
        self.assertEqual(status, 303)

        new_cookie = SimpleCookie()
        new_cookie.load(headers["set-cookie"])
        rotated_session = new_cookie["synapseaudit_session"].value

        # Replayed state on old session -> 401 (old session invalid)
        status, _, _ = self.request("GET", cb_path, headers={"Cookie": f"synapseaudit_session={session.session_id}"})
        self.assertEqual(status, 401)

        # Replayed state on rotated session -> 400 (state already used)
        status, _, _ = self.request("GET", cb_path, headers={"Cookie": f"synapseaudit_session={rotated_session}"})
        self.assertEqual(status, 400)

        # Tampered state -> 400
        tampered_path = f"/api/github/callback?installation_id=98765&setup_action=install&state={state}tampered"
        status, _, _ = self.request("GET", tampered_path, headers={"Cookie": f"synapseaudit_session={rotated_session}"})
        self.assertEqual(status, 400)

    def test_csrf_protection_on_scan_and_disconnect(self) -> None:
        session, _ = self.service.ensure_session(None)
        self.service.sessions.set_connection(session, 101, "tok", 4102444800.0)

        cookie_hdr = {"Cookie": f"synapseaudit_session={session.session_id}", "Authorization": self.auth_header}

        # Disconnect without CSRF -> 403
        status, _, _ = self.request("POST", "/api/github/disconnect", headers=cookie_hdr)
        self.assertEqual(status, 403)

        # Disconnect with wrong CSRF -> 403
        bad_csrf = {**cookie_hdr, "X-CSRF-Token": "bad-token"}
        status, _, _ = self.request("POST", "/api/github/disconnect", headers=bad_csrf)
        self.assertEqual(status, 403)

        # Disconnect with valid CSRF -> 200
        good_csrf = {**cookie_hdr, "X-CSRF-Token": session.csrf_token}
        status, _, body = self.request("POST", "/api/github/disconnect", headers=good_csrf)
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body.decode("utf-8"))["connected"])


class Scenario3_AuthorizedRepositoryScopingTests(RealWorldGitHubBaseTestCase):
    """Scenario 3: Authorized repository listing and selection."""

    def test_unauthorized_repository_access_is_rejected_by_server(self) -> None:
        session, _ = self.service.ensure_session(None)
        self.service.sessions.set_connection(session, 101, "tok", 4102444800.0)
        cookie_hdr = {"Cookie": f"synapseaudit_session={session.session_id}", "Authorization": self.auth_header}

        # 1. Authorized repository listing returns only allowed repos
        status, _, body = self.request("GET", "/api/github/repositories", headers=cookie_hdr)
        self.assertEqual(status, 200)
        repos = json.loads(body.decode("utf-8"))["repositories"]
        self.assertEqual([r["full_name"] for r in repos], ["octo/allowed"])

        # 2. Branch listing for unauthorized repo is blocked by server (404)
        status, _, body = self.request("GET", "/api/github/repositories/octo/forbidden/branches", headers=cookie_hdr)
        self.assertEqual(status, 404)
        self.assertIn("not accessible", json.loads(body.decode("utf-8"))["error"].lower())

        # 3. Scanning unauthorized repo is blocked by server (404)
        scan_body = json.dumps({"owner": "octo", "repository": "forbidden", "branch": "main"}).encode("utf-8")
        status, _, body = self.request(
            "POST",
            "/api/github/scan",
            body=scan_body,
            headers={
                **cookie_hdr,
                "Content-Type": "application/json",
                "Content-Length": str(len(scan_body)),
                "X-CSRF-Token": session.csrf_token,
            },
        )
        self.assertEqual(status, 404)
        self.assertIn("not accessible", json.loads(body.decode("utf-8"))["error"].lower())


class Scenario4_BranchAndCommitResolutionTests(RealWorldGitHubBaseTestCase):
    """Scenario 4: Default branch and immutable commit SHA resolution."""

    def test_slashed_branch_names_and_immutable_commit_resolution(self) -> None:
        session, _ = self.service.ensure_session(None)
        self.service.sessions.set_connection(session, 101, "tok", 4102444800.0)
        cookie_hdr = {
            "Cookie": f"synapseaudit_session={session.session_id}",
            "Authorization": self.auth_header,
            "X-CSRF-Token": session.csrf_token,
            "Content-Type": "application/json",
        }

        # Tree with remediated compose
        blob_sha = git_blob_sha(REMEDIATED_COMPOSE)
        self.github_backend.blobs[blob_sha] = REMEDIATED_COMPOSE
        self.github_backend.tree_entries = [{"path": "compose.yml", "type": "blob", "sha": blob_sha}]

        # Scan branch with slash: 'feature/audit-test'
        scan_payload = json.dumps({"owner": "octo", "repository": "allowed", "branch": "feature/audit-test"}).encode("utf-8")
        status, _, body = self.request(
            "POST",
            "/api/github/scan",
            body=scan_payload,
            headers={**cookie_hdr, "Content-Length": str(len(scan_payload))},
        )
        self.assertEqual(status, 200)
        result = json.loads(body.decode("utf-8"))
        self.assertEqual(result["commit_sha"], self.github_backend.commit_sha)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["branch"], "feature/audit-test")


class Scenario5_RepositoryContentVarietyTests(RealWorldGitHubBaseTestCase):
    """Scenario 5: Vulnerable, remediated, unsupported, malformed, oversized, and symlink cases."""

    def test_multi_file_variety_handling(self) -> None:
        session, _ = self.service.ensure_session(None)
        self.service.sessions.set_connection(session, 101, "tok", 4102444800.0)
        cookie_hdr = {
            "Cookie": f"synapseaudit_session={session.session_id}",
            "Authorization": self.auth_header,
            "X-CSRF-Token": session.csrf_token,
            "Content-Type": "application/json",
        }

        vuln_sha = git_blob_sha(VULNERABLE_COMPOSE)
        remed_sha = git_blob_sha(REMEDIATED_COMPOSE)
        malformed_bytes = b"services:\n  invalid: [\n"
        malformed_sha = git_blob_sha(malformed_bytes)

        self.github_backend.blobs[vuln_sha] = VULNERABLE_COMPOSE
        self.github_backend.blobs[remed_sha] = REMEDIATED_COMPOSE
        self.github_backend.blobs[malformed_sha] = malformed_bytes

        self.github_backend.tree_entries = [
            {"path": "nested/compose.yml", "type": "blob", "sha": vuln_sha},
            {"path": "remediated/docker-compose.yaml", "type": "blob", "sha": remed_sha},
            {"path": "README.md", "type": "blob", "sha": "1" * 40},
            {"path": "src/main.py", "type": "blob", "sha": "2" * 40},
            {"path": "broken/compose.yaml", "type": "blob", "sha": malformed_sha},
            {"path": "symlink/compose.yml", "type": "blob", "mode": "120000", "sha": "3" * 40},
            {"path": "huge/compose.yml", "type": "blob", "size": 999_999_999, "sha": "4" * 40},
        ]

        scan_payload = json.dumps({"owner": "octo", "repository": "allowed", "branch": "main"}).encode("utf-8")
        status, _, body = self.request(
            "POST",
            "/api/github/scan",
            body=scan_payload,
            headers={**cookie_hdr, "Content-Length": str(len(scan_payload))},
        )
        self.assertEqual(status, 200)
        result = json.loads(body.decode("utf-8"))
        self.assertEqual(result["status"], "limited")
        self.assertIn("maximum individual file size exceeded", result["limited_reasons"])

        # Scanned files
        scanned_paths = [f["path"] for f in result["files"]]
        self.assertEqual(scanned_paths, ["nested/compose.yml", "remediated/docker-compose.yaml"])

        # Vulnerable file findings
        vuln_file = next(f for f in result["files"] if f["path"] == "nested/compose.yml")
        self.assertEqual(len(vuln_file["report"]["findings"]), 4)
        self.assertEqual(len(vuln_file["report"]["attack_paths"]), 1)

        # Remediated file findings
        remed_file = next(f for f in result["files"] if f["path"] == "remediated/docker-compose.yaml")
        self.assertEqual(len(remed_file["report"]["findings"]), 0)

        # Skipped counts
        skipped = result["skipped_counts"]
        self.assertIn("filename is outside the supported Compose scope", skipped)
        self.assertIn("file is not valid supported Compose YAML", skipped)
        self.assertIn("symlink entries are not fetched", skipped)
        self.assertIn("maximum individual file size exceeded", skipped)


class Scenario6_GitHubApiErrorsAndRateLimitsTests(RealWorldGitHubBaseTestCase):
    """Scenario 6: GitHub API errors, rate limits, stale scan responses, and incomplete results."""

    def test_primary_rate_limit_preserves_session_connection(self) -> None:
        session, _ = self.service.ensure_session(None)
        self.service.sessions.set_connection(session, 101, "tok", 4102444800.0)
        cookie_hdr = {"Cookie": f"synapseaudit_session={session.session_id}", "Authorization": self.auth_header}

        # GitHub returns 403 with rate limit headers
        self.github_backend.custom_error = HTTPError(
            "https://api.github.com/installation/repositories",
            403,
            "rate limited",
            {"x-ratelimit-remaining": "0", "retry-after": "45"},
            None,
        )
        status, headers, body = self.request("GET", "/api/github/repositories", headers=cookie_hdr)
        self.assertEqual(status, 429)
        self.assertEqual(headers.get("retry-after"), "45")

        # Session connection is preserved
        self.assertIsNotNone(session.installation_id)

    def test_token_revocation_clears_session_connection(self) -> None:
        session, _ = self.service.ensure_session(None)
        self.service.sessions.set_connection(session, 101, "tok", 4102444800.0)
        cookie_hdr = {"Cookie": f"synapseaudit_session={session.session_id}", "Authorization": self.auth_header}

        # GitHub returns 401 Unauthorized (token revoked)
        self.github_backend.custom_error = HTTPError(
            "https://api.github.com/installation/repositories",
            401,
            "Bad credentials",
            {},
            None,
        )
        status, _, _ = self.request("GET", "/api/github/repositories", headers=cookie_hdr)
        self.assertEqual(status, 401)

        # Session connection is cleared
        self.assertIsNone(session.installation_id)

    def test_upstream_502_bad_gateway_preserves_connection(self) -> None:
        session, _ = self.service.ensure_session(None)
        self.service.sessions.set_connection(session, 101, "tok", 4102444800.0)
        cookie_hdr = {"Cookie": f"synapseaudit_session={session.session_id}", "Authorization": self.auth_header}

        self.github_backend.custom_error = HTTPError(
            "https://api.github.com/installation/repositories",
            502,
            "Bad Gateway",
            {},
            None,
        )
        status, _, _ = self.request("GET", "/api/github/repositories", headers=cookie_hdr)
        self.assertEqual(status, 502)
        self.assertIsNotNone(session.installation_id)

    def test_truncated_tree_reports_limited_status(self) -> None:
        session, _ = self.service.ensure_session(None)
        self.service.sessions.set_connection(session, 101, "tok", 4102444800.0)
        cookie_hdr = {
            "Cookie": f"synapseaudit_session={session.session_id}",
            "Authorization": self.auth_header,
            "X-CSRF-Token": session.csrf_token,
            "Content-Type": "application/json",
        }

        self.github_backend.tree_truncated = True
        blob_sha = git_blob_sha(REMEDIATED_COMPOSE)
        self.github_backend.blobs[blob_sha] = REMEDIATED_COMPOSE
        self.github_backend.tree_entries = [{"path": "compose.yml", "type": "blob", "sha": blob_sha}]

        scan_payload = json.dumps({"owner": "octo", "repository": "allowed", "branch": "main"}).encode("utf-8")
        status, _, body = self.request(
            "POST",
            "/api/github/scan",
            body=scan_payload,
            headers={**cookie_hdr, "Content-Length": str(len(scan_payload))},
        )
        self.assertEqual(status, 200)
        result = json.loads(body.decode("utf-8"))
        self.assertEqual(result["status"], "limited")
        self.assertIn("GitHub tree was truncated", result["limited_reasons"])


class Scenario7_RepositoryContentNonExecutionGuaranteeTests(RealWorldGitHubBaseTestCase):
    """Scenario 7: Confirmation that repository content is never executed."""

    def test_malicious_compose_content_is_never_executed(self) -> None:
        canary_file = Path(tempfile.gettempdir()) / f"synapseaudit_exploit_canary_{int(time.time())}.txt"
        if canary_file.exists():
            canary_file.unlink()

        # Malicious Compose content attempting host command execution
        malicious_compose = f"""
services:
  exploit:
    image: alpine:latest
    entrypoint: ["sh", "-c", "touch {canary_file}"]
    command: ["cat", "/etc/shadow"]
    volumes:
      - /:/host:ro
""".strip().encode("utf-8")

        session, _ = self.service.ensure_session(None)
        self.service.sessions.set_connection(session, 101, "tok", 4102444800.0)
        cookie_hdr = {
            "Cookie": f"synapseaudit_session={session.session_id}",
            "Authorization": self.auth_header,
            "X-CSRF-Token": session.csrf_token,
            "Content-Type": "application/json",
        }

        blob_sha = git_blob_sha(malicious_compose)
        self.github_backend.blobs[blob_sha] = malicious_compose
        self.github_backend.tree_entries = [{"path": "compose.yml", "type": "blob", "sha": blob_sha}]

        scan_payload = json.dumps({"owner": "octo", "repository": "allowed", "branch": "main"}).encode("utf-8")
        status, _, body = self.request(
            "POST",
            "/api/github/scan",
            body=scan_payload,
            headers={**cookie_hdr, "Content-Length": str(len(scan_payload))},
        )
        self.assertEqual(status, 200)
        result = json.loads(body.decode("utf-8"))
        self.assertEqual(result["status"], "complete")

        # Assert canary file was NEVER created on host
        self.assertFalse(canary_file.exists(), "CRITICAL: Malicious Compose command was executed on host!")


class Scenario8_ZeroSecretLeakageTests(RealWorldGitHubBaseTestCase):
    """Scenario 8: Confirmation that credentials, keys, and tokens never leak."""

    def test_zero_secrets_leakage_across_all_endpoints_and_logs(self) -> None:
        captured_logs = io.StringIO()
        old_log = self.server.RequestHandlerClass.log_message

        # Intercept server logs
        def intercept_log(handler_instance: object, format_str: str, *args: object) -> None:
            formatted = format_str % args
            captured_logs.write(formatted + "\n")
            old_log(handler_instance, format_str, *args)

        self.server.RequestHandlerClass.log_message = intercept_log  # type: ignore[assignment]

        try:
            session, _ = self.service.ensure_session(None)
            self.service.sessions.set_connection(session, 101, self.github_backend.installation_token, 4102444800.0)
            cookie_hdr = {
                "Cookie": f"synapseaudit_session={session.session_id}",
                "Authorization": self.auth_header,
                "X-CSRF-Token": session.csrf_token,
                "Content-Type": "application/json",
            }

            blob_sha = git_blob_sha(REMEDIATED_COMPOSE)
            self.github_backend.blobs[blob_sha] = REMEDIATED_COMPOSE
            self.github_backend.tree_entries = [{"path": "compose.yml", "type": "blob", "sha": blob_sha}]

            collected_responses: list[str] = []

            # 1. /api/github/status
            _, _, body = self.request("GET", "/api/github/status", headers=cookie_hdr)
            collected_responses.append(body.decode("utf-8"))

            # 2. /api/github/connect
            _, _, body = self.request("GET", "/api/github/connect", headers=cookie_hdr)
            collected_responses.append(body.decode("utf-8"))

            # 3. /api/github/repositories
            _, _, body = self.request("GET", "/api/github/repositories", headers=cookie_hdr)
            collected_responses.append(body.decode("utf-8"))

            # 4. /api/github/scan
            scan_payload = json.dumps({"owner": "octo", "repository": "allowed", "branch": "main"}).encode("utf-8")
            _, _, body = self.request(
                "POST",
                "/api/github/scan",
                body=scan_payload,
                headers={**cookie_hdr, "Content-Length": str(len(scan_payload))},
            )
            collected_responses.append(body.decode("utf-8"))

            # 5. /api/github/disconnect
            _, _, body = self.request("POST", "/api/github/disconnect", headers=cookie_hdr)
            collected_responses.append(body.decode("utf-8"))

            # Combine all response bodies and logs
            all_text = "\n".join(collected_responses) + "\n" + captured_logs.getvalue()

            # Ensure installation token never leaked
            self.assertNotIn(self.github_backend.installation_token, all_text)

            # Ensure private key never leaked
            self.assertNotIn("BEGIN RSA PRIVATE KEY", all_text)
            self.assertNotIn("BEGIN PRIVATE KEY", all_text)

            # Ensure dashboard password never leaked
            self.assertNotIn(self.dashboard_password, all_text)

        finally:
            self.server.RequestHandlerClass.log_message = old_log  # type: ignore[assignment]


if __name__ == "__main__":
    unittest.main()
