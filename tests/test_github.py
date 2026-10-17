from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from synapseaudit.github import (
    GitHubApiError,
    GitHubClient,
    GitHubConfig,
    GitHubService,
    GitHubServiceError,
    SessionStore,
    _NoRedirectHandler,
    _validate_api_url,
)


class FakeGitHubClient:
    def __init__(self) -> None:
        self.repositories = [
            {
                "id": 1,
                "name": "allowed",
                "full_name": "octo/allowed",
                "private": True,
                "default_branch": "main",
            }
        ]
        self.branches = [{"name": "main", "protected": True}]
        self.token_calls = 0
        self.branch_calls: list[tuple[str, str]] = []
        self.token_error: GitHubApiError | None = None
        self.repository_error: GitHubApiError | None = None

    def create_installation_token(self, installation_id: int):
        self.token_calls += 1
        if self.token_error is not None:
            raise self.token_error
        return type("Token", (), {"token": "installation-token", "expires_at": 4102444800.0})()

    def list_installation_repositories(self, token: str):
        self.assert_token(token)
        if self.repository_error is not None:
            raise self.repository_error
        return self.repositories

    def list_branches(self, token: str, owner: str, repository: str):
        self.assert_token(token)
        self.branch_calls.append((owner, repository))
        return self.branches

    @staticmethod
    def assert_token(token: str) -> None:
        if token != "installation-token":
            raise AssertionError("test attempted to use a token other than the server-side token")


def make_config(private_key_path: Path) -> GitHubConfig:
    return GitHubConfig(
        app_id=123,
        app_slug="synapseaudit",
        private_key_path=private_key_path,
        callback_url="https://audit.example.test/api/github/callback",
    )


class GitHubServiceTests(unittest.TestCase):
    def test_empty_environment_keeps_github_optional(self) -> None:
        service = GitHubService.from_environment({})

        status = service.status(None)

        self.assertFalse(status["configured"])
        self.assertFalse(status["connected"])
        with self.assertRaises(GitHubServiceError) as context:
            service.begin_connect("missing-session")
        self.assertEqual(context.exception.status.value, 503)

    def test_configuration_rejects_non_https_callback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "app.pem"
            key_path.write_text("not a private key", encoding="utf-8")
            environment = {
                "SYNAPSEAUDIT_GITHUB_APP_ID": "123",
                "SYNAPSEAUDIT_GITHUB_APP_SLUG": "synapseaudit",
                "SYNAPSEAUDIT_GITHUB_PRIVATE_KEY_FILE": str(key_path),
                "SYNAPSEAUDIT_GITHUB_CALLBACK_URL": "http://audit.example.test/callback",
            }
            with self.assertRaises(ValueError):
                GitHubConfig.from_environment(environment)

    def test_state_is_one_time_and_expiring(self) -> None:
        now = [1000.0]
        store = SessionStore(clock=lambda: now[0])
        session, _ = store.get_or_create(None)

        state = store.issue_state(session, ttl_seconds=10)
        store.consume_state(session, state)
        with self.assertRaises(GitHubServiceError):
            store.consume_state(session, state)

        expiring_state = store.issue_state(session, ttl_seconds=10)
        now[0] += 11
        with self.assertRaises(GitHubServiceError):
            store.consume_state(session, expiring_state)

    def test_expired_session_cannot_start_authorization(self) -> None:
        now = [1000.0]
        store = SessionStore(clock=lambda: now[0], session_ttl_seconds=10)
        service = GitHubService(
            make_config(Path("/nonexistent/private-key.pem")),
            client=FakeGitHubClient(),
            sessions=store,
            clock=lambda: now[0],
        )
        session, _ = store.get_or_create(None)
        now[0] += 11

        with self.assertRaises(GitHubServiceError) as context:
            service.begin_connect(session.session_id)
        self.assertEqual(context.exception.status.value, 401)

    def test_invalid_callback_state_does_not_call_github(self) -> None:
        client = FakeGitHubClient()
        store = SessionStore()
        service = GitHubService(
            make_config(Path("/nonexistent/private-key.pem")),
            client=client,
            sessions=store,
        )
        session, _ = store.get_or_create(None)

        with self.assertRaises(GitHubServiceError) as context:
            service.complete_callback(session.session_id, "not-issued", "42", "install")
        self.assertEqual(context.exception.status.value, 400)
        self.assertEqual(client.token_calls, 0)

    def test_reused_callback_state_is_rejected(self) -> None:
        client = FakeGitHubClient()
        store = SessionStore()
        service = GitHubService(
            make_config(Path("/nonexistent/private-key.pem")),
            client=client,
            sessions=store,
        )
        session, _ = store.get_or_create(None)
        state = store.issue_state(session)

        rotated = service.complete_callback(session.session_id, state, "42", "install")
        self.assertNotEqual(rotated.session_id, session.session_id)
        self.assertIsNone(store.get(session.session_id))
        with self.assertRaises(GitHubServiceError) as context:
            service.complete_callback(session.session_id, state, "42", "install")
        self.assertEqual(context.exception.status.value, 401)
        with self.assertRaises(GitHubServiceError) as context:
            service.complete_callback(rotated.session_id, state, "42", "install")
        self.assertEqual(context.exception.status.value, 400)
        self.assertEqual(client.token_calls, 1)

    def test_token_failure_clears_connection(self) -> None:
        client = FakeGitHubClient()
        client.token_error = GitHubApiError(403)
        store = SessionStore()
        service = GitHubService(
            make_config(Path("/nonexistent/private-key.pem")),
            client=client,
            sessions=store,
        )
        session, _ = store.get_or_create(None)
        state = store.issue_state(session)

        with self.assertRaises(GitHubServiceError) as context:
            service.complete_callback(session.session_id, state, "42", "install")
        self.assertEqual(context.exception.status.value, 401)
        self.assertIsNone(session.installation_id)
        self.assertIsNone(session.installation_token)

    def test_branch_listing_rejects_repository_not_in_installation(self) -> None:
        client = FakeGitHubClient()
        store = SessionStore()
        service = GitHubService(
            make_config(Path("/nonexistent/private-key.pem")),
            client=client,
            sessions=store,
        )
        session, _ = store.get_or_create(None)
        store.set_connection(session, 42, "installation-token", 4102444800.0)

        with self.assertRaises(GitHubServiceError) as context:
            service.list_branches(session.session_id, "octo", "not-allowed")
        self.assertEqual(context.exception.status.value, 404)
        self.assertEqual(client.branch_calls, [])

    def test_branch_listing_uses_server_verified_repository(self) -> None:
        client = FakeGitHubClient()
        store = SessionStore()
        service = GitHubService(
            make_config(Path("/nonexistent/private-key.pem")),
            client=client,
            sessions=store,
        )
        session, _ = store.get_or_create(None)
        store.set_connection(session, 42, "installation-token", 4102444800.0)

        branches = service.list_branches(session.session_id, "octo", "allowed")

        self.assertEqual(branches, [{"name": "main", "protected": True}])
        self.assertEqual(client.branch_calls, [("octo", "allowed")])

    def test_csrf_token_is_required_for_disconnect(self) -> None:
        store = SessionStore()
        service = GitHubService(
            make_config(Path("/nonexistent/private-key.pem")),
            client=FakeGitHubClient(),
            sessions=store,
        )
        session, _ = store.get_or_create(None)
        store.set_connection(session, 42, "installation-token", 4102444800.0)

        with self.assertRaises(GitHubServiceError) as context:
            service.disconnect(session.session_id, "wrong-token")
        self.assertEqual(context.exception.status.value, 403)
        self.assertEqual(session.installation_id, 42)

        service.disconnect(session.session_id, session.csrf_token)
        self.assertIsNone(session.installation_id)

    def test_rate_limit_does_not_clear_authenticated_connection(self) -> None:
        client = FakeGitHubClient()
        client.repository_error = GitHubApiError(
            403,
            headers={"X-RateLimit-Remaining": "0", "Retry-After": "7"},
        )
        store = SessionStore()
        service = GitHubService(
            make_config(Path("/nonexistent/private-key.pem")),
            client=client,
            sessions=store,
        )
        session, _ = store.get_or_create(None)
        store.set_connection(session, 42, "installation-token", 4102444800.0)

        with self.assertRaises(GitHubServiceError) as context:
            service.list_repositories(session.session_id)
        self.assertEqual(context.exception.status.value, 429)
        self.assertEqual(context.exception.retry_after, 7)
        self.assertEqual(session.installation_id, 42)


class GitHubTransportSecurityTests(unittest.TestCase):
    def test_external_api_destination_is_rejected(self) -> None:
        with self.assertRaises(GitHubApiError):
            _validate_api_url("https://evil.example.test/repos/acme/project")

    def test_redirect_handler_rejects_malicious_destination(self) -> None:
        request = Request(
            "https://api.github.com/installation/repositories",
            headers={"Authorization": "Bearer installation-token"},
        )
        handler = _NoRedirectHandler()

        with self.assertRaises(HTTPError):
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {"Location": "https://evil.example.test/collect"},
            )

    def test_rate_limit_headers_are_captured_without_retrying(self) -> None:
        calls: list[Request] = []

        def opener(request: Request, *, timeout: float):
            calls.append(request)
            raise HTTPError(
                request.full_url,
                403,
                "rate limited",
                {"X-RateLimit-Remaining": "0", "Retry-After": "9"},
                None,
            )

        client = GitHubClient(make_config(Path("/nonexistent/private-key.pem")), opener=opener)
        with self.assertRaises(GitHubApiError) as context:
            client._request_json("GET", "/installation/repositories", token="installation-token")

        self.assertEqual(len(calls), 1)
        self.assertTrue(context.exception.is_rate_limited)
        self.assertEqual(context.exception.retry_after, 9)


class GitHubClientTests(unittest.TestCase):
    def test_app_jwt_is_signed_without_exposing_private_key(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "app.pem"
            key_path.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            client = GitHubClient(make_config(key_path), clock=lambda: 1_700_000_000.0)

            token = client.build_app_jwt()
            header, payload, signature = token.split(".")
            decoded_payload = json.loads(
                base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8")
            )

        self.assertEqual(json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))), {"alg": "RS256", "typ": "JWT"})
        self.assertEqual(decoded_payload["iss"], 123)
        self.assertEqual(len(signature), 342)
        self.assertNotIn("BEGIN PRIVATE KEY", token)


if __name__ == "__main__":
    unittest.main()
