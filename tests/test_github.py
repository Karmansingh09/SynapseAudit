from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import threading
import unittest
from http import HTTPStatus
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
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
    ScanAdmission,
    ScanLimits,
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


class JsonResponse:
    def __init__(self, payload: object, url: str) -> None:
        self.body = json.dumps(payload).encode("utf-8")
        self.url = url
        self.headers = {"Content-Length": str(len(self.body))}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def geturl(self) -> str:
        return self.url

    def read(self, amount: int = -1) -> bytes:
        return self.body if amount < 0 else self.body[:amount]


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
                "SYNAPSEAUDIT_DASHBOARD_PASSWORD": "synthetic-test-password",
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

    def test_scan_admission_rejects_simultaneous_session_and_releases_slot(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        class BlockingScanClient(FakeGitHubClient):
            def scan_repository(self, token, owner, repository, branch, *, limits, budget):
                entered.set()
                release.wait(2)
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

        client = BlockingScanClient()
        store = SessionStore()
        admission = ScanAdmission(1)
        service = GitHubService(
            make_config(Path("/nonexistent/private-key.pem")),
            client=client,
            sessions=store,
            scan_admission=admission,
        )
        session, _ = store.get_or_create(None)
        store.set_connection(session, 42, "installation-token", 4102444800.0)
        result_holder: list[dict[str, object]] = []
        scan_thread = threading.Thread(
            target=lambda: result_holder.append(
                service.scan_repository(session.session_id, "octo", "allowed", "main", session.csrf_token)
            )
        )
        scan_thread.start()
        self.assertTrue(entered.wait(1))
        with self.assertRaises(GitHubServiceError) as context:
            service.scan_repository(session.session_id, "octo", "allowed", "main", session.csrf_token)
        self.assertEqual(context.exception.status, HTTPStatus.TOO_MANY_REQUESTS)
        release.set()
        scan_thread.join(timeout=2)
        self.assertFalse(scan_thread.is_alive())
        service.scan_repository(session.session_id, "octo", "allowed", "main", session.csrf_token)


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


class GitHubRepositoryScanTests(unittest.TestCase):
    COMMIT_SHA = "a" * 40
    TREE_SHA = "d" * 40
    BLOB_ONE = "7c39c47e46832dc4b88fa549cf64234c70d0542d"
    BLOB_TWO = "ef6cdd74b51427b8ba33d8c6783b2280e4548552"

    @staticmethod
    def git_blob_sha(content: bytes) -> str:
        return hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()

    def test_scan_limits_are_configurable_with_safe_defaults(self) -> None:
        limits = ScanLimits.from_environment(
            {
                "SYNAPSEAUDIT_SCAN_MAX_TREE_ENTRIES": "7",
                "SYNAPSEAUDIT_SCAN_MAX_SUPPORTED_FILES": "3",
                "SYNAPSEAUDIT_SCAN_MAX_FILE_BYTES": "11",
                "SYNAPSEAUDIT_SCAN_MAX_TOTAL_BYTES": "22",
                "SYNAPSEAUDIT_SCAN_MAX_DURATION_SECONDS": "1.5",
                "SYNAPSEAUDIT_SCAN_MAX_HTTP_RESPONSE_BYTES": "33",
                "SYNAPSEAUDIT_SCAN_MAX_API_PAGES": "4",
                "SYNAPSEAUDIT_SCAN_MAX_API_REQUESTS": "5",
                "SYNAPSEAUDIT_SCAN_MAX_SKIPPED_DETAILS": "6",
            }
        )

        self.assertEqual(limits.max_tree_entries, 7)
        self.assertEqual(limits.max_scan_duration_seconds, 1.5)
        self.assertEqual(limits.max_skipped_details, 6)
        defaults = ScanLimits()
        self.assertEqual(
            ScanLimits.from_environment(
                {"SYNAPSEAUDIT_SCAN_MAX_DURATION_SECONDS": "inf"}
            ).max_scan_duration_seconds,
            defaults.max_scan_duration_seconds,
        )
        capped = ScanLimits.from_environment(
            {
                "SYNAPSEAUDIT_SCAN_MAX_TREE_ENTRIES": "999999999",
                "SYNAPSEAUDIT_SCAN_MAX_CONCURRENT": "999999999",
                "SYNAPSEAUDIT_SCAN_MAX_YAML_DEPTH": "999999999",
            }
        )
        self.assertEqual(capped.max_tree_entries, 50_000)
        self.assertEqual(capped.max_concurrent_scans, 16)
        self.assertEqual(capped.max_yaml_depth, 256)

    @staticmethod
    def blob_payload(content: bytes, sha: str) -> dict[str, object]:
        return {
            "sha": sha,
            "encoding": "base64",
            "size": len(content),
            "content": base64.b64encode(content).decode("ascii"),
        }

    def make_client(
        self,
        tree: list[object],
        blobs: dict[str, bytes],
        *,
        commit_payload: dict[str, object] | None = None,
        tree_response_sha: str | None = None,
        blob_response_shas: dict[str, str] | None = None,
        blob_response_contents: dict[str, bytes] | None = None,
    ) -> tuple[GitHubClient, list[Request]]:
        vulnerable = Path(__file__).resolve().parents[1] / "fixtures" / "compose.vulnerable.yml"
        requested: list[Request] = []

        def opener(request: Request, *, timeout: float):
            requested.append(request)
            parsed = urlsplit(request.full_url)
            if parsed.path == "/installation/repositories":
                payload: object = {
                    "repositories": [
                        {"name": "allowed", "full_name": "octo/allowed", "private": True}
                    ]
                }
            elif parsed.path == "/repos/octo/allowed/branches/main":
                payload = {"name": "main", "commit": {"sha": self.COMMIT_SHA}}
            elif parsed.path == f"/repos/octo/allowed/git/commits/{self.COMMIT_SHA}":
                payload = commit_payload or {"sha": self.COMMIT_SHA, "tree": {"sha": self.TREE_SHA}}
            elif parsed.path == f"/repos/octo/allowed/git/trees/{self.TREE_SHA}":
                payload = {"sha": tree_response_sha or self.TREE_SHA, "truncated": False, "tree": tree}
            elif parsed.path.startswith("/repos/octo/allowed/git/blobs/"):
                blob_sha = parsed.path.rsplit("/", 1)[-1]
                if blob_sha not in blobs:
                    raise HTTPError(request.full_url, 404, "missing", {}, None)
                response_content = (blob_response_contents or {}).get(blob_sha, blobs[blob_sha])
                response_sha = (blob_response_shas or {}).get(blob_sha, blob_sha)
                payload = self.blob_payload(response_content, response_sha)
            else:
                raise AssertionError(f"unexpected GitHub request: {request.full_url}")
            return JsonResponse(payload, request.full_url)

        client = GitHubClient(
            make_config(Path("/nonexistent/private-key.pem")),
            opener=opener,
        )
        if not blobs:
            blobs[self.BLOB_ONE] = vulnerable.read_bytes()
        return client, requested

    def test_scan_pins_tree_and_blobs_to_resolved_commit_and_reports_skips(self) -> None:
        remediated = Path(__file__).resolve().parents[1] / "fixtures" / "compose.remediated.yml"
        tree = [
            {"path": "nested/compose.yml", "type": "blob", "sha": self.BLOB_ONE},
            {"path": "nested/docker-compose.yaml", "type": "blob", "sha": self.BLOB_TWO},
            {"path": "README.md", "type": "blob", "sha": "d" * 40},
            {"path": "nested/compose.yaml", "type": "symlink", "sha": "e" * 40},
            {"path": "nested/docker-compose.yml", "type": "commit", "sha": "f" * 40},
            {"path": "../compose.yml", "type": "blob", "sha": "1" * 40},
        ]
        client, requested = self.make_client(
            tree,
            {self.BLOB_ONE: (Path(__file__).resolve().parents[1] / "fixtures" / "compose.vulnerable.yml").read_bytes(), self.BLOB_TWO: remediated.read_bytes()},
        )

        result = client.scan_repository(
            "installation-token",
            "octo",
            "allowed",
            "main",
            limits=ScanLimits(max_api_requests=20),
        )
        payload = result.to_dict()

        self.assertEqual(payload["status"], "complete")
        self.assertEqual(payload["source"], "github_repository")
        self.assertFalse(payload["analysis_scope"]["repository_code_executed"])
        self.assertEqual(payload["commit_sha"], self.COMMIT_SHA)
        self.assertEqual([item["path"] for item in payload["files"]], ["nested/compose.yml", "nested/docker-compose.yaml"])
        self.assertEqual(len(payload["files"][0]["report"]["findings"]), 4)
        self.assertEqual(payload["files"][1]["report"]["findings"], [])
        self.assertTrue(all(finding["file_path"] == "nested/compose.yml" for finding in payload["files"][0]["report"]["findings"]))
        self.assertIn("filename is outside the supported Compose scope", payload["skipped_counts"])
        self.assertIn("tree entry is not a blob; symlinks and submodules are not fetched", payload["skipped_counts"])
        self.assertIn("repository path is unsafe", payload["skipped_counts"])
        self.assertTrue(any(f"/git/commits/{self.COMMIT_SHA}" in request.full_url for request in requested))
        self.assertTrue(any(f"/git/trees/{self.TREE_SHA}" in request.full_url for request in requested))
        self.assertFalse(any("/git/trees/main" in request.full_url for request in requested))
        self.assertFalse(any("/zipball/" in request.full_url or "/tarball/" in request.full_url for request in requested))

    def test_scan_rejects_missing_or_mismatched_tree_identity(self) -> None:
        content = b"services:\n  web:\n    image: safe\n"
        blob = self.git_blob_sha(content)
        tree = [{"path": "compose.yml", "type": "blob", "sha": blob}]
        cases = (
            {"sha": self.COMMIT_SHA, "tree": {}},
            None,
        )
        for commit_payload in cases:
            with self.subTest(commit_payload=commit_payload):
                client, _ = self.make_client(
                    tree,
                    {blob: content},
                    commit_payload=commit_payload,
                    tree_response_sha="e" * 40 if commit_payload is None else None,
                )
                with self.assertRaises(GitHubApiError):
                    client.scan_repository(
                        "installation-token", "octo", "allowed", "main", limits=ScanLimits()
                    )

        client, _ = self.make_client(
            tree,
            {blob: content},
            tree_response_sha="e" * 40,
        )
        with self.assertRaises(GitHubApiError):
            client.scan_repository(
                "installation-token", "octo", "allowed", "main", limits=ScanLimits()
            )

    def test_scan_rejects_mismatched_blob_identity_and_content_hash(self) -> None:
        content = b"services:\n  web:\n    image: safe\n"
        blob = self.git_blob_sha(content)
        tree = [{"path": "compose.yml", "type": "blob", "sha": blob}]

        client, _ = self.make_client(
            tree,
            {blob: content},
            blob_response_shas={blob: "f" * 40},
        )
        with self.assertRaises(GitHubApiError):
            client.scan_repository(
                "installation-token", "octo", "allowed", "main", limits=ScanLimits()
            )

        client, _ = self.make_client(
            tree,
            {blob: content},
            blob_response_contents={blob: b"services:\n  web:\n    image: changed\n"},
        )
        with self.assertRaises(GitHubApiError):
            client.scan_repository(
                "installation-token", "octo", "allowed", "main", limits=ScanLimits()
            )

    def test_each_scan_budget_returns_explicit_limited_status(self) -> None:
        first_content = b"services:\n  web:\n    image: safe\n"
        second_content = b"services:\n  api:\n    image: safe\n"
        first_blob = self.git_blob_sha(first_content)
        second_blob = self.git_blob_sha(second_content)
        tree = [
            {"path": "compose.yml", "type": "blob", "sha": first_blob},
            {"path": "docker-compose.yaml", "type": "blob", "sha": second_blob},
        ]
        limits = (
            ScanLimits(max_tree_entries=1),
            ScanLimits(max_supported_files=1),
            ScanLimits(max_file_bytes=1),
            ScanLimits(max_total_downloaded_bytes=1),
            ScanLimits(max_scan_duration_seconds=0.000000001),
            ScanLimits(max_http_response_bytes=1),
            ScanLimits(max_api_pages=0),
            ScanLimits(max_api_requests=2),
        )
        for scan_limits in limits:
            with self.subTest(scan_limits=scan_limits):
                client, _ = self.make_client(
                    tree,
                    {first_blob: first_content, second_blob: second_content},
                )
                result = client.scan_repository(
                    "installation-token",
                    "octo",
                    "allowed",
                    "main",
                    limits=scan_limits,
                )
                self.assertEqual(result.status, "limited")
                self.assertTrue(result.limited_reasons)

    def test_invalid_supported_compose_is_skipped_and_not_reported_clean(self) -> None:
        invalid_content = b"services:\n  broken: [\n"
        invalid_blob = self.git_blob_sha(invalid_content)
        client, _ = self.make_client(
            [{"path": "compose.yml", "type": "blob", "sha": invalid_blob}],
            {invalid_blob: invalid_content},
        )

        result = client.scan_repository(
            "installation-token",
            "octo",
            "allowed",
            "main",
            limits=ScanLimits(),
        )

        self.assertEqual(result.status, "no_supported_files")
        self.assertEqual(result.files, ())
        self.assertIn("file is not valid supported Compose YAML", result.skipped_counts)


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
