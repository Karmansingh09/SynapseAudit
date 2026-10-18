"""Safe, loopback-only HTTP server for the SynapseAudit landing page and console.

The server exposes allowlisted fixture analysis, bounded in-memory YAML upload
analysis, and optional server-side GitHub App authorization metadata routes. It
never executes repository or Compose content and never exposes GitHub secrets.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import math
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import parse_qs, unquote, urlsplit

from .analyzer import ComposeConfigError, analyze_compose_bytes, analyze_file
from .github import (
    GitHubService,
    GitHubServiceError,
    SESSION_COOKIE_NAME,
    parse_trusted_proxies,
    resolve_client_ip,
    validate_repository_component,
)


LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
UPLOAD_ENDPOINT = "/api/analyze-upload"
UPLOAD_FIELD_NAME = "compose_file"
GITHUB_STATUS_ENDPOINT = "/api/github/status"
GITHUB_CONNECT_ENDPOINT = "/api/github/connect"
GITHUB_CALLBACK_ENDPOINT = "/api/github/callback"
GITHUB_REPOSITORIES_ENDPOINT = "/api/github/repositories"
GITHUB_DISCONNECT_ENDPOINT = "/api/github/disconnect"
GITHUB_SCAN_ENDPOINT = "/api/github/scan"
GITHUB_REPOSITORY_PREFIX = "/api/github/repositories/"
PUBLIC_GET_ROUTES = frozenset(
    {
        "/",
        "/static/dashboard.js",
        GITHUB_CALLBACK_ENDPOINT,
    }
)
MAX_UPLOAD_BYTES = 1 * 1024 * 1024
MAX_UPLOAD_REQUEST_BYTES = MAX_UPLOAD_BYTES + (64 * 1024)
MAX_SCAN_REQUEST_BYTES = 16 * 1024
PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATHS: Mapping[str, Path] = {
    "vulnerable": PROJECT_ROOT / "fixtures" / "compose.vulnerable.yml",
    "remediated": PROJECT_ROOT / "fixtures" / "compose.remediated.yml",
}
STATIC_LANDING = Path(__file__).with_name("static") / "landing.html"
STATIC_DASHBOARD = Path(__file__).with_name("static") / "dashboard.html"
STATIC_DASHBOARD_SCRIPT = Path(__file__).with_name("static") / "dashboard.js"
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "base-uri 'none'; "
    "connect-src 'self'; "
    "font-src 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'; "
    "img-src 'none'; "
    "object-src 'none'; "
    "script-src 'self'; "
    "style-src 'unsafe-inline'"
)
RESPONSE_SECURITY_HEADERS: Mapping[str, str] = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}
_GITHUB_CALLBACK_LOG_PATTERN = re.compile(r"(/api/github/callback)(?:\?[^\s\"]*)?")


def _redact_request_log(message: str) -> str:
    """Remove GitHub callback state and installation parameters from logs."""

    return _GITHUB_CALLBACK_LOG_PATTERN.sub(r"\1?[redacted]", message)


class _UploadError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _upload_compose_error(message: str) -> str:
    if "valid UTF-8" in message:
        return "Upload file must be valid UTF-8 text."
    if "valid YAML" in message:
        return "Upload file is not valid YAML."
    if "must define a non-empty services mapping" in message:
        return "Upload file must define a non-empty services mapping."
    return "Upload file is not a valid Compose configuration."


def analyze_fixture(fixture_id: str) -> dict[str, Any]:
    """Analyze one allowlisted fixture and return the analyzer's JSON shape."""

    fixture_path = FIXTURE_PATHS.get(fixture_id)
    if fixture_path is None:
        raise KeyError(fixture_id)
    return analyze_file(fixture_path).to_dict()


@dataclass
class _ClientRateLimitState:
    failures: list[float]
    locked_until: float = 0.0


class AuthRateLimiter:
    """Thread-safe, bounded in-memory rate limiter for failed dashboard authentication."""

    def __init__(
        self,
        *,
        max_failures: int = 5,
        window_seconds: float = 60.0,
        lockout_seconds: float = 300.0,
        max_tracked_clients: int = 1000,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.max_tracked_clients = max_tracked_clients
        self._clock = clock
        self._lock = threading.Lock()
        self._clients: dict[str, _ClientRateLimitState] = {}

    def is_locked(self, client_ip: str) -> tuple[bool, int]:
        with self._lock:
            now = self._clock()
            state = self._clients.get(client_ip)
            if state is None:
                return False, 0
            if state.locked_until > now:
                return True, int(math.ceil(state.locked_until - now))
            return False, 0

    def record_failure(self, client_ip: str) -> tuple[bool, int]:
        with self._lock:
            now = self._clock()
            self._prune_expired(now)
            state = self._clients.get(client_ip)
            if state is None:
                if len(self._clients) >= self.max_tracked_clients:
                    oldest_ip = min(
                        self._clients,
                        key=lambda ip: self._clients[ip].failures[-1]
                        if self._clients[ip].failures
                        else self._clients[ip].locked_until,
                    )
                    self._clients.pop(oldest_ip, None)
                state = _ClientRateLimitState(failures=[])
                self._clients[client_ip] = state

            state.failures = [t for t in state.failures if (now - t) <= self.window_seconds]
            state.failures.append(now)

            if len(state.failures) >= self.max_failures:
                state.locked_until = now + self.lockout_seconds
                state.failures.clear()
                return True, int(math.ceil(self.lockout_seconds))
            return False, 0

    def record_success(self, client_ip: str) -> None:
        with self._lock:
            self._clients.pop(client_ip, None)

    def _prune_expired(self, now: float) -> None:
        expired: list[str] = []
        for ip, state in self._clients.items():
            if state.locked_until > 0 and state.locked_until <= now:
                state.locked_until = 0.0
            state.failures = [t for t in state.failures if (now - t) <= self.window_seconds]
            if not state.failures and state.locked_until <= now:
                expired.append(ip)
        for ip in expired:
            self._clients.pop(ip, None)


class DashboardHandler(BaseHTTPRequestHandler):
    """Serve local analysis and optional GitHub App authorization endpoints."""

    server_version = "SynapseAuditDashboard/0.1"

    @property
    def _dashboard_password(self) -> str | None:
        return self.server.dashboard_password  # type: ignore[attr-defined]

    @property
    def _auth_rate_limiter(self) -> AuthRateLimiter:
        return self.server.auth_rate_limiter  # type: ignore[attr-defined]

    @property
    def _trusted_proxies(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        return getattr(self.server, "trusted_proxies", ())

    def _client_ip(self) -> str:
        peer = self.client_address[0] if self.client_address else "127.0.0.1"
        forwarded = self.headers.get_all("X-Forwarded-For") if self.headers else None
        return resolve_client_ip(peer, forwarded, self._trusted_proxies)

    def _send_unauthorized(self) -> None:
        self._send_json(
            HTTPStatus.UNAUTHORIZED,
            {"error": "Dashboard authentication required."},
            headers={"WWW-Authenticate": 'Basic realm="SynapseAudit"'},
        )

    def _send_rate_limited(self, retry_after: int) -> None:
        self._send_json(
            HTTPStatus.TOO_MANY_REQUESTS,
            {"error": "Too many failed authentication attempts. Please try again later."},
            headers={"Retry-After": str(retry_after)},
        )

    def _check_access(self, method: str, path: str) -> bool:
        """Enforce fail-closed access control on incoming requests."""

        if method == "GET" and path in PUBLIC_GET_ROUTES:
            return True

        if self._dashboard_password is None:
            return True

        locked, retry_after = self._auth_rate_limiter.is_locked(self._client_ip())
        if locked:
            self._send_rate_limited(retry_after)
            return False

        auth_header = self.headers.get("Authorization")
        if not auth_header:
            self._send_unauthorized()
            return False

        try:
            scheme, _, credentials = auth_header.partition(" ")
            if scheme.lower() != "basic" or not credentials:
                raise ValueError("Unsupported or malformed authorization header")
            decoded = base64.b64decode(credentials.strip(), validate=True).decode("utf-8")
            _, has_colon, password = decoded.partition(":")
            if not has_colon:
                raise ValueError("Basic auth must contain username and password")
        except Exception:
            locked, retry_after = self._auth_rate_limiter.record_failure(self._client_ip())
            if locked:
                self._send_rate_limited(retry_after)
            else:
                self._send_unauthorized()
            return False

        if secrets.compare_digest(password, self._dashboard_password):
            self._auth_rate_limiter.record_success(self._client_ip())
            return True

        locked, retry_after = self._auth_rate_limiter.record_failure(self._client_ip())
        if locked:
            self._send_rate_limited(retry_after)
        else:
            self._send_unauthorized()
        return False

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        request = urlsplit(self.path)
        if not self._check_access("GET", request.path):
            return
        if request.path == "/":
            self._serve_landing()
            return
        if request.path == "/console":
            self._serve_dashboard()
            return
        if request.path == "/static/dashboard.js":
            self._serve_dashboard_script()
            return
        if request.path == GITHUB_STATUS_ENDPOINT:
            self._serve_github_status()
            return
        if request.path == GITHUB_CONNECT_ENDPOINT:
            self._serve_github_connect()
            return
        if request.path == GITHUB_CALLBACK_ENDPOINT:
            self._serve_github_callback(parse_qs(request.query, keep_blank_values=True))
            return
        if request.path == GITHUB_REPOSITORIES_ENDPOINT:
            self._serve_github_repositories()
            return
        if request.path == GITHUB_SCAN_ENDPOINT:
            self._github_method_not_allowed()
            return
        branch_route = self._parse_github_branch_route(request.path)
        if branch_route is not None:
            self._serve_github_branches(*branch_route)
            return
        if request.path == UPLOAD_ENDPOINT:
            self._upload_method_not_allowed()
            return
        if request.path == "/api/analyze":
            self._serve_analysis(parse_qs(request.query, keep_blank_values=True))
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    @property
    def _github(self) -> GitHubService:
        return self.server.github_service  # type: ignore[attr-defined]

    def _session_cookie_value(self) -> str | None:
        cookie_header = self.headers.get("Cookie", "")
        cookies = SimpleCookie()
        try:
            cookies.load(cookie_header)
        except ValueError:
            return None
        morsel = cookies.get(SESSION_COOKIE_NAME)
        if morsel is None:
            return None
        value = morsel.value
        if not value or len(value) > 128 or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in value):
            return None
        return value

    def _ensure_github_session(self) -> tuple[str, str | None]:
        session, created = self._github.ensure_session(self._session_cookie_value())
        return session.session_id, self._github.session_cookie(session.session_id) if created else None

    def _existing_github_session(self) -> str | None:
        session_id = self._session_cookie_value()
        if self._github.existing_session(session_id) is None:
            return None
        return session_id

    def _serve_github_status(self) -> None:
        session_id, cookie = self._ensure_github_session()
        headers = {"Set-Cookie": cookie} if cookie else None
        self._send_json(HTTPStatus.OK, self._github.status(session_id), headers=headers)

    def _serve_github_connect(self) -> None:
        session_id, cookie = self._ensure_github_session()
        try:
            authorization_url = self._github.begin_connect(session_id)
        except GitHubServiceError as exc:
            self._send_github_error(exc, cookie=cookie)
            return
        headers = {"Set-Cookie": cookie} if cookie else None
        self._send_json(
            HTTPStatus.OK,
            {"status": "authorization_pending", "authorization_url": authorization_url},
            headers=headers,
        )

    def _serve_github_callback(self, query: Mapping[str, list[str]]) -> None:
        session_id = self._existing_github_session()
        if session_id is None:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "GitHub authorization session is missing or expired."},
            )
            return
        if any(len(values) > 1 for values in query.values()):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "GitHub authorization callback is incomplete."},
            )
            return
        state_values = query.get("state", [])
        installation_values = query.get("installation_id", [])
        setup_values = query.get("setup_action", [])
        error_values = query.get("error", [])
        try:
            rotated_session = self._github.complete_callback(
                session_id,
                state_values[0] if len(state_values) == 1 else "",
                installation_values[0] if len(installation_values) == 1 else "",
                setup_values[0] if len(setup_values) == 1 else "",
                error=error_values[0] if error_values else None,
            )
        except GitHubServiceError as exc:
            self._send_github_error(exc)
            return
        self._send_redirect(
            "/console?github=connected",
            headers={"Set-Cookie": self._github.session_cookie(rotated_session.session_id)},
        )

    def _serve_github_repositories(self) -> None:
        session_id = self._existing_github_session()
        if session_id is None:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "GitHub authorization is required."})
            return
        try:
            repositories = self._github.list_repositories(session_id)
        except GitHubServiceError as exc:
            self._send_github_error(exc)
            return
        self._send_json(HTTPStatus.OK, {"repositories": repositories})

    def _serve_github_branches(self, owner: str, repository: str) -> None:
        session_id = self._existing_github_session()
        if session_id is None:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "GitHub authorization is required."})
            return
        try:
            branches = self._github.list_branches(session_id, owner, repository)
        except GitHubServiceError as exc:
            self._send_github_error(exc)
            return
        self._send_json(HTTPStatus.OK, {"branches": branches})

    def _serve_github_disconnect(self) -> None:
        session_id = self._existing_github_session()
        if session_id is None:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "GitHub authorization is required."})
            return
        try:
            self._github.disconnect(session_id, self.headers.get("X-CSRF-Token"))
        except GitHubServiceError as exc:
            self._send_github_error(exc)
            return
        self._send_json(HTTPStatus.OK, {"connected": False})

    def _serve_github_scan(self) -> None:
        session_id = self._existing_github_session()
        if session_id is None:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "GitHub authorization is required."})
            return
        body = self._read_scan_request_body()
        if body is None:
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "GitHub scan requests must use application/json."},
            )
            return
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "GitHub scan request is invalid JSON."})
            return
        if not isinstance(payload, dict) or set(payload) != {"owner", "repository", "branch"}:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "GitHub scan requires owner, repository, and branch."},
            )
            return
        if not all(isinstance(payload.get(key), str) for key in ("owner", "repository", "branch")):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "GitHub scan identifiers must be strings."},
            )
            return
        try:
            result = self._github.scan_repository(
                session_id,
                payload["owner"],
                payload["repository"],
                payload["branch"],
                self.headers.get("X-CSRF-Token"),
            )
        except GitHubServiceError as exc:
            self._send_github_error(exc)
            return
        self._send_json(HTTPStatus.OK, result)

    def _read_scan_request_body(self) -> bytes | None:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self._send_json(
                HTTPStatus.LENGTH_REQUIRED,
                {"error": "Content-Length is required for GitHub scans."},
            )
            return None
        try:
            content_length = int(raw_length)
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Content-Length is invalid."})
            return None
        if content_length < 0:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Content-Length is invalid."})
            return None
        if content_length > MAX_SCAN_REQUEST_BYTES:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": "GitHub scan request exceeds the bounded request limit."},
            )
            return None
        body = self.rfile.read(content_length)
        if len(body) != content_length:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "GitHub scan request was incomplete."})
            return None
        return body

    def _parse_github_branch_route(self, path: str) -> tuple[str, str] | None:
        if not path.startswith(GITHUB_REPOSITORY_PREFIX) or not path.endswith("/branches"):
            return None
        middle = path[len(GITHUB_REPOSITORY_PREFIX) : -len("/branches")]
        components = middle.split("/")
        if len(components) != 2:
            return None
        try:
            return (
                validate_repository_component(unquote(components[0])),
                validate_repository_component(unquote(components[1])),
            )
        except GitHubServiceError:
            return None

    def _send_github_error(self, error: GitHubServiceError, *, cookie: str | None = None) -> None:
        headers: dict[str, str] = {}
        if cookie:
            headers["Set-Cookie"] = cookie
        if error.retry_after is not None:
            headers["Retry-After"] = str(error.retry_after)
        payload: dict[str, Any] = {"error": error.public_message}
        if error.clear_connection:
            payload["connected"] = False
        self._send_json(error.status, payload, headers=headers or None)

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        request = urlsplit(self.path)
        if not self._check_access("POST", request.path):
            return
        if request.path == UPLOAD_ENDPOINT:
            self._serve_upload()
            return
        if request.path == GITHUB_DISCONNECT_ENDPOINT:
            self._serve_github_disconnect()
            return
        if request.path == GITHUB_SCAN_ENDPOINT:
            self._serve_github_scan()
            return
        if request.path.startswith("/api/github/"):
            self._github_method_not_allowed()
            return
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        request = urlsplit(self.path)
        if not self._check_access("PUT", request.path):
            return
        if request.path == UPLOAD_ENDPOINT:
            self._upload_method_not_allowed()
            return
        if request.path.startswith("/api/github/"):
            self._github_method_not_allowed()
            return
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        request = urlsplit(self.path)
        if not self._check_access("DELETE", request.path):
            return
        if request.path == UPLOAD_ENDPOINT:
            self._upload_method_not_allowed()
            return
        if request.path.startswith("/api/github/"):
            self._github_method_not_allowed()
            return
        self._method_not_allowed()

    def do_HEAD(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        request = urlsplit(self.path)
        if not self._check_access("HEAD", request.path):
            return
        self._method_not_allowed()

    def _serve_landing(self) -> None:
        self._serve_fixed_html(STATIC_LANDING, "Landing page")

    def _serve_dashboard(self) -> None:
        self._serve_fixed_html(STATIC_DASHBOARD, "Dashboard asset")

    def _serve_dashboard_script(self) -> None:
        self._serve_fixed_asset(
            STATIC_DASHBOARD_SCRIPT,
            "Dashboard script",
            "application/javascript; charset=utf-8",
        )

    def _serve_fixed_html(self, asset_path: Path, asset_name: str) -> None:
        self._serve_fixed_asset(asset_path, asset_name, "text/html; charset=utf-8")

    def _serve_fixed_asset(self, asset_path: Path, asset_name: str, content_type: str) -> None:
        try:
            content = asset_path.read_bytes()
        except OSError as exc:
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": f"{asset_name} is unavailable: {exc}"},
            )
            return

        self._send_bytes(HTTPStatus.OK, content, content_type)

    def _serve_analysis(self, query: Mapping[str, list[str]]) -> None:
        fixture_values = query.get("fixture", [])
        if len(fixture_values) != 1 or not fixture_values[0]:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Provide exactly one fixture query parameter."},
            )
            return

        fixture_id = fixture_values[0]
        if fixture_id not in FIXTURE_PATHS:
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"error": "Unknown fixture. Use vulnerable or remediated."},
            )
            return

        try:
            report = analyze_fixture(fixture_id)
        except ComposeConfigError as exc:
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": f"Fixture analysis failed: {exc}"},
            )
            return

        self._send_json(HTTPStatus.OK, report)

    def _serve_upload(self) -> None:
        content_length = self._request_content_length()
        if content_length is None:
            return

        body = self.rfile.read(content_length)
        if len(body) != content_length:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Upload body was incomplete."})
            return

        try:
            content = self._extract_upload(body)
        except _UploadError as exc:
            self._send_json(exc.status, {"error": exc.message})
            return
        except Exception:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Multipart upload is malformed."},
            )
            return

        if not content:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Upload file must not be empty."})
            return
        if len(content) > MAX_UPLOAD_BYTES:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": "Upload file exceeds the 1 MiB limit."},
            )
            return

        try:
            report = analyze_compose_bytes(content).to_dict()
        except ComposeConfigError as exc:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": _upload_compose_error(str(exc))},
            )
            return

        self._send_json(HTTPStatus.OK, report)

    def _request_content_length(self) -> int | None:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self._send_json(
                HTTPStatus.LENGTH_REQUIRED,
                {"error": "Content-Length is required for uploads."},
            )
            return None
        try:
            content_length = int(raw_length)
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Content-Length is invalid."})
            return None
        if content_length < 0:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Content-Length is invalid."})
            return None
        if content_length > MAX_UPLOAD_REQUEST_BYTES:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": "Upload request exceeds the bounded request limit."},
            )
            return None
        return content_length

    def _extract_upload(self, body: bytes) -> bytes:
        content_type = self.headers.get("Content-Type", "")
        header = Message()
        try:
            header["Content-Type"] = content_type
            media_type = header.get_content_type()
            boundary = header.get_param("boundary", header="Content-Type")
        except (TypeError, ValueError) as exc:
            raise _UploadError(HTTPStatus.BAD_REQUEST, "Multipart content type is invalid.") from exc

        if media_type != "multipart/form-data" or not boundary:
            raise _UploadError(
                HTTPStatus.BAD_REQUEST,
                "Upload must use multipart/form-data.",
            )

        try:
            content_type_header = content_type.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise _UploadError(HTTPStatus.BAD_REQUEST, "Multipart content type is invalid.") from exc

        message_bytes = (
            b"MIME-Version: 1.0\r\n"
            + b"Content-Type: "
            + content_type_header
            + b"\r\n\r\n"
            + body
        )
        try:
            message = BytesParser(policy=policy.default).parsebytes(message_bytes)
        except (OSError, ValueError) as exc:
            raise _UploadError(HTTPStatus.BAD_REQUEST, "Multipart upload is malformed.") from exc

        if not message.is_multipart():
            raise _UploadError(HTTPStatus.BAD_REQUEST, "Multipart upload is malformed.")

        upload_content: bytes | None = None
        for part in message.iter_parts():
            if part.get_content_disposition() != "form-data":
                continue
            field_name = part.get_param("name", header="content-disposition")
            if field_name != UPLOAD_FIELD_NAME:
                continue
            if upload_content is not None:
                raise _UploadError(
                    HTTPStatus.BAD_REQUEST,
                    f"Provide exactly one {UPLOAD_FIELD_NAME} file.",
                )
            if part.get_filename() is None:
                raise _UploadError(HTTPStatus.BAD_REQUEST, "Upload file is missing.")
            if not part.get_filename().lower().endswith((".yml", ".yaml")):
                raise _UploadError(
                    HTTPStatus.BAD_REQUEST,
                    "Upload filename must end in .yml or .yaml.",
                )
            if part.is_multipart():
                raise _UploadError(HTTPStatus.BAD_REQUEST, "Upload file part is invalid.")
            transfer_encoding = (part.get("Content-Transfer-Encoding") or "").lower()
            if transfer_encoding not in {"", "7bit", "8bit", "binary"}:
                raise _UploadError(HTTPStatus.BAD_REQUEST, "Upload transfer encoding is unsupported.")
            upload_content = part.get_payload(decode=True) or b""

        if upload_content is None:
            raise _UploadError(
                HTTPStatus.BAD_REQUEST,
                f"Multipart field {UPLOAD_FIELD_NAME!r} is required.",
            )
        return upload_content

    def _method_not_allowed(self) -> None:
        self._send_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"error": "Only GET requests are supported."},
            headers={"Allow": "GET"},
        )

    def _upload_method_not_allowed(self) -> None:
        self._send_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"error": "Only POST requests are supported for uploads."},
            headers={"Allow": "POST"},
        )

    def _github_method_not_allowed(self) -> None:
        self._send_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"error": "GitHub endpoint method is not supported."},
            headers={"Allow": "GET, POST"},
        )

    def _send_redirect(
        self,
        location: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self._send_bytes(
            HTTPStatus.SEE_OTHER,
            b"GitHub authorization completed. Return to the SynapseAudit console.",
            "text/plain; charset=utf-8",
            headers={"Location": location, **(headers or {})},
        )

    def _send_json(
        self,
        status: HTTPStatus,
        payload: Mapping[str, Any],
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8", headers=headers)

    def _send_bytes(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in RESPONSE_SECURITY_HEADERS.items():
            self.send_header(name, value)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        """Keep normal request logs concise while retaining local diagnostics."""

        print(f"[dashboard] {_redact_request_log(format % args)}")


class DashboardServer(ThreadingHTTPServer):
    """HTTP server configured for short-lived local dashboard requests."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler: type[BaseHTTPRequestHandler],
        github_service: GitHubService | None = None,
        dashboard_password: str | None = None,
        auth_rate_limiter: AuthRateLimiter | None = None,
        trusted_proxies: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network] = (),
    ) -> None:
        super().__init__(server_address, request_handler)
        self.github_service = github_service or GitHubService.from_environment()
        self.dashboard_password = dashboard_password
        self.auth_rate_limiter = auth_rate_limiter or AuthRateLimiter()
        self.trusted_proxies = tuple(trusted_proxies)


def create_server(
    port: int = DEFAULT_PORT,
    *,
    github_service: GitHubService | None = None,
    dashboard_password: str | None = None,
    auth_rate_limiter: AuthRateLimiter | None = None,
    trusted_proxies: (
        Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network | str] | str | None
    ) = None,
    environ: Mapping[str, str] | None = None,
) -> DashboardServer:
    """Create a server bound only to loopback; port 0 requests an ephemeral port."""

    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise ValueError("port must be an integer from 0 through 65535")
    values = environ if environ is not None else os.environ
    service = github_service or GitHubService.from_environment(values)
    pwd = (
        dashboard_password
        if dashboard_password is not None
        else values.get("SYNAPSEAUDIT_DASHBOARD_PASSWORD", "").strip() or None
    )
    if service.configured and not pwd:
        raise ValueError(
            "SYNAPSEAUDIT_DASHBOARD_PASSWORD is required when GitHub integration is enabled."
        )
    raw_proxies = (
        trusted_proxies
        if trusted_proxies is not None
        else (
            service.config.trusted_proxies
            if service.config is not None and service.config.trusted_proxies
            else values.get("SYNAPSEAUDIT_TRUSTED_PROXIES")
        )
    )
    parsed_proxies = parse_trusted_proxies(raw_proxies)
    return DashboardServer(
        (LOOPBACK_HOST, port),
        DashboardHandler,
        service,
        dashboard_password=pwd,
        auth_rate_limiter=auth_rate_limiter,
        trusted_proxies=parsed_proxies,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="synapseaudit-dashboard",
        description="Serve the SynapseAudit dashboard on loopback only.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"loopback TCP port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--trusted-proxies",
        type=str,
        default=None,
        help="comma-separated list of trusted proxy IP addresses or CIDRs",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        server = create_server(args.port, trusted_proxies=args.trusted_proxies)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    except OSError as exc:
        print(f"error: could not bind to http://{LOOPBACK_HOST}:{args.port}: {exc}")
        return 2

    actual_port = server.server_address[1]
    print(f"SynapseAudit local UI: http://{LOOPBACK_HOST}:{actual_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSynapseAudit dashboard stopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
