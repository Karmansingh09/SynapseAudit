"""Optional, server-side GitHub App authorization for SynapseAudit.

This module only manages GitHub App installation authorization and bounded
metadata requests. It never fetches repository contents, executes repository
code, or exposes GitHub credentials to the browser.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from typing import Any, Callable, Mapping, MutableMapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


GITHUB_API_ORIGIN = "https://api.github.com"
GITHUB_INSTALL_ORIGIN = "https://github.com/apps"
GITHUB_API_VERSION = "2022-11-28"
GITHUB_USER_AGENT = "SynapseAudit-GitHub-App/1.0"
SESSION_COOKIE_NAME = "synapseaudit_session"
SESSION_TTL_SECONDS = 60 * 60
STATE_TTL_SECONDS = 10 * 60
INSTALLATION_TOKEN_SKEW_SECONDS = 60
MAX_GITHUB_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_REPOSITORIES = 1000
MAX_BRANCHES = 1000
MAX_API_PAGES = 10
MAX_SESSIONS = 1000
REPOSITORY_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]+$")


class GitHubConfigurationError(ValueError):
    """Raised when GitHub App configuration is incomplete or invalid."""


class GitHubServiceError(Exception):
    """A safe, user-facing GitHub integration failure."""

    def __init__(
        self,
        status: HTTPStatus,
        public_message: str,
        *,
        clear_connection: bool = False,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(public_message)
        self.status = status
        self.public_message = public_message
        self.clear_connection = clear_connection
        self.retry_after = retry_after


class GitHubApiError(Exception):
    """Internal GitHub API failure without response-body or token details."""

    def __init__(
        self,
        status: int | None,
        message: str = "GitHub API request failed",
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.headers = {name.lower(): value for name, value in (headers or {}).items()}

    @property
    def is_rate_limited(self) -> bool:
        return (
            self.status == HTTPStatus.TOO_MANY_REQUESTS
            or self.headers.get("x-ratelimit-remaining") == "0"
            or "retry-after" in self.headers
        )

    @property
    def retry_after(self) -> int:
        raw_retry_after = self.headers.get("retry-after", "")
        if raw_retry_after.isdigit():
            return max(1, min(int(raw_retry_after), 3600))
        raw_reset = self.headers.get("x-ratelimit-reset", "")
        if raw_reset.isdigit():
            return max(1, min(int(raw_reset) - int(time.time()), 3600))
        return 60


class _NoRedirectHandler(HTTPRedirectHandler):
    """Reject redirects so GitHub credentials never cross origins."""

    def redirect_request(self, request: Request, *args: Any, **kwargs: Any) -> Request:
        raise HTTPError(request.full_url, 302, "GitHub API redirects are disabled", {}, None)


def _validate_api_url(url: str) -> None:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise GitHubApiError(None, "GitHub API destination was rejected.") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.github.com"
        or port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise GitHubApiError(None, "GitHub API destination was rejected.")


@dataclass(frozen=True)
class GitHubConfig:
    """Validated server-side GitHub App configuration."""

    app_id: int
    app_slug: str
    private_key_path: Path
    callback_url: str
    session_ttl_seconds: int = SESSION_TTL_SECONDS
    state_ttl_seconds: int = STATE_TTL_SECONDS

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> GitHubConfig | None:
        values = environ if environ is not None else os.environ
        names = (
            "SYNAPSEAUDIT_GITHUB_APP_ID",
            "SYNAPSEAUDIT_GITHUB_APP_SLUG",
            "SYNAPSEAUDIT_GITHUB_PRIVATE_KEY_FILE",
            "SYNAPSEAUDIT_GITHUB_CALLBACK_URL",
        )
        configured = [bool(values.get(name, "").strip()) for name in names]
        if not any(configured):
            return None
        if not all(configured):
            raise GitHubConfigurationError(
                "GitHub App integration requires all server-side configuration values."
            )

        raw_app_id = values["SYNAPSEAUDIT_GITHUB_APP_ID"]
        if not raw_app_id.isdigit() or int(raw_app_id) <= 0:
            raise GitHubConfigurationError("GitHub App ID must be a positive integer.")

        app_slug = values["SYNAPSEAUDIT_GITHUB_APP_SLUG"].strip()
        if not REPOSITORY_COMPONENT.fullmatch(app_slug):
            raise GitHubConfigurationError("GitHub App slug contains unsupported characters.")

        callback_url = values["SYNAPSEAUDIT_GITHUB_CALLBACK_URL"].strip()
        callback = urlsplit(callback_url)
        if (
            callback.scheme != "https"
            or not callback.netloc
            or callback.username is not None
            or callback.password is not None
            or callback.fragment
        ):
            raise GitHubConfigurationError(
                "GitHub callback URL must use HTTPS and include a host."
            )

        private_key_path = Path(values["SYNAPSEAUDIT_GITHUB_PRIVATE_KEY_FILE"].strip())
        if not private_key_path.is_file():
            raise GitHubConfigurationError("GitHub App private key file is unavailable.")

        return cls(
            app_id=int(raw_app_id),
            app_slug=app_slug,
            private_key_path=private_key_path,
            callback_url=callback_url,
        )


@dataclass
class SessionRecord:
    """Ephemeral browser session state; credentials never leave this object."""

    session_id: str
    csrf_token: str
    created_at: float
    expires_at: float
    pending_states: MutableMapping[str, float] = field(default_factory=dict)
    installation_id: int | None = None
    installation_token: str | None = None
    installation_token_expires_at: float | None = None


class SessionStore:
    """Thread-safe, expiring in-memory sessions for the single local server."""

    def __init__(
        self,
        clock: Callable[[], float] = time.time,
        session_ttl_seconds: int = SESSION_TTL_SECONDS,
    ) -> None:
        self._clock = clock
        self._session_ttl_seconds = session_ttl_seconds
        self._lock = threading.RLock()
        self._sessions: dict[str, SessionRecord] = {}

    def get_or_create(self, session_id: str | None) -> tuple[SessionRecord, bool]:
        with self._lock:
            now = self._clock()
            expired = [
                key for key, value in self._sessions.items() if value.expires_at <= now
            ]
            for key in expired:
                self._sessions.pop(key, None)
            if session_id:
                existing = self._sessions.get(session_id)
                if existing is not None and existing.expires_at > now:
                    return existing, False
                self._sessions.pop(session_id, None)

            created = SessionRecord(
                session_id=secrets.token_urlsafe(32),
                csrf_token=secrets.token_urlsafe(32),
                created_at=now,
                expires_at=now + self._session_ttl_seconds,
            )
            if len(self._sessions) >= MAX_SESSIONS:
                oldest = min(self._sessions, key=lambda key: self._sessions[key].created_at)
                self._sessions.pop(oldest, None)
            self._sessions[created.session_id] = created
            return created, True

    def get(self, session_id: str | None) -> SessionRecord | None:
        if not session_id:
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if session.expires_at <= self._clock():
                self._sessions.pop(session_id, None)
                return None
            return session

    def issue_state(self, session: SessionRecord, ttl_seconds: int = STATE_TTL_SECONDS) -> str:
        with self._lock:
            state = secrets.token_urlsafe(32)
            session.pending_states[state] = self._clock() + ttl_seconds
            return state

    def consume_state(self, session: SessionRecord, state: str) -> None:
        with self._lock:
            expires_at = session.pending_states.pop(state, None)
            if expires_at is None or expires_at <= self._clock():
                raise GitHubServiceError(
                    HTTPStatus.BAD_REQUEST,
                    "GitHub authorization state is invalid or expired.",
                )

    def set_connection(
        self,
        session: SessionRecord,
        installation_id: int,
        installation_token: str,
        token_expires_at: float,
    ) -> None:
        with self._lock:
            session.installation_id = installation_id
            session.installation_token = installation_token
            session.installation_token_expires_at = token_expires_at

    def clear_connection(self, session: SessionRecord) -> None:
        with self._lock:
            session.installation_id = None
            session.installation_token = None
            session.installation_token_expires_at = None
            session.pending_states.clear()

    def rotate_authenticated_session(
        self,
        old_session: SessionRecord,
        installation_id: int,
        installation_token: str,
        token_expires_at: float,
    ) -> SessionRecord:
        with self._lock:
            if self._sessions.get(old_session.session_id) is not old_session:
                raise GitHubServiceError(
                    HTTPStatus.UNAUTHORIZED,
                    "GitHub session is missing or expired.",
                )
            now = self._clock()
            rotated = SessionRecord(
                session_id=secrets.token_urlsafe(32),
                csrf_token=secrets.token_urlsafe(32),
                created_at=now,
                expires_at=now + self._session_ttl_seconds,
                installation_id=installation_id,
                installation_token=installation_token,
                installation_token_expires_at=token_expires_at,
            )
            self._sessions.pop(old_session.session_id, None)
            self._sessions[rotated.session_id] = rotated
            return rotated


@dataclass(frozen=True)
class InstallationToken:
    token: str
    expires_at: float


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _parse_github_timestamp(value: Any, fallback: float) -> float:
    if not isinstance(value, str):
        return fallback
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return fallback
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def validate_repository_component(value: str) -> str:
    """Validate one owner/repository URL component before API path construction."""

    if not value or value in {".", ".."} or "/" in value or "\\" in value:
        raise GitHubServiceError(HTTPStatus.BAD_REQUEST, "Repository identifier is invalid.")
    if not REPOSITORY_COMPONENT.fullmatch(value):
        raise GitHubServiceError(HTTPStatus.BAD_REQUEST, "Repository identifier is invalid.")
    return value


class GitHubClient:
    """Small allowlisted GitHub API client using installation credentials."""

    def __init__(
        self,
        config: GitHubConfig,
        *,
        opener: Callable[..., Any] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self._opener = opener or build_opener(_NoRedirectHandler())
        self._clock = clock
        self._private_key: Any | None = None
        self._private_key_lock = threading.Lock()

    def build_app_jwt(self, now: int | None = None) -> str:
        current = int(self._clock() if now is None else now)
        header = _base64url(_json_bytes({"alg": "RS256", "typ": "JWT"}))
        payload = _base64url(
            _json_bytes(
                {
                    "exp": current + 540,
                    "iat": current - 60,
                    "iss": self.config.app_id,
                }
            )
        )
        signing_input = f"{header}.{payload}".encode("ascii")
        signature = self._load_private_key().sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return f"{header}.{payload}.{_base64url(signature)}"

    def _load_private_key(self) -> Any:
        with self._private_key_lock:
            if self._private_key is None:
                try:
                    key_bytes = self.config.private_key_path.read_bytes()
                    self._private_key = serialization.load_pem_private_key(
                        key_bytes,
                        password=None,
                    )
                except Exception as exc:
                    raise GitHubApiError(None, "GitHub App credentials are unavailable.") from exc
            return self._private_key

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        app_jwt: str | None = None,
        body: bytes | None = None,
        query: Mapping[str, str] | None = None,
    ) -> Any:
        if not path.startswith("/") or "//" in path or ".." in path:
            raise GitHubApiError(None, "GitHub API path was rejected.")
        url = f"{GITHUB_API_ORIGIN}{path}"
        if query:
            url = f"{url}?{urlencode(query)}"
        _validate_api_url(url)
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": GITHUB_USER_AGENT,
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        elif app_jwt is not None:
            headers["Authorization"] = f"Bearer {app_jwt}"
        if body is not None:
            headers["Content-Type"] = "application/json"

        request = Request(url, data=body, headers=headers, method=method)
        try:
            with self._opener(request, timeout=10) as response:
                final_url = response.geturl() if hasattr(response, "geturl") else url
                _validate_api_url(final_url)
                content_length = response.headers.get("Content-Length")
                if content_length is not None and int(content_length) > MAX_GITHUB_RESPONSE_BYTES:
                    raise GitHubApiError(None, "GitHub response exceeded the safe limit.")
                response_body = response.read(MAX_GITHUB_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            response_headers = {
                str(name).lower(): str(value)
                for name, value in (exc.headers.items() if exc.headers else ())
            }
            try:
                exc.close()
            finally:
                raise GitHubApiError(exc.code, headers=response_headers) from None
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            raise GitHubApiError(None) from exc

        if len(response_body) > MAX_GITHUB_RESPONSE_BYTES:
            raise GitHubApiError(None, "GitHub response exceeded the safe limit.")
        try:
            return json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GitHubApiError(None, "GitHub returned an invalid response.") from exc

    def create_installation_token(self, installation_id: int) -> InstallationToken:
        if installation_id <= 0:
            raise GitHubApiError(None, "Installation ID is invalid.")
        payload = self._request_json(
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            app_jwt=self.build_app_jwt(),
            body=b"{}",
        )
        if not isinstance(payload, dict) or not isinstance(payload.get("token"), str):
            raise GitHubApiError(None, "GitHub returned an invalid installation token response.")
        return InstallationToken(
            token=payload["token"],
            expires_at=_parse_github_timestamp(
                payload.get("expires_at"),
                self._clock() + 3600,
            ),
        )

    def list_installation_repositories(self, token: str) -> list[dict[str, Any]]:
        repositories: list[dict[str, Any]] = []
        for page in range(1, MAX_API_PAGES + 1):
            payload = self._request_json(
                "GET",
                "/installation/repositories",
                token=token,
                query={"per_page": "100", "page": str(page)},
            )
            if not isinstance(payload, dict) or not isinstance(payload.get("repositories"), list):
                raise GitHubApiError(None, "GitHub returned an invalid repository response.")
            page_repositories = payload["repositories"]
            for repository in page_repositories:
                if not isinstance(repository, dict):
                    continue
                full_name = repository.get("full_name")
                name = repository.get("name")
                if not isinstance(full_name, str) or not isinstance(name, str):
                    continue
                repositories.append(
                    {
                        "id": repository.get("id"),
                        "name": name,
                        "full_name": full_name,
                        "private": bool(repository.get("private", False)),
                        "default_branch": repository.get("default_branch")
                        if isinstance(repository.get("default_branch"), str)
                        else None,
                    }
                )
                if len(repositories) >= MAX_REPOSITORIES:
                    return repositories[:MAX_REPOSITORIES]
            if len(page_repositories) < 100:
                break
        return repositories

    def list_branches(self, token: str, owner: str, repository: str) -> list[dict[str, Any]]:
        validate_repository_component(owner)
        validate_repository_component(repository)
        branches: list[dict[str, Any]] = []
        for page in range(1, MAX_API_PAGES + 1):
            payload = self._request_json(
                "GET",
                f"/repos/{quote(owner, safe='')}/{quote(repository, safe='')}/branches",
                token=token,
                query={"per_page": "100", "page": str(page)},
            )
            if not isinstance(payload, list):
                raise GitHubApiError(None, "GitHub returned an invalid branch response.")
            for branch in payload:
                if not isinstance(branch, dict) or not isinstance(branch.get("name"), str):
                    continue
                branches.append(
                    {
                        "name": branch["name"],
                        "protected": bool(branch.get("protected", False)),
                    }
                )
                if len(branches) >= MAX_BRANCHES:
                    return branches[:MAX_BRANCHES]
            if len(payload) < 100:
                break
        return branches


class GitHubService:
    """Application-level authorization and installation access service."""

    def __init__(
        self,
        config: GitHubConfig | None,
        *,
        client: Any | None = None,
        sessions: SessionStore | None = None,
        clock: Callable[[], float] = time.time,
        configuration_error: str | None = None,
    ) -> None:
        self.config = config
        self._clock = clock
        self.sessions = sessions or SessionStore(
            clock=clock,
            session_ttl_seconds=config.session_ttl_seconds if config else SESSION_TTL_SECONDS,
        )
        self.client = client if client is not None else (GitHubClient(config, clock=clock) if config else None)
        self.configuration_error = configuration_error

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> GitHubService:
        try:
            config = GitHubConfig.from_environment(environ)
        except GitHubConfigurationError:
            return cls(None, configuration_error="GitHub App integration is not configured correctly.")
        return cls(config)

    @property
    def configured(self) -> bool:
        return self.config is not None and self.client is not None and self.configuration_error is None

    def ensure_session(self, session_id: str | None) -> tuple[SessionRecord, bool]:
        return self.sessions.get_or_create(session_id)

    def existing_session(self, session_id: str | None) -> SessionRecord | None:
        return self.sessions.get(session_id)

    def session_cookie(self, session_id: str) -> str:
        secure = self.config is not None and self.config.callback_url.startswith("https://")
        flags = [
            f"{SESSION_COOKIE_NAME}={session_id}",
            "Path=/",
            f"Max-Age={self.config.session_ttl_seconds if self.config else SESSION_TTL_SECONDS}",
            "HttpOnly",
            "SameSite=Lax",
        ]
        if secure:
            flags.append("Secure")
        return "; ".join(flags)

    def status(self, session_id: str | None) -> dict[str, Any]:
        session = self.sessions.get(session_id)
        return {
            "configured": self.configured,
            "connected": bool(session and session.installation_id is not None),
            "csrf_token": session.csrf_token if session and self.configured else None,
            "message": self.configuration_error
            if not self.configured and self.configuration_error
            else "GitHub App integration is configured.",
        }

    def begin_connect(self, session_id: str) -> str:
        self._require_configured()
        session = self._require_session(session_id)
        state = self.sessions.issue_state(session, self.config.state_ttl_seconds)
        return (
            f"{GITHUB_INSTALL_ORIGIN}/{quote(self.config.app_slug, safe='')}/installations/new?"
            f"{urlencode({'state': state})}"
        )

    def complete_callback(
        self,
        session_id: str,
        state: str,
        installation_id: str,
        setup_action: str,
    ) -> SessionRecord:
        self._require_configured()
        session = self._require_session(session_id)
        if not state or not installation_id or setup_action not in {"install", "update"}:
            raise GitHubServiceError(
                HTTPStatus.BAD_REQUEST,
                "GitHub authorization callback is incomplete.",
            )
        self.sessions.consume_state(session, state)
        try:
            parsed_installation_id = int(installation_id)
        except ValueError as exc:
            raise GitHubServiceError(
                HTTPStatus.BAD_REQUEST,
                "GitHub installation identifier is invalid.",
            ) from exc
        if parsed_installation_id <= 0:
            raise GitHubServiceError(
                HTTPStatus.BAD_REQUEST,
                "GitHub installation identifier is invalid.",
            )

        try:
            token = self.client.create_installation_token(parsed_installation_id)
        except GitHubApiError as exc:
            self.sessions.clear_connection(session)
            raise self._authorization_error(exc) from None
        return self.sessions.rotate_authenticated_session(
            session,
            parsed_installation_id,
            token.token,
            token.expires_at,
        )

    def list_repositories(self, session_id: str) -> list[dict[str, Any]]:
        session = self._require_connected_session(session_id)
        token = self._installation_token(session)
        try:
            return self.client.list_installation_repositories(token)
        except GitHubApiError as exc:
            raise self._handle_api_failure(session, exc) from None

    def list_branches(self, session_id: str, owner: str, repository: str) -> list[dict[str, Any]]:
        owner = validate_repository_component(owner)
        repository = validate_repository_component(repository)
        session = self._require_connected_session(session_id)
        token = self._installation_token(session)
        try:
            repositories = self.client.list_installation_repositories(token)
            full_name = f"{owner}/{repository}".lower()
            if not any(
                isinstance(item.get("full_name"), str)
                and item["full_name"].lower() == full_name
                for item in repositories
            ):
                raise GitHubServiceError(
                    HTTPStatus.NOT_FOUND,
                    "Repository is not accessible to this GitHub installation.",
                )
            return self.client.list_branches(token, owner, repository)
        except GitHubServiceError:
            raise
        except GitHubApiError as exc:
            raise self._handle_api_failure(session, exc) from None

    def disconnect(self, session_id: str, csrf_token: str | None) -> None:
        session = self._require_session(session_id)
        if not csrf_token or not secrets.compare_digest(csrf_token, session.csrf_token):
            raise GitHubServiceError(HTTPStatus.FORBIDDEN, "GitHub disconnect request was rejected.")
        self.sessions.clear_connection(session)

    def _require_configured(self) -> None:
        if not self.configured:
            raise GitHubServiceError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                self.configuration_error or "GitHub App integration is not configured.",
            )

    def _require_session(self, session_id: str) -> SessionRecord:
        session = self.sessions.get(session_id)
        if session is None:
            raise GitHubServiceError(HTTPStatus.UNAUTHORIZED, "GitHub session is missing or expired.")
        return session

    def _require_connected_session(self, session_id: str) -> SessionRecord:
        session = self._require_session(session_id)
        if session.installation_id is None:
            raise GitHubServiceError(HTTPStatus.UNAUTHORIZED, "GitHub authorization is required.")
        return session

    def _installation_token(self, session: SessionRecord) -> str:
        if (
            session.installation_token
            and session.installation_token_expires_at
            and session.installation_token_expires_at > self._clock() + INSTALLATION_TOKEN_SKEW_SECONDS
        ):
            return session.installation_token
        if session.installation_id is None:
            raise GitHubServiceError(HTTPStatus.UNAUTHORIZED, "GitHub authorization is required.")
        try:
            token = self.client.create_installation_token(session.installation_id)
        except GitHubApiError as exc:
            self.sessions.clear_connection(session)
            raise self._authorization_error(exc) from None
        self.sessions.set_connection(session, session.installation_id, token.token, token.expires_at)
        return token.token

    def _authorization_error(self, error: GitHubApiError) -> GitHubServiceError:
        return GitHubServiceError(
            HTTPStatus.UNAUTHORIZED,
            "GitHub authorization expired, was revoked, or could not be completed.",
            clear_connection=True,
        )

    def _handle_api_failure(
        self,
        session: SessionRecord,
        error: GitHubApiError,
    ) -> GitHubServiceError:
        if error.is_rate_limited:
            return GitHubServiceError(
                HTTPStatus.TOO_MANY_REQUESTS,
                "GitHub API rate limit reached; try again later.",
                retry_after=error.retry_after,
            )
        if error.status in {401, 403, 404}:
            self.sessions.clear_connection(session)
            return self._authorization_error(error)
        return GitHubServiceError(
            HTTPStatus.BAD_GATEWAY,
            "GitHub could not complete the repository request.",
        )
