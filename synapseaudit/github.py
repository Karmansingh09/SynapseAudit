"""Optional, server-side GitHub App authorization for SynapseAudit.

This module manages GitHub App installation authorization and bounded
repository metadata/blob requests. It never executes repository code or
exposes GitHub credentials to the browser.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import stat
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

from .analyzer import (
    ComposeAnalysisLimitError,
    ComposeAnalysisTimeoutError,
    ComposeAnalysisWorkerError,
    ComposeAnalysisLimits,
    ComposeConfigError,
    analyze_compose_bytes_bounded,
)


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
GIT_SHA = re.compile(r"^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
SUPPORTED_COMPOSE_FILENAMES = frozenset(
    {"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"}
)
MAX_SCAN_SKIPPED_DETAILS = 100
MAX_SCAN_TREE_ENTRIES = 50_000
MAX_SCAN_SUPPORTED_FILES = 100
MAX_SCAN_FILE_BYTES = 8 * 1024 * 1024
MAX_SCAN_TOTAL_BYTES = 64 * 1024 * 1024
MAX_SCAN_DURATION_SECONDS = 300.0
MAX_SCAN_HTTP_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_SCAN_API_PAGES = 50
MAX_SCAN_API_REQUESTS = 200
MAX_SCAN_SKIPPED_DETAILS_HARD = 1_000
MAX_CONCURRENT_SCANS = 16
MAX_ANALYSIS_DURATION_SECONDS = 30.0
MAX_YAML_DEPTH = 256
MAX_YAML_EVENTS = 100_000
MAX_YAML_ALIASES = 1_024
MAX_YAML_SCALAR_CHARS = 8 * 1024 * 1024
MAX_YAML_COLLECTION_ITEMS = 10_000
MAX_COMPOSE_SERVICES = 1_000
MAX_COMPOSE_SERVICE_ITEMS = 10_000


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


class ScanLimitExceeded(Exception):
    """Raised internally when a repository scan reaches a configured budget."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class GitHubRepositoryAccessError(Exception):
    """Raised when an installation cannot access the selected repository."""


class UnsafeRepositoryPathError(ValueError):
    """Raised when a Git tree path is not safe to use as repository metadata."""


def _validate_private_key_file(path: Path) -> None:
    """Validate key-file metadata without opening or reading its contents."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise GitHubConfigurationError("GitHub App private key file is unavailable.") from exc
    mode = stat.S_IMODE(metadata.st_mode)
    if not stat.S_ISREG(metadata.st_mode) or mode & 0o077 or not mode & 0o400:
        raise GitHubConfigurationError(
            "GitHub App private key file must be a readable owner-only regular file."
        )


def parse_trusted_proxies(
    raw: str | Sequence[str | ipaddress.IPv4Network | ipaddress.IPv6Network] | None,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse comma-separated or sequence of IP addresses/CIDRs into IP networks."""

    if raw is None:
        return ()
    if isinstance(raw, str):
        trimmed = raw.strip()
        if not trimmed:
            return ()
        parts = [part.strip() for part in trimmed.split(",")]
    else:
        parts = list(raw)
        if not parts:
            return ()

    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for part in parts:
        if isinstance(part, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            networks.append(part)
            continue
        if not isinstance(part, str) or not part.strip():
            raise ValueError("Trusted proxy configuration contains an empty entry.")
        item = part.strip()
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ValueError(f"Invalid trusted proxy entry '{item}': {exc}") from exc
    return tuple(networks)


def is_trusted_proxy(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    trusted_proxies: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    """Return True if the IP address belongs to any of the trusted proxy networks."""

    return any(ip in network for network in trusted_proxies)


def resolve_client_ip(
    peer_address: str | None,
    forwarded_for_headers: Sequence[str] | str | None,
    trusted_proxies: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> str:
    """Resolve genuine client IP address using explicit trusted proxy boundaries."""

    if not peer_address or not peer_address.strip():
        return "127.0.0.1"

    peer_str = peer_address.strip()
    try:
        peer_ip = ipaddress.ip_address(peer_str)
    except ValueError:
        return peer_str

    canonical_peer = str(peer_ip)

    if not trusted_proxies or not is_trusted_proxy(peer_ip, trusted_proxies):
        return canonical_peer

    if forwarded_for_headers is None:
        return canonical_peer

    if isinstance(forwarded_for_headers, str):
        headers_list = [forwarded_for_headers]
    else:
        headers_list = list(forwarded_for_headers)

    tokens: list[str] = []
    for header in headers_list:
        if not header:
            continue
        for part in header.split(","):
            token = part.strip()
            if not token:
                return canonical_peer
            if token.startswith("[") and token.endswith("]"):
                token = token[1:-1].strip()
            tokens.append(token)

    if not tokens:
        return canonical_peer

    for token in reversed(tokens):
        try:
            token_ip = ipaddress.ip_address(token)
        except ValueError:
            return canonical_peer

        if is_trusted_proxy(token_ip, trusted_proxies):
            continue

        return str(token_ip)

    return canonical_peer


@dataclass(frozen=True)
class ScanLimits:
    """Configurable ceilings for one server-side repository scan."""

    max_tree_entries: int = 10_000
    max_supported_files: int = 20
    max_file_bytes: int = 1 * 1024 * 1024
    max_total_downloaded_bytes: int = 8 * 1024 * 1024
    max_scan_duration_seconds: float = 30.0
    max_http_response_bytes: int = MAX_GITHUB_RESPONSE_BYTES
    max_api_pages: int = MAX_API_PAGES
    max_api_requests: int = 40
    max_skipped_details: int = MAX_SCAN_SKIPPED_DETAILS
    max_concurrent_scans: int = 4
    max_analysis_duration_seconds: float = 5.0
    max_yaml_depth: int = 64
    max_yaml_events: int = 20_000
    max_yaml_aliases: int = 128
    max_yaml_scalar_chars: int = 1 * 1024 * 1024
    max_yaml_collection_items: int = 2_000
    max_compose_services: int = 200
    max_compose_service_items: int = 1_000

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> ScanLimits:
        values = environ if environ is not None else os.environ
        defaults = cls()

        def bounded_int(name: str, default: int, maximum: int) -> int:
            raw = values.get(name, "").strip()
            if not raw:
                return default
            try:
                value = int(raw)
            except ValueError:
                return default
            return min(value, maximum) if value > 0 else default

        def bounded_float(name: str, default: float, maximum: float) -> float:
            raw = values.get(name, "").strip()
            if not raw:
                return default
            try:
                value = float(raw)
            except ValueError:
                return default
            return min(value, maximum) if value > 0 and math.isfinite(value) else default

        return cls(
            max_tree_entries=bounded_int(
                "SYNAPSEAUDIT_SCAN_MAX_TREE_ENTRIES", defaults.max_tree_entries, MAX_SCAN_TREE_ENTRIES
            ),
            max_supported_files=bounded_int(
                "SYNAPSEAUDIT_SCAN_MAX_SUPPORTED_FILES", defaults.max_supported_files, MAX_SCAN_SUPPORTED_FILES
            ),
            max_file_bytes=bounded_int(
                "SYNAPSEAUDIT_SCAN_MAX_FILE_BYTES", defaults.max_file_bytes, MAX_SCAN_FILE_BYTES
            ),
            max_total_downloaded_bytes=bounded_int(
                "SYNAPSEAUDIT_SCAN_MAX_TOTAL_BYTES", defaults.max_total_downloaded_bytes, MAX_SCAN_TOTAL_BYTES
            ),
            max_scan_duration_seconds=bounded_float(
                "SYNAPSEAUDIT_SCAN_MAX_DURATION_SECONDS",
                defaults.max_scan_duration_seconds,
                MAX_SCAN_DURATION_SECONDS,
            ),
            max_http_response_bytes=bounded_int(
                "SYNAPSEAUDIT_SCAN_MAX_HTTP_RESPONSE_BYTES",
                defaults.max_http_response_bytes,
                MAX_SCAN_HTTP_RESPONSE_BYTES,
            ),
            max_api_pages=bounded_int(
                "SYNAPSEAUDIT_SCAN_MAX_API_PAGES", defaults.max_api_pages, MAX_SCAN_API_PAGES
            ),
            max_api_requests=bounded_int(
                "SYNAPSEAUDIT_SCAN_MAX_API_REQUESTS", defaults.max_api_requests, MAX_SCAN_API_REQUESTS
            ),
            max_skipped_details=bounded_int(
                "SYNAPSEAUDIT_SCAN_MAX_SKIPPED_DETAILS", defaults.max_skipped_details, MAX_SCAN_SKIPPED_DETAILS_HARD
            ),
            max_concurrent_scans=bounded_int(
                "SYNAPSEAUDIT_SCAN_MAX_CONCURRENT", defaults.max_concurrent_scans, MAX_CONCURRENT_SCANS
            ),
            max_analysis_duration_seconds=bounded_float(
                "SYNAPSEAUDIT_SCAN_MAX_ANALYSIS_SECONDS",
                defaults.max_analysis_duration_seconds,
                MAX_ANALYSIS_DURATION_SECONDS,
            ),
            max_yaml_depth=bounded_int(
                "SYNAPSEAUDIT_SCAN_MAX_YAML_DEPTH", defaults.max_yaml_depth, MAX_YAML_DEPTH
            ),
            max_yaml_events=bounded_int(
                "SYNAPSEAUDIT_SCAN_MAX_YAML_EVENTS", defaults.max_yaml_events, MAX_YAML_EVENTS
            ),
            max_yaml_aliases=bounded_int(
                "SYNAPSEAUDIT_SCAN_MAX_YAML_ALIASES", defaults.max_yaml_aliases, MAX_YAML_ALIASES
            ),
            max_yaml_scalar_chars=bounded_int(
                "SYNAPSEAUDIT_SCAN_MAX_YAML_SCALAR_CHARS",
                defaults.max_yaml_scalar_chars,
                MAX_YAML_SCALAR_CHARS,
            ),
            max_yaml_collection_items=bounded_int(
                "SYNAPSEAUDIT_SCAN_MAX_YAML_COLLECTION_ITEMS",
                defaults.max_yaml_collection_items,
                MAX_YAML_COLLECTION_ITEMS,
            ),
            max_compose_services=bounded_int(
                "SYNAPSEAUDIT_SCAN_MAX_SERVICES", defaults.max_compose_services, MAX_COMPOSE_SERVICES
            ),
            max_compose_service_items=bounded_int(
                "SYNAPSEAUDIT_SCAN_MAX_SERVICE_ITEMS",
                defaults.max_compose_service_items,
                MAX_COMPOSE_SERVICE_ITEMS,
            ),
        )

    def to_dict(self) -> dict[str, int | float]:
        return {
            "max_tree_entries": self.max_tree_entries,
            "max_supported_files": self.max_supported_files,
            "max_file_bytes": self.max_file_bytes,
            "max_total_downloaded_bytes": self.max_total_downloaded_bytes,
            "max_scan_duration_seconds": self.max_scan_duration_seconds,
            "max_http_response_bytes": self.max_http_response_bytes,
            "max_api_pages": self.max_api_pages,
            "max_api_requests": self.max_api_requests,
            "max_skipped_details": self.max_skipped_details,
            "max_concurrent_scans": self.max_concurrent_scans,
            "max_analysis_duration_seconds": self.max_analysis_duration_seconds,
            "max_yaml_depth": self.max_yaml_depth,
            "max_yaml_events": self.max_yaml_events,
            "max_yaml_aliases": self.max_yaml_aliases,
            "max_yaml_scalar_chars": self.max_yaml_scalar_chars,
            "max_yaml_collection_items": self.max_yaml_collection_items,
            "max_compose_services": self.max_compose_services,
            "max_compose_service_items": self.max_compose_service_items,
        }

    def compose_analysis_limits(self) -> ComposeAnalysisLimits:
        return ComposeAnalysisLimits(
            max_input_bytes=self.max_file_bytes,
            max_yaml_depth=self.max_yaml_depth,
            max_yaml_events=self.max_yaml_events,
            max_yaml_aliases=self.max_yaml_aliases,
            max_yaml_scalar_chars=self.max_yaml_scalar_chars,
            max_yaml_collection_items=self.max_yaml_collection_items,
            max_services=self.max_compose_services,
            max_service_items=self.max_compose_service_items,
            max_duration_seconds=self.max_analysis_duration_seconds,
        )


class ScanBudget:
    """One shared budget spanning authorization, fetching, and analysis."""

    def __init__(
        self,
        limits: ScanLimits,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limits = limits
        self._clock = clock
        self.started_at = clock()
        self.requests_used = 0
        self.pages_used = 0
        self.downloaded_bytes = 0

    def check_time(self) -> None:
        if self._clock() - self.started_at >= self.limits.max_scan_duration_seconds:
            raise ScanLimitExceeded("maximum scan duration exceeded")

    def before_request(self, *, page: bool = False) -> None:
        self.check_time()
        if self.requests_used >= self.limits.max_api_requests:
            raise ScanLimitExceeded("maximum API requests exceeded")
        if page and self.pages_used >= self.limits.max_api_pages:
            raise ScanLimitExceeded("maximum API pages exceeded")
        self.requests_used += 1
        if page:
            self.pages_used += 1

    def remaining_downloaded_bytes(self) -> int:
        return max(0, self.limits.max_total_downloaded_bytes - self.downloaded_bytes)

    def remaining_seconds(self) -> float:
        return max(0.0, self.limits.max_scan_duration_seconds - (self._clock() - self.started_at))

    def record_response(self, size: int) -> None:
        if size < 0 or self.downloaded_bytes + size > self.limits.max_total_downloaded_bytes:
            raise ScanLimitExceeded("maximum total downloaded bytes exceeded")
        self.downloaded_bytes += size
        self.check_time()

    def usage(self) -> dict[str, int | float]:
        return {
            "api_requests": self.requests_used,
            "api_pages": self.pages_used,
            "downloaded_bytes": self.downloaded_bytes,
            "elapsed_seconds": round(max(0.0, self._clock() - self.started_at), 6),
        }


class ScanAdmission:
    """Non-queued global and per-session scan admission control."""

    def __init__(self, max_concurrent: int) -> None:
        self._global = threading.BoundedSemaphore(max_concurrent)
        self._lock = threading.Lock()
        self._active_sessions: set[str] = set()

    def acquire(self, session_id: str) -> bool:
        with self._lock:
            if session_id in self._active_sessions or not self._global.acquire(blocking=False):
                return False
            self._active_sessions.add(session_id)
            return True

    def release(self, session_id: str) -> None:
        with self._lock:
            if session_id not in self._active_sessions:
                return
            self._active_sessions.remove(session_id)
            self._global.release()


@dataclass(frozen=True)
class RepositoryFileResult:
    path: str
    blob_sha: str
    size_bytes: int
    report: dict[str, Any]


@dataclass(frozen=True)
class SkippedRepositoryFile:
    path: str | None
    reason: str


@dataclass(frozen=True)
class RepositoryScanResult:
    repository: str
    branch: str
    commit_sha: str | None
    status: str
    files: tuple[RepositoryFileResult, ...]
    skipped: tuple[SkippedRepositoryFile, ...]
    skipped_counts: dict[str, int]
    limited_reasons: tuple[str, ...]
    limits: dict[str, int | float]
    usage: dict[str, int | float]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": "github_repository",
            "repository": self.repository,
            "branch": self.branch,
            "commit_sha": self.commit_sha,
            "analysis_scope": {
                "supported_filenames": sorted(SUPPORTED_COMPOSE_FILENAMES),
                "rules": [
                    "PRIVILEGED_CONTAINER",
                    "WRITABLE_HOST_BIND",
                    "DANGEROUS_CAPABILITY",
                    "EXPOSED_SERVICE_PORT",
                ],
                "repository_code_executed": False,
            },
            "status": self.status,
            "complete": self.status == "complete",
            "limited": self.status == "limited",
            "files": [
                {
                    "path": file_result.path,
                    "blob_sha": file_result.blob_sha,
                    "size_bytes": file_result.size_bytes,
                    "report": file_result.report,
                }
                for file_result in self.files
            ],
            "skipped": [
                {"path": skipped.path, "reason": skipped.reason} for skipped in self.skipped
            ],
            "skipped_counts": self.skipped_counts,
            "limited_reasons": list(self.limited_reasons),
            "limits": self.limits,
            "usage": self.usage,
        }


class _ScanAccumulator:
    def __init__(
        self,
        repository: str,
        branch: str,
        limits: ScanLimits,
        budget: ScanBudget,
    ) -> None:
        self.repository = repository
        self.branch = branch
        self.limits = limits
        self.budget = budget
        self.commit_sha: str | None = None
        self.files: list[RepositoryFileResult] = []
        self.skipped: list[SkippedRepositoryFile] = []
        self.skipped_counts: dict[str, int] = {}
        self.limited_reasons: list[str] = []

    def add_skipped(self, path: str | None, reason: str) -> None:
        self.skipped_counts[reason] = self.skipped_counts.get(reason, 0) + 1
        if len(self.skipped) < self.limits.max_skipped_details:
            self.skipped.append(SkippedRepositoryFile(path, reason))

    def mark_limited(self, reason: str) -> None:
        if reason not in self.limited_reasons:
            self.limited_reasons.append(reason)

    def finish(self) -> RepositoryScanResult:
        status = "limited" if self.limited_reasons else "complete"
        if not self.files and not self.limited_reasons:
            status = "no_supported_files"
        return RepositoryScanResult(
            repository=self.repository,
            branch=self.branch,
            commit_sha=self.commit_sha,
            status=status,
            files=tuple(self.files),
            skipped=tuple(self.skipped),
            skipped_counts=dict(self.skipped_counts),
            limited_reasons=tuple(self.limited_reasons),
            limits=self.limits.to_dict(),
            usage=self.budget.usage(),
        )


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
    dashboard_password: str | None = None
    trusted_proxies: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    session_ttl_seconds: int = SESSION_TTL_SECONDS
    state_ttl_seconds: int = STATE_TTL_SECONDS

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> GitHubConfig | None:
        values = environ if environ is not None else os.environ
        raw_trusted_proxies = values.get("SYNAPSEAUDIT_TRUSTED_PROXIES", "").strip()
        try:
            trusted_proxies = parse_trusted_proxies(raw_trusted_proxies)
        except ValueError as exc:
            raise GitHubConfigurationError(str(exc)) from exc

        names = (
            "SYNAPSEAUDIT_GITHUB_APP_ID",
            "SYNAPSEAUDIT_GITHUB_APP_SLUG",
            "SYNAPSEAUDIT_GITHUB_PRIVATE_KEY_FILE",
            "SYNAPSEAUDIT_GITHUB_CALLBACK_URL",
        )
        configured = [bool(values.get(name, "").strip()) for name in names]
        if not any(configured):
            return None
        missing = [name for name, present in zip(names, configured) if not present]
        dashboard_password = values.get("SYNAPSEAUDIT_DASHBOARD_PASSWORD", "").strip()
        if not dashboard_password:
            missing.append("SYNAPSEAUDIT_DASHBOARD_PASSWORD")
        if missing:
            raise GitHubConfigurationError(
                "GitHub App integration is incomplete; missing: " + ", ".join(missing)
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
            or callback.path != "/api/github/callback"
            or callback.username is not None
            or callback.password is not None
            or callback.fragment
        ):
            raise GitHubConfigurationError(
                "GitHub callback URL must use HTTPS and the exact /api/github/callback path."
            )

        private_key_path = Path(values["SYNAPSEAUDIT_GITHUB_PRIVATE_KEY_FILE"].strip())
        _validate_private_key_file(private_key_path)

        return cls(
            app_id=int(raw_app_id),
            app_slug=app_slug,
            private_key_path=private_key_path,
            callback_url=callback_url,
            dashboard_password=dashboard_password,
            trusted_proxies=trusted_proxies,
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


def validate_branch_name(value: str) -> str:
    """Validate a branch name before encoding it into an API path."""

    if (
        not isinstance(value, str)
        or not value
        or len(value) > 255
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or "\\" in value
        or any(ord(character) < 32 or character.isspace() for character in value)
        or any(component in {"", ".", ".."} for component in value.split("/"))
        or any(character in value for character in ("~", "^", ":", "?", "*", "["))
    ):
        raise GitHubServiceError(HTTPStatus.BAD_REQUEST, "Branch identifier is invalid.")
    return value


def _validate_git_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not GIT_SHA.fullmatch(value):
        raise GitHubApiError(None, f"GitHub returned an invalid {label}.")
    return value.lower()


def _validate_tree_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(component in {"", ".", ".."} for component in value.split("/"))
    ):
        raise UnsafeRepositoryPathError("repository path is unsafe")
    if any(ord(character) < 32 for character in value):
        raise UnsafeRepositoryPathError("repository path is unsafe")
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
        budget: ScanBudget | None = None,
        page_request: bool = False,
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
        if budget is not None:
            budget.before_request(page=page_request)
        response_limit = budget.limits.max_http_response_bytes if budget else MAX_GITHUB_RESPONSE_BYTES
        timeout = min(10.0, budget.remaining_seconds()) if budget else 10.0
        if timeout <= 0:
            raise ScanLimitExceeded("maximum scan duration exceeded")
        try:
            with self._opener(request, timeout=timeout) as response:
                final_url = response.geturl() if hasattr(response, "geturl") else url
                _validate_api_url(final_url)
                content_length = response.headers.get("Content-Length")
                if content_length is not None and int(content_length) > response_limit:
                    if budget is not None:
                        raise ScanLimitExceeded("maximum HTTP response body size exceeded")
                    raise GitHubApiError(None, "GitHub response exceeded the safe limit.")
                remaining = budget.remaining_downloaded_bytes() if budget else response_limit
                if remaining <= 0 and budget is not None:
                    raise ScanLimitExceeded("maximum total downloaded bytes exceeded")
                read_limit = min(response_limit, remaining) + 1
                response_body = response.read(read_limit)
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
            if budget is not None:
                try:
                    budget.check_time()
                except ScanLimitExceeded:
                    raise
            raise GitHubApiError(None) from exc

        if len(response_body) > response_limit:
            if budget is not None:
                raise ScanLimitExceeded("maximum HTTP response body size exceeded")
            raise GitHubApiError(None, "GitHub response exceeded the safe limit.")
        if budget is not None:
            if len(response_body) > budget.remaining_downloaded_bytes():
                raise ScanLimitExceeded("maximum total downloaded bytes exceeded")
            budget.record_response(len(response_body))
        try:
            return json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GitHubApiError(None, "GitHub returned an invalid response.") from exc

    def revoke_installation_token(self, token: str) -> bool:
        """Revoke an installation access token upstream on GitHub (DELETE /installation/token)."""
        if not token or not token.strip():
            return False
        url = f"{GITHUB_API_ORIGIN}/installation/token"
        _validate_api_url(url)
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token.strip()}",
            "User-Agent": GITHUB_USER_AGENT,
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        request = Request(url, headers=headers, method="DELETE")
        try:
            with self._opener(request, timeout=5.0) as response:
                status = getattr(response, "status", getattr(response, "code", None))
                return status in (HTTPStatus.NO_CONTENT, HTTPStatus.OK)
        except Exception:
            return False

    def create_installation_token(
        self,
        installation_id: int,
        *,
        budget: ScanBudget | None = None,
    ) -> InstallationToken:
        if installation_id <= 0:
            raise GitHubApiError(None, "Installation ID is invalid.")
        payload = self._request_json(
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            app_jwt=self.build_app_jwt(),
            body=b"{}",
            budget=budget,
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

    def list_installation_repositories(
        self,
        token: str,
        *,
        budget: ScanBudget | None = None,
    ) -> list[dict[str, Any]]:
        repositories: list[dict[str, Any]] = []
        for page in range(1, MAX_API_PAGES + 1):
            payload = self._request_json(
                "GET",
                "/installation/repositories",
                token=token,
                query={"per_page": "100", "page": str(page)},
                budget=budget,
                page_request=budget is not None,
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

    def resolve_branch_commit(
        self,
        token: str,
        owner: str,
        repository: str,
        branch: str,
        *,
        budget: ScanBudget,
    ) -> str:
        validate_repository_component(owner)
        validate_repository_component(repository)
        validate_branch_name(branch)
        payload = self._request_json(
            "GET",
            f"/repos/{quote(owner, safe='')}/{quote(repository, safe='')}/branches/{quote(branch, safe='')}",
            token=token,
            budget=budget,
        )
        if not isinstance(payload, dict) or not isinstance(payload.get("commit"), dict):
            raise GitHubApiError(None, "GitHub returned an invalid branch response.")
        return _validate_git_sha(payload["commit"].get("sha"), "branch commit SHA")

    def fetch_repository_tree(
        self,
        token: str,
        owner: str,
        repository: str,
        commit_sha: str,
        *,
        budget: ScanBudget,
    ) -> dict[str, Any]:
        validate_repository_component(owner)
        validate_repository_component(repository)
        commit_sha = _validate_git_sha(commit_sha, "commit SHA")
        commit_payload = self._request_json(
            "GET",
            f"/repos/{quote(owner, safe='')}/{quote(repository, safe='')}/git/commits/{commit_sha}",
            token=token,
            budget=budget,
        )
        if (
            not isinstance(commit_payload, dict)
            or commit_payload.get("sha") != commit_sha
            or not isinstance(commit_payload.get("tree"), dict)
        ):
            raise GitHubApiError(None, "GitHub returned an invalid commit response.")
        tree_sha = _validate_git_sha(commit_payload["tree"].get("sha"), "tree SHA")
        payload = self._request_json(
            "GET",
            f"/repos/{quote(owner, safe='')}/{quote(repository, safe='')}/git/trees/{tree_sha}",
            token=token,
            query={"recursive": "1"},
            budget=budget,
        )
        if (
            not isinstance(payload, dict)
            or payload.get("sha") != tree_sha
            or not isinstance(payload.get("tree"), list)
        ):
            raise GitHubApiError(None, "GitHub returned an invalid repository tree.")
        if not isinstance(payload.get("truncated", False), bool):
            raise GitHubApiError(None, "GitHub returned an invalid repository tree.")
        return payload

    def fetch_repository_blob(
        self,
        token: str,
        owner: str,
        repository: str,
        blob_sha: str,
        *,
        budget: ScanBudget,
    ) -> bytes:
        validate_repository_component(owner)
        validate_repository_component(repository)
        blob_sha = _validate_git_sha(blob_sha, "blob SHA")
        payload = self._request_json(
            "GET",
            f"/repos/{quote(owner, safe='')}/{quote(repository, safe='')}/git/blobs/{blob_sha}",
            token=token,
            budget=budget,
        )
        if not isinstance(payload, dict) or payload.get("encoding") != "base64":
            raise GitHubApiError(None, "GitHub returned an invalid repository blob.")
        response_sha = _validate_git_sha(payload.get("sha"), "blob SHA")
        if response_sha != blob_sha:
            raise GitHubApiError(None, "GitHub returned a mismatched repository blob.")
        content = payload.get("content")
        if not isinstance(content, str):
            raise GitHubApiError(None, "GitHub returned an invalid repository blob.")
        declared_size = payload.get("size")
        if declared_size is not None and (
            isinstance(declared_size, bool)
            or not isinstance(declared_size, int)
            or declared_size < 0
        ):
            raise GitHubApiError(None, "GitHub returned an invalid repository blob.")
        if declared_size is not None and declared_size > budget.limits.max_file_bytes:
            raise ScanLimitExceeded("maximum individual file size exceeded")
        try:
            decoded = base64.b64decode("".join(content.split()), validate=True)
        except (ValueError, TypeError) as exc:
            raise GitHubApiError(None, "GitHub returned an invalid repository blob.") from exc
        if declared_size is not None and declared_size != len(decoded):
            raise GitHubApiError(None, "GitHub returned an invalid repository blob.")
        if len(decoded) > budget.limits.max_file_bytes:
            raise ScanLimitExceeded("maximum individual file size exceeded")
        object_header = f"blob {len(decoded)}\0".encode("ascii")
        digest = hashlib.sha1(object_header + decoded).hexdigest()
        if len(blob_sha) == 64:
            digest = hashlib.sha256(object_header + decoded).hexdigest()
        if digest != blob_sha:
            raise GitHubApiError(None, "GitHub returned invalid repository blob content.")
        return decoded

    def scan_repository(
        self,
        token: str,
        owner: str,
        repository: str,
        branch: str,
        *,
        limits: ScanLimits,
        budget: ScanBudget | None = None,
    ) -> RepositoryScanResult:
        validate_repository_component(owner)
        validate_repository_component(repository)
        validate_branch_name(branch)
        budget = budget or ScanBudget(limits)
        full_name = f"{owner}/{repository}"
        normalized_full_name = full_name.lower()
        accumulator = _ScanAccumulator(full_name, branch, limits, budget)

        try:
            repositories = self.list_installation_repositories(token, budget=budget)
            if not any(
                isinstance(item.get("full_name"), str)
                and item["full_name"].lower() == normalized_full_name
                for item in repositories
            ):
                raise GitHubRepositoryAccessError

            commit_sha = self.resolve_branch_commit(
                token, owner, repository, branch, budget=budget
            )
            accumulator.commit_sha = commit_sha
            tree_payload = self.fetch_repository_tree(
                token, owner, repository, commit_sha, budget=budget
            )
            if tree_payload.get("truncated"):
                accumulator.mark_limited("GitHub tree was truncated")

            tree_entries = tree_payload["tree"]
            if len(tree_entries) > limits.max_tree_entries:
                accumulator.mark_limited("maximum repository tree entries exceeded")
                tree_entries = tree_entries[: limits.max_tree_entries]

            candidates: list[tuple[str, str]] = []
            for entry in tree_entries:
                budget.check_time()
                if not isinstance(entry, dict):
                    accumulator.add_skipped(None, "tree entry was not a mapping")
                    continue
                raw_path = entry.get("path")
                try:
                    path = _validate_tree_path(raw_path)
                except UnsafeRepositoryPathError:
                    accumulator.add_skipped(
                        raw_path if isinstance(raw_path, str) else None,
                        "repository path is unsafe",
                    )
                    continue
                if entry.get("type") != "blob":
                    accumulator.add_skipped(
                        path,
                        "tree entry is not a blob; symlinks and submodules are not fetched",
                    )
                    continue
                if entry.get("mode") == "120000":
                    accumulator.add_skipped(path, "symlink entries are not fetched")
                    continue
                if path.rsplit("/", 1)[-1] not in SUPPORTED_COMPOSE_FILENAMES:
                    accumulator.add_skipped(
                        path,
                        "filename is outside the supported Compose scope",
                    )
                    continue
                if len(candidates) >= limits.max_supported_files:
                    accumulator.mark_limited("maximum supported files per scan exceeded")
                    accumulator.add_skipped(
                        path,
                        "maximum supported files per scan exceeded",
                    )
                    continue
                try:
                    blob_sha = _validate_git_sha(entry.get("sha"), "blob SHA")
                except GitHubApiError:
                    accumulator.add_skipped(path, "supported blob has an invalid object SHA")
                    continue
                declared_size = entry.get("size")
                if declared_size is not None and (
                    isinstance(declared_size, bool)
                    or not isinstance(declared_size, int)
                    or declared_size < 0
                ):
                    accumulator.add_skipped(path, "supported blob has an invalid size")
                    continue
                if declared_size is not None and declared_size > limits.max_file_bytes:
                    accumulator.mark_limited("maximum individual file size exceeded")
                    accumulator.add_skipped(path, "maximum individual file size exceeded")
                    continue
                candidates.append((path, blob_sha))

            for path, blob_sha in candidates:
                try:
                    content = self.fetch_repository_blob(
                        token, owner, repository, blob_sha, budget=budget
                    )
                    analysis_timeout = min(
                        limits.max_analysis_duration_seconds,
                        budget.remaining_seconds(),
                    )
                    report = analyze_compose_bytes_bounded(
                        content,
                        source_file=path,
                        limits=limits.compose_analysis_limits(),
                        timeout_seconds=analysis_timeout,
                    ).to_dict()
                    budget.check_time()
                except ScanLimitExceeded as exc:
                    accumulator.mark_limited(exc.reason)
                    accumulator.add_skipped(path, exc.reason)
                    break
                except ComposeAnalysisTimeoutError:
                    accumulator.mark_limited("Compose analysis deadline exceeded")
                    accumulator.add_skipped(path, "Compose analysis deadline exceeded")
                    continue
                except ComposeAnalysisLimitError as exc:
                    accumulator.mark_limited(str(exc))
                    accumulator.add_skipped(path, str(exc))
                    continue
                except ComposeAnalysisWorkerError:
                    accumulator.mark_limited("Compose analysis worker failed")
                    accumulator.add_skipped(path, "Compose analysis worker failed")
                    continue
                except ComposeConfigError:
                    accumulator.add_skipped(
                        path,
                        "file is not valid supported Compose YAML",
                    )
                    continue
                except GitHubApiError as exc:
                    if exc.status == HTTPStatus.NOT_FOUND:
                        accumulator.add_skipped(path, "repository blob was unavailable")
                        continue
                    raise
                accumulator.files.append(
                    RepositoryFileResult(
                        path=path,
                        blob_sha=blob_sha,
                        size_bytes=len(content),
                        report=report,
                    )
                )
        except ScanLimitExceeded as exc:
            accumulator.mark_limited(exc.reason)

        return accumulator.finish()


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
        scan_limits: ScanLimits | None = None,
        scan_admission: ScanAdmission | None = None,
    ) -> None:
        self.config = config
        self._clock = clock
        self.sessions = sessions or SessionStore(
            clock=clock,
            session_ttl_seconds=config.session_ttl_seconds if config else SESSION_TTL_SECONDS,
        )
        self.client = client if client is not None else (GitHubClient(config, clock=clock) if config else None)
        self.configuration_error = configuration_error
        self.scan_limits = scan_limits or ScanLimits.from_environment()
        self.scan_admission = scan_admission or ScanAdmission(self.scan_limits.max_concurrent_scans)

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> GitHubService:
        try:
            config = GitHubConfig.from_environment(environ)
        except GitHubConfigurationError:
            return cls(
                None,
                configuration_error="GitHub App integration is not configured correctly.",
                scan_limits=ScanLimits.from_environment(environ),
            )
        return cls(config, scan_limits=ScanLimits.from_environment(environ))

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
        *,
        error: str | None = None,
    ) -> SessionRecord:
        self._require_configured()
        session = self._require_session(session_id)
        if not state:
            raise GitHubServiceError(
                HTTPStatus.BAD_REQUEST,
                "GitHub authorization callback is incomplete.",
            )
        self.sessions.consume_state(session, state)
        if error:
            raise GitHubServiceError(
                HTTPStatus.BAD_REQUEST,
                "GitHub authorization was denied or canceled.",
            )
        if setup_action == "request":
            raise GitHubServiceError(
                HTTPStatus.BAD_REQUEST,
                "GitHub App installation request submitted for administrator approval.",
            )
        if not installation_id or setup_action not in {"install", "update"}:
            raise GitHubServiceError(
                HTTPStatus.BAD_REQUEST,
                "GitHub authorization callback is incomplete.",
            )
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

    def scan_repository(
        self,
        session_id: str,
        owner: str,
        repository: str,
        branch: str,
        csrf_token: str | None,
    ) -> dict[str, Any]:
        session = self._require_connected_session(session_id)
        if not csrf_token or not secrets.compare_digest(csrf_token, session.csrf_token):
            raise GitHubServiceError(HTTPStatus.FORBIDDEN, "GitHub scan request was rejected.")
        owner = validate_repository_component(owner)
        repository = validate_repository_component(repository)
        branch = validate_branch_name(branch)
        if not self.scan_admission.acquire(session_id):
            raise GitHubServiceError(
                HTTPStatus.TOO_MANY_REQUESTS,
                "Another bounded GitHub scan is already active; try again later.",
                retry_after=1,
            )
        budget = ScanBudget(self.scan_limits)
        try:
            token = self._installation_token(session, budget=budget)
            result = self.client.scan_repository(
                token,
                owner,
                repository,
                branch,
                limits=self.scan_limits,
                budget=budget,
            )
        except ScanLimitExceeded as exc:
            result = RepositoryScanResult(
                repository=f"{owner}/{repository}",
                branch=branch,
                commit_sha=None,
                status="limited",
                files=(),
                skipped=(SkippedRepositoryFile(None, exc.reason),),
                skipped_counts={exc.reason: 1},
                limited_reasons=(exc.reason,),
                limits=self.scan_limits.to_dict(),
                usage=budget.usage(),
            )
        except GitHubRepositoryAccessError:
            raise GitHubServiceError(
                HTTPStatus.NOT_FOUND,
                "Repository is not accessible to this GitHub installation.",
            ) from None
        except GitHubApiError as exc:
            if exc.status == HTTPStatus.NOT_FOUND:
                raise GitHubServiceError(
                    HTTPStatus.NOT_FOUND,
                    "The selected repository or branch is no longer available.",
                ) from None
            raise self._handle_api_failure(session, exc) from None
        finally:
            self.scan_admission.release(session_id)
        return result.to_dict()

    def disconnect(self, session_id: str, csrf_token: str | None) -> None:
        session = self._require_session(session_id)
        if not csrf_token or not secrets.compare_digest(csrf_token, session.csrf_token):
            raise GitHubServiceError(HTTPStatus.FORBIDDEN, "GitHub disconnect request was rejected.")
        token_to_revoke = session.installation_token
        try:
            if token_to_revoke and self.configured:
                self.client.revoke_installation_token(token_to_revoke)
        except Exception:
            pass
        finally:
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

    def _installation_token(
        self,
        session: SessionRecord,
        *,
        budget: ScanBudget | None = None,
    ) -> str:
        if (
            session.installation_token
            and session.installation_token_expires_at
            and session.installation_token_expires_at > self._clock() + INSTALLATION_TOKEN_SKEW_SECONDS
        ):
            return session.installation_token
        if session.installation_id is None:
            raise GitHubServiceError(HTTPStatus.UNAUTHORIZED, "GitHub authorization is required.")
        try:
            if budget is None:
                token = self.client.create_installation_token(session.installation_id)
            else:
                token = self.client.create_installation_token(
                    session.installation_id,
                    budget=budget,
                )
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
