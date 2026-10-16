"""Safe, loopback-only HTTP server for the SynapseAudit landing page and console.

The server exposes only two repository-owned Compose fixtures. It never accepts
filesystem paths, uploads, shell commands, or Docker operations.
"""

from __future__ import annotations

import argparse
import json
from email import policy
from email.message import Message
from email.parser import BytesParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qs, urlsplit

from .analyzer import ComposeConfigError, analyze_compose_bytes, analyze_file


LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
UPLOAD_ENDPOINT = "/api/analyze-upload"
UPLOAD_FIELD_NAME = "compose_file"
MAX_UPLOAD_BYTES = 1 * 1024 * 1024
MAX_UPLOAD_REQUEST_BYTES = MAX_UPLOAD_BYTES + (64 * 1024)
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


class DashboardHandler(BaseHTTPRequestHandler):
    """Serve fixed local pages and the read-only fixture analysis endpoint."""

    server_version = "SynapseAuditDashboard/0.1"

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        request = urlsplit(self.path)
        if request.path == "/":
            self._serve_landing()
            return
        if request.path == "/console":
            self._serve_dashboard()
            return
        if request.path == "/static/dashboard.js":
            self._serve_dashboard_script()
            return
        if request.path == UPLOAD_ENDPOINT:
            self._upload_method_not_allowed()
            return
        if request.path == "/api/analyze":
            self._serve_analysis(parse_qs(request.query, keep_blank_values=True))
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if urlsplit(self.path).path == UPLOAD_ENDPOINT:
            self._serve_upload()
            return
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if urlsplit(self.path).path == UPLOAD_ENDPOINT:
            self._upload_method_not_allowed()
            return
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if urlsplit(self.path).path == UPLOAD_ENDPOINT:
            self._upload_method_not_allowed()
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

        print(f"[dashboard] {format % args}")


class DashboardServer(ThreadingHTTPServer):
    """HTTP server configured for short-lived local dashboard requests."""

    daemon_threads = True
    allow_reuse_address = True


def create_server(port: int = DEFAULT_PORT) -> DashboardServer:
    """Create a server bound only to loopback; port 0 requests an ephemeral port."""

    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise ValueError("port must be an integer from 0 through 65535")
    return DashboardServer((LOOPBACK_HOST, port), DashboardHandler)


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        server = create_server(args.port)
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
