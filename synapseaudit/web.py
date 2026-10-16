"""Safe, loopback-only HTTP server for the SynapseAudit landing page and console.

The server exposes only two repository-owned Compose fixtures. It never accepts
filesystem paths, uploads, shell commands, or Docker operations.
"""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qs, urlsplit

from .analyzer import ComposeConfigError, analyze_file


LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATHS: Mapping[str, Path] = {
    "vulnerable": PROJECT_ROOT / "fixtures" / "compose.vulnerable.yml",
    "remediated": PROJECT_ROOT / "fixtures" / "compose.remediated.yml",
}
STATIC_LANDING = Path(__file__).with_name("static") / "landing.html"
STATIC_DASHBOARD = Path(__file__).with_name("static") / "dashboard.html"


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
        if request.path == "/api/analyze":
            self._serve_analysis(parse_qs(request.query, keep_blank_values=True))
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self._method_not_allowed()

    def _serve_landing(self) -> None:
        self._serve_fixed_html(STATIC_LANDING, "Landing page")

    def _serve_dashboard(self) -> None:
        self._serve_fixed_html(STATIC_DASHBOARD, "Dashboard asset")

    def _serve_fixed_html(self, asset_path: Path, asset_name: str) -> None:
        try:
            content = asset_path.read_bytes()
        except OSError as exc:
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": f"{asset_name} is unavailable: {exc}"},
            )
            return

        self._send_bytes(HTTPStatus.OK, content, "text/html; charset=utf-8")

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

    def _method_not_allowed(self) -> None:
        self._send_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"error": "Only GET requests are supported."},
            headers={"Allow": "GET"},
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
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
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
