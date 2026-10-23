"""`fnh dashboard`: a local, read-only web view of run reports.

Standard library only. Serves three static files and a small JSON API over
the reports written by `fnh run --report-dir`, plus queued promotion
requests. It never changes anything: promotions are still applied with
`fnh promote`.

Security posture, since reports hold advisory text from external feeds and
describe your infrastructure:
- binds to 127.0.0.1 by default;
- rejects requests whose Host header isn't the address it serves, which
  stops DNS-rebinding pages from reading the API through your browser;
- serves a strict Content-Security-Policy (no inline script, no third-party
  origins), and the page inserts all data as text, never as HTML;
- only allow-listed paths are served; report names are validated.
"""

from __future__ import annotations

import json
import re
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from .promote import FilePromoter
from .report import list_reports, load_report

# Runs the trend chart covers, and runs listed in the picker.
HISTORY_LIMIT = 60
RUNS_LIMIT = 200

_STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}

_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _static(name: str) -> bytes:
    return resources.files("fnh").joinpath("static", name).read_bytes()


class DashboardApp:
    """The data side of the dashboard, independent of HTTP for testing."""

    def __init__(self, report_dir: str | Path, promote_dir: Optional[str | Path] = None):
        self.report_dir = Path(report_dir)
        self.promote_dir = Path(promote_dir) if promote_dir else None

    def runs(self) -> list[dict]:
        """Newest first: name, time and summary of each run."""
        out = []
        for path in reversed(list_reports(self.report_dir)[-RUNS_LIMIT:]):
            report = load_report(self.report_dir, path.name)
            if report:
                out.append({
                    "name": path.name,
                    "generated_at": report.get("generated_at"),
                    "dry_run": report.get("dry_run"),
                    "sources": report.get("sources", []),
                    "summary": report.get("summary", {}),
                })
        return out

    def run(self, name: str) -> Optional[dict]:
        return load_report(self.report_dir, name)

    def history(self) -> list[dict]:
        """Oldest first: the fields the trend chart filters on, per finding."""
        out = []
        for path in list_reports(self.report_dir)[-HISTORY_LIMIT:]:
            report = load_report(self.report_dir, path.name)
            if not report:
                continue
            out.append({
                "name": path.name,
                "generated_at": report.get("generated_at"),
                "findings": [
                    {
                        "status": o.get("status"),
                        "severity": (o.get("advisory") or {}).get("severity"),
                        "source": (o.get("advisory") or {}).get("source"),
                        "environment": (o.get("asset") or {}).get("environment"),
                    }
                    for o in report.get("outcomes", [])
                ],
            })
        return out

    def promotions(self) -> dict:
        if self.promote_dir is None:
            return {"directory": None, "requests": []}
        return {
            "directory": str(self.promote_dir),
            "requests": [r.to_dict() for r in FilePromoter(self.promote_dir).requests()],
        }


def _allowed_hosts(host: str, port: int) -> set[str]:
    names = {host}
    if host in ("127.0.0.1", "localhost", "::1"):
        names |= {"127.0.0.1", "localhost", "[::1]"}
    return {f"{n}:{port}" for n in names}


def make_handler(app: DashboardApp, allowed_hosts: set[str]):
    class Handler(BaseHTTPRequestHandler):
        server_version = "fnh-dashboard"
        sys_version = ""

        def do_GET(self):  # noqa: N802 (http.server naming)
            if self.headers.get("Host", "") not in allowed_hosts:
                return self._send(421, b"misdirected request", "text/plain; charset=utf-8")
            path = urlsplit(self.path).path
            if path in _STATIC:
                name, ctype = _STATIC[path]
                return self._send(200, _static(name), ctype)
            if path == "/api/runs":
                return self._json(app.runs())
            if path == "/api/history":
                return self._json(app.history())
            if path == "/api/promotions":
                return self._json(app.promotions())
            m = re.fullmatch(r"/api/runs/([^/]+)", path)
            if m:
                report = app.run(m.group(1))
                if report is not None:
                    return self._json(report)
            return self._send(404, b"not found", "text/plain; charset=utf-8")

        def do_HEAD(self):  # noqa: N802
            self.send_error(405)

        def _json(self, data) -> None:
            self._send(200, json.dumps(data).encode("utf-8"), "application/json")

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for key, value in _SECURITY_HEADERS.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass  # keep the terminal quiet; errors still surface as responses

    return Handler


def make_server(app: DashboardApp, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(app, set()))
    # Port 0 means "any free port": allow the one actually bound.
    bound_port = server.server_address[1]
    server.RequestHandlerClass = make_handler(app, _allowed_hosts(host, bound_port))
    return server


def serve(report_dir: str | Path, promote_dir: Optional[str | Path] = None,
          host: str = "127.0.0.1", port: int = 8765, open_browser: bool = False) -> None:
    server = make_server(DashboardApp(report_dir, promote_dir), host, port)
    url = f"http://{'localhost' if host == '127.0.0.1' else host}:{server.server_address[1]}/"
    print(f"fnh dashboard: {url}  (reports from {report_dir}; Ctrl-C to stop)")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
