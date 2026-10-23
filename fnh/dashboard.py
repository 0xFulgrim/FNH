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

import ipaddress
import json
import re
import socket
import threading
import webbrowser
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import urlsplit

from .promote import FilePromoter
from .report import REPORT_NAME, list_reports, load_report

# Runs the trend chart covers, and runs listed in the picker.
HISTORY_LIMIT = 60
RUNS_LIMIT = 200

_STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/logo.svg": ("logo.svg", "image/svg+xml"),
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
    """The data side of the dashboard, independent of HTTP for testing.

    Reports are immutable once written, so each is parsed once: a poll only
    stats the directory and parses files it hasn't seen (or that changed).
    """

    # Full reports kept for /api/runs/<name>; the summaries are kept for all.
    _FULL_CACHE = 4

    def __init__(self, report_dir: str | Path, promote_dir: Optional[str | Path] = None):
        self.report_dir = Path(report_dir)
        self.promote_dir = Path(promote_dir) if promote_dir else None
        self._lock = threading.Lock()
        # name -> (stat key, summary row, compact findings)
        self._index: dict[str, tuple[tuple, dict, list]] = {}
        self._full: "OrderedDict[str, tuple[tuple, dict]]" = OrderedDict()

    def _entries(self, limit: int) -> list[tuple[dict, list]]:
        """(summary row, compact findings) for the newest `limit` reports,
        oldest first."""
        all_paths = list_reports(self.report_dir)
        paths = all_paths[-limit:]
        out = []
        with self._lock:
            for path in paths:
                try:
                    st = path.stat()
                except OSError:
                    continue
                key = (st.st_mtime_ns, st.st_size)
                cached = self._index.get(path.name)
                if cached is None or cached[0] != key:
                    report = load_report(self.report_dir, path.name)
                    if not report:
                        continue
                    cached = (key, _summary_row(path.name, report), _compact_findings(report))
                    self._index[path.name] = cached
                out.append((cached[1], cached[2]))
            # Forget reports deleted from disk (not ones outside this window).
            if len(self._index) > len(all_paths):
                live = {p.name for p in all_paths}
                for name in [n for n in self._index if n not in live]:
                    del self._index[name]
        return out

    def runs(self) -> list[dict]:
        """Newest first: name, time and summary of each run."""
        return [row for row, _ in reversed(self._entries(RUNS_LIMIT))]

    def run(self, name: str) -> Optional[dict]:
        if not REPORT_NAME.fullmatch(name):
            return None
        path = self.report_dir / name
        try:
            st = path.stat()
        except OSError:
            return None
        key = (st.st_mtime_ns, st.st_size)
        with self._lock:
            hit = self._full.get(name)
            if hit and hit[0] == key:
                self._full.move_to_end(name)
                return hit[1]
        report = load_report(self.report_dir, name)
        if report is not None:
            with self._lock:
                self._full[name] = (key, report)
                while len(self._full) > self._FULL_CACHE:
                    self._full.popitem(last=False)
        return report

    def history(self) -> list[dict]:
        """Oldest first: the fields the trend chart filters on, per finding."""
        return [{"name": row["name"], "generated_at": row["generated_at"], "findings": findings}
                for row, findings in self._entries(HISTORY_LIMIT)]

    def promotions(self) -> dict:
        if self.promote_dir is None:
            return {"directory": None, "requests": []}
        return {
            "directory": str(self.promote_dir),
            "requests": [r.to_dict() for r in FilePromoter(self.promote_dir).requests()],
        }


def _summary_row(name: str, report: dict) -> dict:
    return {
        "name": name,
        "generated_at": report.get("generated_at"),
        "dry_run": report.get("dry_run"),
        "sources": report.get("sources", []),
        "summary": report.get("summary", {}),
    }


def _compact_findings(report: dict) -> list[dict]:
    return [
        {
            "status": o.get("status"),
            "severity": (o.get("advisory") or {}).get("severity"),
            "source": (o.get("advisory") or {}).get("source"),
            "environment": (o.get("asset") or {}).get("environment"),
        }
        for o in report.get("outcomes", [])
    ]


class HostCheck:
    """Accept a request only if its Host header names this server.

    DNS rebinding works by pointing an attacker's *domain name* at our
    address, so IP-literal hosts are always safe to accept. Names are limited
    to localhost, this machine's own names and any the operator allows.
    """

    def __init__(self, port: int, bind_host: str, extra_names: Iterable[str] = ()):
        self.port = port
        self.names = {"localhost", socket.gethostname().lower(), socket.getfqdn().lower()}
        self.names |= {n.lower() for n in extra_names}
        if not _is_ip(bind_host):
            self.names.add(bind_host.lower())

    def __call__(self, header: str) -> bool:
        host, sep, port = header.rpartition(":")
        if not sep or not port.isdigit() or int(port) != self.port:
            return False
        host = host.lower()
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        return _is_ip(host) or host in self.names


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return True


def make_handler(app: DashboardApp, host_ok: Callable[[str], bool]):
    class Handler(BaseHTTPRequestHandler):
        server_version = "fnh-dashboard"
        sys_version = ""

        def do_GET(self):  # noqa: N802 (http.server naming)
            if not host_ok(self.headers.get("Host", "")):
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


class _Server(ThreadingHTTPServer):
    daemon_threads = True


class _Server6(_Server):
    address_family = socket.AF_INET6


def make_server(app: DashboardApp, host: str = "127.0.0.1", port: int = 8765,
                allow_hosts: Iterable[str] = ()) -> ThreadingHTTPServer:
    cls = _Server6 if ":" in host else _Server
    server = cls((host, port), make_handler(app, lambda _: False))
    # Port 0 means "any free port": check against the one actually bound.
    check = HostCheck(server.server_address[1], host, allow_hosts)
    server.RequestHandlerClass = make_handler(app, check)
    return server


def serve(report_dir: str | Path, promote_dir: Optional[str | Path] = None,
          host: str = "127.0.0.1", port: int = 8765, open_browser: bool = False,
          allow_hosts: Iterable[str] = ()) -> None:
    server = make_server(DashboardApp(report_dir, promote_dir), host, port, allow_hosts)
    shown = "localhost" if host in ("127.0.0.1", "::1", "0.0.0.0", "::") else host
    url = f"http://{f'[{shown}]' if ':' in shown else shown}:{server.server_address[1]}/"
    print(f"fnh dashboard: {url}  (reports from {report_dir}; Ctrl-C to stop)")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
