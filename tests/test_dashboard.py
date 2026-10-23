import http.client
import json
import threading
from datetime import datetime, timezone
from importlib import resources

import pytest

from fnh.__main__ import main
from fnh.dashboard import DashboardApp, make_server
from fnh.models import Advisory, Asset, Match, Outcome, OutcomeStatus, Remediation, RemediationKind, Severity
from fnh.promote import FilePromoter
from fnh.report import build_report, list_reports, load_report, write_report


def _outcome(status=OutcomeStatus.PATCHED, sev=Severity.HIGH, env="staging"):
    adv = Advisory("CVE-1", "title <b>", "s", sev, 7.5, source="osv",
                   references=[f"https://x.test/{i}" for i in range(20)])
    asset = Asset("a1", "requests", "package", ecosystem="pypi", version="2.31.0", environment=env)
    rem = Remediation(RemediationKind.PATCH, "Upgrade", target_version="2.32.0", steps=["pip install x"])
    return Outcome(Match(adv, asset, "why"), status, rem, validated=True, notes=["n"], recommendations=["r"])


def _report(when, outcomes):
    return build_report(outcomes, sources=["osv"], inventory_source="file", dry_run=True,
                        generated_at=when)


# -- reports -------------------------------------------------------------------

def test_report_shape_and_round_trip(tmp_path):
    when = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    report = _report(when, [_outcome(), _outcome(OutcomeStatus.NEEDS_REVIEW, Severity.LOW)])
    assert report["schema"] == 1
    assert report["summary"] == {"total": 2, "by_status": {"patched": 1, "needs_review": 1},
                                 "by_severity": {"high": 1, "low": 1}}
    o = report["outcomes"][0]
    assert o["advisory"]["id"] == "CVE-1" and len(o["advisory"]["references"]) == 10
    assert o["asset"]["environment"] == "staging"
    assert o["remediation"]["target_version"] == "2.32.0"

    path = write_report(report, tmp_path)
    assert path.name == "run-20261001T120000.000000Z.json"
    assert list_reports(tmp_path) == [path]
    assert load_report(tmp_path, path.name) == report


@pytest.mark.parametrize("name", ["../secret.json", "run-x.json", "/etc/passwd", "run-20261001T120000.000000Z.json/.."])
def test_load_report_rejects_non_report_names(tmp_path, name):
    (tmp_path / "secret.json").write_text("{}")
    assert load_report(tmp_path, name) is None


def test_list_reports_ignores_other_files_and_sorts(tmp_path):
    for day in (3, 1, 2):
        write_report(_report(datetime(2026, 10, day, tzinfo=timezone.utc), []), tmp_path)
    (tmp_path / "notes.txt").write_text("x")
    (tmp_path / "run-20261004T000000.000000Z.json.tmp").write_text("{")
    assert [p.name[4:12] for p in list_reports(tmp_path)] == ["20261001", "20261002", "20261003"]


def test_cli_run_writes_report(tmp_path, capsys):
    assert main(["run", "--dry-run", "--report-dir", str(tmp_path)]) == 0
    (path,) = list_reports(tmp_path)
    report = json.loads(path.read_text())
    assert report["sources"] == ["file"] and report["dry_run"] is True
    assert report["summary"]["total"] == 3
    assert "report written to" in capsys.readouterr().err


def test_static_files_are_packaged():
    for name in ("index.html", "app.js", "app.css"):
        assert resources.files("fnh").joinpath("static", name).is_file()


def test_page_never_builds_html_from_strings():
    js = resources.files("fnh").joinpath("static", "app.js").read_text()
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in js
    html = resources.files("fnh").joinpath("static", "index.html").read_text()
    assert "http://" not in html and "https://" not in html  # no third-party assets
    assert "<script>" not in html and "style=" not in html    # nothing inline for CSP to allow


# -- server --------------------------------------------------------------------

@pytest.fixture
def server(tmp_path):
    reports, promos = tmp_path / "reports", tmp_path / "promos"
    for day, status in ((1, OutcomeStatus.NEEDS_REVIEW), (2, OutcomeStatus.PATCHED)):
        write_report(_report(datetime(2026, 10, day, tzinfo=timezone.utc), [_outcome(status)]), reports)
    FilePromoter(promos).promote(_outcome(OutcomeStatus.AWAITING_PROMOTION, env="production"))
    srv = make_server(DashboardApp(reports, promos), "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def _get(port, path, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers={"Host": host or f"localhost:{port}"})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp, body


def test_serves_page_with_security_headers(server):
    resp, body = _get(server, "/")
    assert resp.status == 200 and b"<title>FNH Dashboard</title>" in body
    csp = resp.getheader("Content-Security-Policy")
    assert "script-src 'self'" in csp and "default-src 'none'" in csp and "unsafe-inline" not in csp
    assert resp.getheader("X-Content-Type-Options") == "nosniff"
    for path, ctype in (("/app.js", "text/javascript"), ("/app.css", "text/css")):
        resp, _ = _get(server, path)
        assert resp.status == 200 and resp.getheader("Content-Type").startswith(ctype)


def test_api_runs_history_and_report(server):
    _, body = _get(server, "/api/runs")
    runs = json.loads(body)
    assert [r["generated_at"][:10] for r in runs] == ["2026-10-02", "2026-10-01"]  # newest first
    assert runs[0]["summary"]["by_status"] == {"patched": 1}

    _, body = _get(server, "/api/history")
    history = json.loads(body)
    assert [h["findings"][0]["status"] for h in history] == ["needs_review", "patched"]  # oldest first
    assert set(history[0]["findings"][0]) == {"status", "severity", "source", "environment"}

    resp, body = _get(server, f"/api/runs/{runs[0]['name']}")
    assert resp.status == 200 and json.loads(body)["outcomes"][0]["advisory"]["id"] == "CVE-1"


def test_api_promotions(server):
    _, body = _get(server, "/api/promotions")
    data = json.loads(body)
    assert data["directory"].endswith("promos")
    (req,) = data["requests"]
    assert req["advisory_id"] == "CVE-1" and req["result"] is None


@pytest.mark.parametrize("path", [
    "/api/runs/..%2f..%2fetc%2fpasswd", "/api/runs/../promos", "/static/app.js",
    "/fnh/__init__.py", "/api/runs/run-x.json", "/nope",
])
def test_unknown_and_traversal_paths_are_404(server, path):
    resp, _ = _get(server, path)
    assert resp.status == 404


def test_rejects_foreign_host_header(server):
    # A DNS-rebinding page would arrive with its own hostname.
    resp, _ = _get(server, "/api/runs", host=f"attacker.example:{server}")
    assert resp.status == 421
    resp, _ = _get(server, "/api/runs", host=f"127.0.0.1:{server}")
    assert resp.status == 200


def test_without_promote_dir(tmp_path):
    app = DashboardApp(tmp_path)
    assert app.promotions() == {"directory": None, "requests": []}
    assert app.runs() == [] and app.history() == []


def test_dashboard_cli_warns_when_not_loopback(monkeypatch, capsys, tmp_path):
    import fnh.__main__ as cli
    calls = []
    monkeypatch.setattr(cli, "serve", lambda *a: calls.append(a))
    assert main(["dashboard", "--report-dir", str(tmp_path), "--host", "0.0.0.0"]) == 0
    assert "no authentication" in capsys.readouterr().err
    assert calls and calls[0][2] == "0.0.0.0"



# -- host check -----------------------------------------------------------------

@pytest.mark.parametrize("header,ok", [
    ("localhost:8765", True),
    ("127.0.0.1:8765", True),
    ("192.0.2.10:8765", True),        # any IP literal: rebinding needs a domain name
    ("[::1]:8765", True),
    ("[2001:db8::1]:8765", True),
    ("dash.internal:8765", True),     # --allow-host
    ("DASH.INTERNAL:8765", True),
    ("attacker.example:8765", False),
    ("localhost:9999", False),        # wrong port
    ("localhost", False),             # no port
    ("", False),
])
def test_host_check(header, ok):
    from fnh.dashboard import HostCheck
    assert HostCheck(8765, "0.0.0.0", ["dash.internal"])(header) is ok


def test_host_check_accepts_machine_name():
    import socket
    from fnh.dashboard import HostCheck
    assert HostCheck(80, "0.0.0.0")(f"{socket.gethostname()}:80")


def test_wildcard_bind_is_reachable(tmp_path):
    # Regression: binding to 0.0.0.0 used to reject every request with 421.
    srv = make_server(DashboardApp(tmp_path), "0.0.0.0", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        assert _get(port, "/api/runs", host=f"127.0.0.1:{port}")[0].status == 200
        assert _get(port, "/api/runs", host=f"evil.example:{port}")[0].status == 421
    finally:
        srv.shutdown()
        srv.server_close()


def test_ipv6_bind(tmp_path):
    import socket
    if not socket.has_ipv6:
        pytest.skip("no IPv6")
    try:
        srv = make_server(DashboardApp(tmp_path), "::1", 0)
    except OSError:
        pytest.skip("IPv6 loopback unavailable")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        conn = http.client.HTTPConnection("::1", port, timeout=5)
        conn.request("GET", "/api/runs", headers={"Host": f"[::1]:{port}"})
        assert conn.getresponse().status == 200
        conn.close()
    finally:
        srv.shutdown()
        srv.server_close()


# -- report cache -----------------------------------------------------------------

def test_cache_parses_each_report_once(tmp_path, monkeypatch):
    import fnh.dashboard as dash
    for day in range(1, 6):
        write_report(_report(datetime(2026, 10, day, tzinfo=timezone.utc), [_outcome()]), tmp_path)
    calls = []
    real = dash.load_report
    monkeypatch.setattr(dash, "load_report", lambda d, n: calls.append(n) or real(d, n))
    monkeypatch.setattr(dash, "HISTORY_LIMIT", 2)
    app = DashboardApp(tmp_path)
    for _ in range(3):
        app.runs()
        app.history()  # a smaller window must not evict the others
    assert len(calls) == 5


def test_cache_sees_changed_and_deleted_reports(tmp_path):
    app = DashboardApp(tmp_path)
    first = write_report(_report(datetime(2026, 10, 1, tzinfo=timezone.utc), [_outcome()]), tmp_path)
    second = write_report(_report(datetime(2026, 10, 2, tzinfo=timezone.utc), [_outcome()]), tmp_path)
    assert app.runs()[0]["summary"]["total"] == 1
    assert app.run(second.name)["summary"]["total"] == 1

    # Rewritten in place (new size): served fresh, both summary and full report.
    report = _report(datetime(2026, 10, 2, tzinfo=timezone.utc), [_outcome(), _outcome(sev=Severity.LOW)])
    second.write_text(json.dumps(report))
    assert app.runs()[0]["summary"]["total"] == 2
    assert app.run(second.name)["summary"]["total"] == 2

    first.unlink()
    assert [r["name"] for r in app.runs()] == [second.name]
    assert app.run(first.name) is None


def test_run_rejects_bad_names_before_touching_disk(tmp_path):
    assert DashboardApp(tmp_path).run("../../etc/passwd") is None


# -- promotion index ----------------------------------------------------------------

def test_promoter_index_dedupes_and_respects_results(tmp_path):
    promoter = FilePromoter(tmp_path)
    o = _outcome(OutcomeStatus.AWAITING_PROMOTION, env="production")
    first = promoter.promote(o)
    assert promoter.promote(o).id == first.id
    assert len(list(tmp_path.glob("*.json"))) == 1

    first.result = "applied"
    promoter.save(first)
    again = promoter.promote(o)  # the old one is done, so a new request is queued
    assert again.id != first.id
    # A fresh promoter (next run) reads the same state from disk.
    assert FilePromoter(tmp_path).promote(o).id == again.id
    assert not list(tmp_path.glob("*.tmp"))
