import http.server
import shutil
import subprocess
import threading

import pytest

from fnh.probes import available_probes, build_verify


def test_raw_string_passthrough():
    assert build_verify("curl -sf https://x") == "curl -sf https://x"


def test_none_is_none():
    assert build_verify(None) is None


def test_http_status_builds_curl():
    cmd = build_verify({"probe": "http_status", "url": "https://stg/x", "expect": 400})
    assert cmd.startswith('test "$(')
    assert "curl" in cmd and "https://stg/x" in cmd
    assert cmd.rstrip().endswith("= 400")


def test_http_status_options():
    cmd = build_verify({
        "probe": "http_status", "url": "https://stg/x",
        "method": "POST", "header": "X-Test: 1", "data": "body", "insecure": True,
    })
    assert "-X POST" in cmd
    assert "-k" in cmd
    assert "X-Test: 1" in cmd
    assert "--data-binary" in cmd


@pytest.fixture
def header_server():
    """Local HTTP server: /leaky leaks a header and body; /slow stalls."""
    import time

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/slow":
                time.sleep(1.5)
            body = b"secret-token" if self.path == "/leaky" else b"all clear"
            self.send_response(200)
            if self.path == "/leaky":
                self.send_header("X-Leak", "secret")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except BrokenPipeError:
                pass  # a client that timed out (response_under test) hung up

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _run(cmd):
    return subprocess.run(["bash", "-c", cmd], capture_output=True).returncode


needs_curl = pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")


@needs_curl
def test_http_header_absent_passes_when_header_missing(header_server):
    cmd = build_verify({"probe": "http_header_absent", "url": header_server + "/clean", "header": "X-Leak"})
    assert _run(cmd) == 0


@needs_curl
def test_http_header_absent_fails_when_header_present(header_server):
    cmd = build_verify({"probe": "http_header_absent", "url": header_server + "/leaky", "header": "x-leak"})
    assert _run(cmd) != 0


@needs_curl
def test_http_header_absent_fails_when_service_down():
    # Port 1 refuses connections; that must not read as "header absent".
    cmd = build_verify({"probe": "http_header_absent", "url": "http://127.0.0.1:1/", "header": "X-Leak"})
    assert _run(cmd) != 0


def test_port_closed_rejects_shell_in_host():
    with pytest.raises(ValueError):
        build_verify({"probe": "port_closed", "host": "x; touch /tmp/p", "port": 80})
    with pytest.raises(ValueError):
        build_verify({"probe": "port_closed", "host": "stg", "port": 70000})


def test_port_closed():
    cmd = build_verify({"probe": "port_closed", "host": "stg", "port": 8080, "timeout": 3})
    assert cmd.startswith("! ")
    assert "/dev/tcp/stg/8080" in cmd
    assert "timeout 3" in cmd


def test_command_fails_inverts():
    cmd = build_verify({"probe": "command_fails", "cmd": "exploit.sh"})
    assert cmd == "! { exploit.sh ; }"


def test_unknown_probe_raises():
    with pytest.raises(ValueError):
        build_verify({"probe": "nope"})


def test_invalid_spec_raises():
    with pytest.raises(ValueError):
        build_verify(123)


def test_registry_lists_probes():
    assert set(available_probes()) == {
        "http_status", "http_header_absent", "http_header_present",
        "http_body_lacks", "response_under", "port_closed", "command_fails",
    }


@needs_curl
def test_http_header_present_passes_when_header_set(header_server):
    cmd = build_verify({"probe": "http_header_present", "url": header_server + "/leaky", "header": "x-leak"})
    assert _run(cmd) == 0


@needs_curl
def test_http_header_present_fails_when_missing_or_down(header_server):
    assert _run(build_verify({"probe": "http_header_present", "url": header_server + "/clean", "header": "X-Leak"})) != 0
    assert _run(build_verify({"probe": "http_header_present", "url": "http://127.0.0.1:1/", "header": "X-Leak"})) != 0


@needs_curl
def test_http_body_lacks(header_server):
    # Marker gone -> pass; marker present -> fail; service down -> fail.
    assert _run(build_verify({"probe": "http_body_lacks", "url": header_server + "/clean", "marker": "secret-token"})) == 0
    assert _run(build_verify({"probe": "http_body_lacks", "url": header_server + "/leaky", "marker": "secret-token"})) != 0
    assert _run(build_verify({"probe": "http_body_lacks", "url": "http://127.0.0.1:1/", "marker": "x"})) != 0


@needs_curl
def test_response_under(header_server):
    assert _run(build_verify({"probe": "response_under", "url": header_server + "/clean", "timeout": 5})) == 0
    # /slow sleeps 1.5s; a 1s budget must fail.
    assert _run(build_verify({"probe": "response_under", "url": header_server + "/slow", "timeout": 1})) != 0


def test_http_body_lacks_marker_is_literal_not_regex():
    # A marker with regex metacharacters and a leading dash must stay literal
    # and not be read as a grep option.
    cmd = build_verify({"probe": "http_body_lacks", "url": "https://stg/", "marker": "-v.*[x]"})
    assert "grep -qF -- " in cmd and _run(cmd + "; true") == 0  # compiles & runs
