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


def test_http_header_absent_inverts():
    cmd = build_verify({"probe": "http_header_absent", "url": "https://stg", "header": "Authorization"})
    assert cmd.startswith("! ")
    assert "grep -qi" in cmd
    assert "Authorization:" in cmd


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
        "http_status", "http_header_absent", "port_closed", "command_fails"
    }
