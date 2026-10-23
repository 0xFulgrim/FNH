"""Mitigation probes — concrete "is the gap actually closed?" checks.

A mitigation is only trustworthy if something confirms it works. A probe is a
small, safe command run against *your own staging* service whose exit code is
the verdict: exit 0 means the vulnerability is confirmed closed, non-zero means
it is still open. These builders turn a declarative spec (from the mitigation
library) into such a command, so a mitigation entry can say

    "verify": {"probe": "http_status", "url": "https://stg/x", "expect": 400}

instead of hand-writing shell. A raw string `verify` is still honored as-is.

The builders lean on widely available tools (curl, bash). They assert the
*hardened* behavior you expect after mitigation — e.g. a now-rejected request
returns 400, a disabled endpoint returns 404, a port no longer listens.

Every probe but `command_fails` is a bounded template: the spec only fills in
parameters (url, header, marker, ...), never shell. `command_fails` and a raw
string `verify` are the two escape hatches that run arbitrary shell, so the LLM
enricher (enrich.py) is not allowed to emit either — it may only draft the
parametrized probes, which a human reviews before they are used.
"""

from __future__ import annotations

import re
import shlex
from typing import Callable, Optional

ProbeBuilder = Callable[[dict], str]


def _q(value) -> str:
    return shlex.quote(str(value))


def http_status(spec: dict) -> str:
    """Assert an HTTP(S) request returns an expected status code.

    spec: url, expect (int, default 400), method (default GET),
          data (optional request body), header (optional "K: V"), insecure (bool).
    """
    url = spec["url"]
    expect = int(spec.get("expect", 400))
    parts = ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", _q(spec.get("timeout", 10)),
             "-X", _q(spec.get("method", "GET"))]
    if spec.get("insecure"):
        parts.append("-k")
    if spec.get("header"):
        parts += ["-H", _q(spec["header"])]
    if spec.get("data") is not None:
        parts += ["--data-binary", _q(spec["data"])]
    parts.append(_q(url))
    # Compare the observed code to the expected one; exit 0 only on a match.
    return (
        'test "$(' + " ".join(parts) + ')" = ' + _q(expect)
    )


def http_header_absent(spec: dict) -> str:
    """Assert a response does NOT leak a given header (e.g. after a fix).

    spec: url, header (name, case-insensitive), insecure (bool).
    """
    url = spec["url"]
    header = spec["header"]
    curl = ["curl", "-sS", "-D", "-", "-o", "/dev/null",
            "--max-time", _q(spec.get("timeout", 10))]
    if spec.get("insecure"):
        curl.append("-k")
    curl.append(_q(url))
    # Capture headers first so a failed request (service down, TLS error) fails
    # the probe instead of reading as "header absent". Then invert grep so
    # absent => exit 0. Anchored to the start of a header line.
    return (
        "h=$(" + " ".join(curl) + ") && ! printf '%s\\n' \"$h\" | grep -qi "
        + _q("^" + header + ":")
    )


def port_closed(spec: dict) -> str:
    """Assert a TCP port is no longer accepting connections.

    spec: host, port, timeout (seconds, default 5).
    """
    host, port = str(spec["host"]), int(spec["port"])
    timeout = int(spec.get("timeout", 5))
    # The host lands inside a `bash -c` string, so only allow hostname/IP chars.
    if not re.fullmatch(r"[A-Za-z0-9.:\-\[\]]+", host):
        raise ValueError(f"invalid host for port_closed probe: {host!r}")
    if not 0 < port < 65536:
        raise ValueError(f"invalid port for port_closed probe: {port}")
    # bash's /dev/tcp connects; invert so a refused connection => exit 0.
    return (
        f"! timeout {timeout} bash -c "
        + _q(f"exec 3<>/dev/tcp/{host}/{port}")
    )


def _curl(spec: dict, *extra: str) -> list[str]:
    """Shared curl invocation for the HTTP probes."""
    curl = ["curl", "-sS", "--max-time", _q(spec.get("timeout", 10)), *extra]
    if spec.get("insecure"):
        curl.append("-k")
    if spec.get("method"):
        curl += ["-X", _q(spec["method"])]
    if spec.get("header"):
        curl += ["-H", _q(spec["header"])]
    if spec.get("data") is not None:
        curl += ["--data-binary", _q(spec["data"])]
    curl.append(_q(spec["url"]))
    return curl


def http_header_present(spec: dict) -> str:
    """Assert a response now carries a given header (e.g. a security header the
    fix adds, like Content-Security-Policy).

    spec: url, header (name, case-insensitive), insecure (bool).
    """
    curl = _curl(spec, "-D", "-", "-o", "/dev/null")
    # Capture first so a failed request fails the probe rather than reading as
    # "header missing"; match a header line by name.
    return (
        "h=$(" + " ".join(curl) + ") && printf '%s\\n' \"$h\" | grep -qi "
        + _q("^" + spec["header"] + ":")
    )


def http_body_lacks(spec: dict) -> str:
    """Assert a response body no longer contains a marker (a leaked secret, a
    stack trace, a version banner the fix removes).

    spec: url, marker (literal text), insecure (bool).
    """
    curl = _curl(spec, "-o", "-")
    # Fixed-string, literal match; `--` guards a marker starting with "-".
    # Capture first so a failed request fails the probe, then invert the grep.
    return (
        "b=$(" + " ".join(curl) + ") && ! printf '%s' \"$b\" | grep -qF -- "
        + _q(spec["marker"])
    )


def response_under(spec: dict) -> str:
    """Assert a request completes within a time budget (the fix stops it
    hanging or crashing). curl's own --max-time is the budget.

    spec: url, timeout (seconds, default 10), insecure (bool).
    """
    return " ".join(_curl(spec, "-o", "/dev/null"))


def command_fails(spec: dict) -> str:
    """Assert an arbitrary command now fails (the exploit path is blocked).

    spec: cmd (string). Exit 0 only when `cmd` exits non-zero.
    """
    return "! { " + spec["cmd"] + " ; }"


_REGISTRY: dict[str, ProbeBuilder] = {
    "http_status": http_status,
    "http_header_absent": http_header_absent,
    "http_header_present": http_header_present,
    "http_body_lacks": http_body_lacks,
    "response_under": response_under,
    "port_closed": port_closed,
    "command_fails": command_fails,
}


def build_verify(spec) -> Optional[str]:
    """Resolve a mitigation `verify` spec into a command string.

    - None             -> None
    - a string         -> used verbatim
    - a dict with "probe" -> dispatched to the matching builder
    """
    if spec is None:
        return None
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict) and "probe" in spec:
        name = spec["probe"]
        if name not in _REGISTRY:
            raise ValueError(f"unknown probe: {name!r}")
        return _REGISTRY[name](spec)
    raise ValueError(f"invalid verify spec: {spec!r}")


def available_probes() -> list[str]:
    return sorted(_REGISTRY)
