"""Minimal JSON-over-HTTPS client shared by the advisory feeds.

Standard library only. Requests go through HTTP(S)_PROXY when set, and the
agent proxy's CA bundle is trusted when present. Feeds take injectable
transports built on these helpers, so tests never touch the network.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Optional

_PROXY_CA_BUNDLE = "/root/.ccr/ca-bundle.crt"
USER_AGENT = "fnh (Friendly Neighborhood Helminth)"


@dataclass
class Response:
    status: int
    data: Any
    # Header names lower-cased.
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


class HTTPStatusError(Exception):
    def __init__(self, url: str, response: Response):
        super().__init__(f"HTTP {response.status} from {url}")
        self.response = response


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    # The agent proxy may terminate TLS; trust its CA bundle when present.
    if os.path.exists(_PROXY_CA_BUNDLE):
        try:
            ctx.load_verify_locations(_PROXY_CA_BUNDLE)
        except ssl.SSLError:
            pass
    return ctx


@lru_cache(maxsize=1)
def _opener() -> urllib.request.OpenerDirector:
    # Built once: loading the CA bundle is the expensive part.
    # ProxyHandler() with no args reads HTTP(S)_PROXY from the environment.
    return urllib.request.build_opener(
        urllib.request.ProxyHandler(),
        urllib.request.HTTPSHandler(context=_ssl_context()),
    )


def fetch_json(
    url: str,
    *,
    method: str = "GET",
    payload: Any = None,
    headers: Optional[dict[str, str]] = None,
    timeout: int = 30,
) -> Response:
    """Send a request and decode a JSON body. HTTP errors come back as a
    Response with the error status rather than raising; network failures
    still raise."""
    all_headers = {"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        all_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=all_headers, method=method)
    try:
        with _opener().open(req, timeout=timeout) as resp:
            status, body, resp_headers = resp.status, resp.read(), resp.headers
    except urllib.error.HTTPError as exc:
        status, body, resp_headers = exc.code, exc.read(), exc.headers
    try:
        decoded = json.loads(body.decode("utf-8")) if body else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        decoded = None
    return Response(status, decoded, {k.lower(): v for k, v in (resp_headers or {}).items()})


def get_json(url: str, headers: Optional[dict[str, str]] = None) -> Any:
    """GET and return the decoded body, raising HTTPStatusError on non-2xx."""
    resp = fetch_json(url, headers=headers)
    if not resp.ok:
        raise HTTPStatusError(url, resp)
    return resp.data


def post_json(url: str, payload: Any) -> Any:
    """POST JSON and return the decoded body, raising HTTPStatusError on non-2xx."""
    resp = fetch_json(url, method="POST", payload=payload)
    if not resp.ok:
        raise HTTPStatusError(url, resp)
    return resp.data
