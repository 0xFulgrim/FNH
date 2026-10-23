"""LLM advisory enrichment — drafts a reproduction check, never runs it.

Given an advisory and the asset it matched, an LLM is asked to:
  - summarize the issue in plain language,
  - name the condition that triggers it,
  - *draft* a `verify` probe spec (see probes.py) that would confirm a fix holds.

The draft is a suggestion for a human to review, written to a file by
`fnh enrich`. It is never executed here, and three things keep a hallucinated
or hostile model reply from turning into code that runs:

  1. The reply is parsed as JSON data, never evaluated.
  2. A drafted probe must name one of the *bounded* probe builders and compile
     through `probes.build_verify`; anything else is dropped with a warning. The
     arbitrary-shell escape hatches (`command_fails` and a raw-string verify)
     are refused outright.
  3. Even once reviewed, a probe only runs through the normal path — added to
     the mitigation library, vetted again by the SafetyPolicy, applied against
     your own staging.

The LLM client is injectable, so tests run without network or an API key.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Optional, Protocol

from .httpclient import FeedError, fetch_json
from .models import Advisory, Asset
from .probes import build_verify

ANTHROPIC_API = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-5-5"
# Probes the enricher may draft: the bounded templates only. `command_fails`
# and raw-string verify run arbitrary shell, so they are never LLM-drafted.
ALLOWED_PROBES = frozenset({
    "http_status", "http_header_absent", "http_header_present",
    "http_body_lacks", "response_under", "port_closed",
})

_SYSTEM = (
    "You are a security engineer assistant. Given a vulnerability advisory and "
    "one affected asset, reply with ONLY a JSON object (no prose, no code fence) "
    "with keys: summary (one plain sentence), trigger (the condition that sets "
    "off the vulnerability), and probe (a check that a fix HOLDS, or null). The "
    "probe is an object {\"probe\": <type>, ...params} using exactly one of these "
    "types, which assert the HARDENED behaviour after a fix:\n"
    "- http_status: {url, expect:int, method?, header?, data?} request now returns `expect`\n"
    "- http_header_absent: {url, header} response no longer sends `header`\n"
    "- http_header_present: {url, header} response now sends `header`\n"
    "- http_body_lacks: {url, marker} body no longer contains literal `marker`\n"
    "- response_under: {url, timeout:int} request completes within `timeout`s\n"
    "- port_closed: {host, port:int} TCP port no longer accepts connections\n"
    "Use a staging URL placeholder like https://staging.internal/PATH when you "
    "don't know the real one. If no safe check fits, set probe to null. Never "
    "propose running exploit code."
)


class LLMClient(Protocol):
    def complete(self, system: str, user: str) -> str: ...


@dataclass
class Enrichment:
    advisory_id: str
    asset_id: str
    summary: str = ""
    trigger: str = ""
    suggested_probe: Optional[dict] = None
    # The compiled command, shown so a reviewer sees exactly what would run.
    probe_command: Optional[str] = None
    model: Optional[str] = None
    warnings: list = field(default_factory=list)
    # Always starts false: a drafted probe is a proposal, not an approval.
    approved: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class AnthropicClient:
    """Default client: the Claude Messages API over the shared HTTPS client.

    Reads ANTHROPIC_API_KEY from the environment unless a key is given.
    """

    def __init__(self, api_key: Optional[str] = None, model: str = DEFAULT_MODEL,
                 base_url: str = ANTHROPIC_API, max_tokens: int = 1024):
        self.api_key = api_key if api_key is not None else os.environ.get("ANTHROPIC_API_KEY")
        self.model = model
        self.base_url = base_url
        self.max_tokens = max_tokens

    def complete(self, system: str, user: str) -> str:
        if not self.api_key:
            raise FeedError("ANTHROPIC_API_KEY is not set")
        resp = fetch_json(
            self.base_url, method="POST",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            payload={
                "model": self.model, "max_tokens": self.max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        if not resp.ok:
            message = (resp.data or {}).get("error", {}).get("message", "") \
                if isinstance(resp.data, dict) else ""
            raise FeedError(f"Anthropic API returned HTTP {resp.status} {message}".strip())
        blocks = (resp.data or {}).get("content") or []
        return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")


def _user_prompt(advisory: Advisory, asset: Asset) -> str:
    return json.dumps({
        "advisory": {
            "id": advisory.id, "title": advisory.title,
            "summary": advisory.summary[:2000], "severity": advisory.severity.value,
        },
        "asset": {
            "name": asset.name, "ecosystem": asset.ecosystem,
            "version": asset.version, "environment": asset.environment,
        },
    }, indent=2)


def _extract_json(reply: str) -> Optional[dict]:
    reply = reply.strip()
    # Tolerate a ```json ... ``` fence around the object.
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", reply, re.DOTALL)
    if fence:
        reply = fence.group(1)
    start, end = reply.find("{"), reply.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        data = json.loads(reply[start:end + 1])
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _validate_probe(probe, allowed_hosts: Optional[set]) -> tuple[Optional[dict], Optional[str], list]:
    """Return (clean_probe, compiled_command, warnings). Drops anything that is
    not a bounded, compilable probe."""
    warnings: list = []
    if probe is None:
        return None, None, warnings
    if not isinstance(probe, dict) or "probe" not in probe:
        return None, None, ["ignored a drafted probe that was not an object"]
    name = probe.get("probe")
    if name not in ALLOWED_PROBES:
        return None, None, [f"ignored drafted probe of disallowed type {name!r}"]
    try:
        command = build_verify(probe)
    except ValueError as exc:
        return None, None, [f"ignored a drafted probe that did not compile: {exc}"]
    # The probe targets a host; flag one that isn't a known staging host so the
    # reviewer re-points it. It never runs without review, so this is advisory.
    if allowed_hosts:
        host = _probe_host(probe)
        if host and host.lower() not in {h.lower() for h in allowed_hosts}:
            warnings.append(f"drafted probe targets {host!r}; re-point it at your staging host")
    return probe, command, warnings


def _probe_host(probe: dict) -> Optional[str]:
    if probe.get("host"):
        return str(probe["host"])
    url = probe.get("url")
    if url:
        m = re.match(r"[a-z]+://([^/:]+)", str(url), re.I)
        if m:
            return m.group(1)
    return None


def enrich(advisory: Advisory, asset: Asset, client: LLMClient,
           allowed_hosts: Optional[set] = None, model: Optional[str] = None) -> Enrichment:
    """Draft a plain-language summary and a review-only verify probe."""
    out = Enrichment(advisory_id=advisory.id, asset_id=asset.id, model=model)
    try:
        reply = client.complete(_SYSTEM, _user_prompt(advisory, asset))
    except FeedError as exc:
        out.warnings.append(f"enrichment failed: {exc}")
        return out
    data = _extract_json(reply)
    if data is None:
        out.warnings.append("model reply was not valid JSON")
        return out
    out.summary = str(data.get("summary", ""))[:500]
    out.trigger = str(data.get("trigger", ""))[:500]
    probe, command, warnings = _validate_probe(data.get("probe"), allowed_hosts)
    out.suggested_probe = probe
    out.probe_command = command
    out.warnings += warnings
    return out
