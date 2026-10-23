"""GitHub Advisory Database (GHSA) feed.

Queries GitHub's global advisories endpoint (`GET /advisories`) for the
packages in your inventory, using the `affects` filter so one request covers
many packages. Pages are followed through the `Link` header. Withdrawn
advisories are skipped.

Authentication is optional: set GITHUB_TOKEN to raise the rate limit from 60
to 5,000 requests per hour.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime
from typing import Callable, Iterable, Optional
from urllib.parse import quote, urlencode

from .feed import Feed
from .httpclient import FeedError, Response, fetch_json
from .models import Advisory, Asset, Severity

GITHUB_API = "https://api.github.com"

# Inventory ecosystem label -> GHSA ecosystem name.
ECOSYSTEM_MAP = {
    "pypi": "pip",
    "npm": "npm",
    "go": "go",
    "maven": "maven",
    "nuget": "nuget",
    "cargo": "rust",
    "rubygems": "rubygems",
    "composer": "composer",
    "pub": "pub",
    "hex": "erlang",
}
REVERSE_ECOSYSTEM = {ghsa: inv for inv, ghsa in ECOSYSTEM_MAP.items()}

# Packages per request. GitHub allows 1000 in `affects`, but the URL has to
# stay under common length limits.
_AFFECTS_CHUNK = 100
_PER_PAGE = 100
_MAX_PAGES = 100
# Wait at most this long when GitHub asks us to back off; otherwise fail.
_MAX_RETRY_AFTER = 60

Transport = Callable[[str, dict], Response]


class GHSAError(FeedError):
    pass


def packages_from_inventory(assets: Iterable[Asset]) -> list[tuple[str, str]]:
    """Distinct (ghsa_ecosystem, name) pairs we can query GitHub for."""
    seen: dict[tuple[str, str], None] = {}
    for asset in assets:
        eco = ECOSYSTEM_MAP.get(asset.ecosystem or "")
        if eco:
            seen.setdefault((eco, asset.name), None)
    return list(seen)


def _range_to_constraint(expr: str) -> str:
    # ">= 1.0.0, < 1.2.3" -> ">=1.0.0,<1.2.3"
    return ",".join(re.sub(r"\s+", "", part) for part in expr.split(",") if part.strip())


def _first_patched(vuln: dict) -> Optional[str]:
    value = vuln.get("first_patched_version")
    if isinstance(value, dict):  # older payloads nest it as {"identifier": ...}
        value = value.get("identifier")
    return value or None


def parse_ghsa_advisory(raw: dict) -> Advisory:
    """Parse one advisory from `GET /advisories` into an Advisory."""
    # One affected entry per package, merging repeated vulnerability rows.
    affected: dict[tuple, dict] = {}
    for vuln in raw.get("vulnerabilities") or []:
        pkg = vuln.get("package") or {}
        eco = REVERSE_ECOSYSTEM.get(pkg.get("ecosystem"), pkg.get("ecosystem"))
        entry = affected.setdefault(
            (eco, pkg.get("name")),
            {"ecosystem": eco, "name": pkg.get("name"), "ranges": [], "fixed": []},
        )
        if vuln.get("vulnerable_version_range"):
            entry["ranges"].append(_range_to_constraint(vuln["vulnerable_version_range"]))
        patched = _first_patched(vuln)
        if patched and patched not in entry["fixed"]:
            entry["fixed"].append(patched)

    cvss = (raw.get("cvss") or {}).get("score")
    severity = Severity.from_label(raw.get("severity"))
    if severity is None:
        severity = Severity.from_cvss(cvss) if cvss else Severity.MEDIUM

    published = None
    if raw.get("published_at"):
        try:
            published = datetime.fromisoformat(raw["published_at"].replace("Z", "+00:00"))
        except ValueError:
            pass

    references = raw.get("references") or []
    if raw.get("html_url"):
        references = [raw["html_url"], *references]

    entries = list(affected.values())
    return Advisory(
        id=raw.get("cve_id") or raw["ghsa_id"],
        title=raw.get("summary") or raw["ghsa_id"],
        summary=raw.get("description") or raw.get("summary") or "",
        severity=severity,
        cvss=float(cvss) if cvss else None,
        published=published,
        source="ghsa",
        affected=entries,
        vulnerable_ranges=[r for e in entries for r in e["ranges"]],
        fixed_versions=[f for e in entries for f in e["fixed"]],
        references=[r for r in references if isinstance(r, str)],
    )


def _next_link(headers: dict) -> Optional[str]:
    # Match on the whole header: the URLs themselves can contain commas
    # (`affects=a,b`), so splitting on "," would cut a link apart.
    m = re.search(r'<([^>]+)>\s*;\s*rel="next"', headers.get("link", ""))
    return m.group(1) if m else None


class GHSAFeed(Feed):
    """Advisories from the GitHub Advisory Database for a set of packages."""

    def __init__(
        self,
        packages: Iterable[tuple[str, str]],
        token: Optional[str] = None,
        base_url: str = GITHUB_API,
        transport: Optional[Transport] = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.packages = list(packages)
        self.token = token if token is not None else os.environ.get("GITHUB_TOKEN")
        self.base_url = base_url.rstrip("/")
        self._get: Transport = transport or (lambda url, headers: fetch_json(url, headers=headers))
        self._sleep = sleep

    def fetch(self) -> list[Advisory]:
        by_eco: dict[str, list[str]] = {}
        for eco, name in self.packages:
            by_eco.setdefault(eco, []).append(name)

        seen: dict[str, dict] = {}
        for eco, names in by_eco.items():
            for start in range(0, len(names), _AFFECTS_CHUNK):
                chunk = names[start:start + _AFFECTS_CHUNK]
                for raw in self._query(eco, chunk):
                    if raw.get("withdrawn_at"):
                        continue
                    seen.setdefault(raw["ghsa_id"], raw)
        return [parse_ghsa_advisory(raw) for raw in seen.values()]

    def _query(self, ecosystem: str, names: list[str]) -> list[dict]:
        params = urlencode({"ecosystem": ecosystem, "type": "reviewed", "per_page": _PER_PAGE})
        affects = ",".join(quote(n, safe="") for n in names)
        url: Optional[str] = f"{self.base_url}/advisories?{params}&affects={affects}"
        results: list[dict] = []
        pages = 0
        while url and pages < _MAX_PAGES:
            pages += 1
            resp = self._request(url)
            results.extend(resp.data or [])
            url = _next_link(resp.headers)
        return results

    def _request(self, url: str) -> Response:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        resp = self._get(url, headers)
        if resp.status in (403, 429):
            wait = _retry_after(resp.headers)
            if wait is not None and wait <= _MAX_RETRY_AFTER:
                self._sleep(wait)
                resp = self._get(url, headers)
        if not resp.ok:
            message = (resp.data or {}).get("message", "") if isinstance(resp.data, dict) else ""
            hint = "" if self.token else " (set GITHUB_TOKEN for a higher rate limit)"
            raise GHSAError(f"GitHub advisories request failed: HTTP {resp.status} {message}{hint}")
        return resp


def _retry_after(headers: dict) -> Optional[float]:
    if headers.get("retry-after", "").isdigit():
        return float(headers["retry-after"])
    if headers.get("x-ratelimit-remaining") == "0" and headers.get("x-ratelimit-reset", "").isdigit():
        return max(0.0, float(headers["x-ratelimit-reset"]) - time.time())
    return None
