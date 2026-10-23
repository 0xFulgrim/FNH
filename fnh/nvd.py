"""NVD (National Vulnerability Database) feed, CVE API 2.0.

NVD identifies software by CPE (vendor and product), not by package name, so
this feed only covers inventory assets that carry a `cpe` such as
"cpe:2.3:a:nginx:nginx". For each distinct product it asks NVD for every CVE
whose configurations match, then turns each vulnerable `cpeMatch` into a
version range on the assets with that CPE.

Requests are paced to NVD's published limits: 5 per rolling 30 seconds
without an API key, 50 with one. Set NVD_API_KEY to use a key.

NVD ranges are upstream versions. Distribution packages that backport fixes
without changing the upstream version (Debian, Ubuntu, RHEL) will show false
positives; use the OSV feed for those.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime
from typing import Callable, Iterable, Optional
from urllib.parse import urlencode

from .feed import Feed
from .httpclient import FeedError, Response, fetch_json
from .models import Advisory, Asset, Severity

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE_SIZE = 2000  # NVD's maximum resultsPerPage
_MAX_PAGES = 50
# Seconds between requests: 30s / 5 requests without a key, 30s / 50 with one.
_INTERVAL_NO_KEY = 6.0
_INTERVAL_WITH_KEY = 0.6
# NVD answers rate limiting with 403 and overload with 503.
_RETRY_STATUSES = (403, 429, 500, 502, 503, 504)
_MAX_RETRIES = 3
# Preferred metric versions, newest first.
_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

Transport = Callable[[str, dict], Response]
Product = tuple[str, str, str]  # (part, vendor, product), lower-cased


class NVDError(FeedError):
    pass


def _split_cpe(cpe: str) -> list[str]:
    # Fields are colon-separated; a literal colon inside a value is "\:".
    return [f.replace("\\:", ":") for f in re.split(r"(?<!\\):", cpe)]


def parse_cpe(cpe: str) -> Optional[Product]:
    """(part, vendor, product) from "cpe:2.3:a:vendor:product[:...]" or
    the shorthand "vendor:product" (part "a"). None if it doesn't parse."""
    fields = _split_cpe(cpe.strip())
    if len(fields) >= 5 and fields[0].lower() == "cpe" and fields[1] == "2.3":
        part, vendor, product = fields[2], fields[3], fields[4]
    elif len(fields) == 2:
        part, (vendor, product) = "a", fields
    else:
        return None
    if not vendor or not product or vendor == "*" or product == "*":
        return None
    return part.lower(), vendor.lower(), product.lower()


def products_from_inventory(assets: Iterable[Asset]) -> dict[Product, list[Asset]]:
    """Group assets that carry a CPE by the product NVD should be asked about."""
    out: dict[Product, list[Asset]] = {}
    for asset in assets:
        product = parse_cpe(asset.cpe) if asset.cpe else None
        if product:
            out.setdefault(product, []).append(asset)
    return out


def _constraint(match: dict) -> Optional[str]:
    """Version constraint for one vulnerable cpeMatch, or None to skip it."""
    bounds = [
        (">=", match.get("versionStartIncluding")),
        (">", match.get("versionStartExcluding")),
        ("<=", match.get("versionEndIncluding")),
        ("<", match.get("versionEndExcluding")),
    ]
    parts = [f"{op}{v}" for op, v in bounds if v]
    if parts:
        return ",".join(parts)
    fields = _split_cpe(match.get("criteria", ""))
    version = fields[5] if len(fields) > 5 else "*"
    if version == "*":
        return ""  # every version
    if version == "-":
        return None  # "not applicable": nothing to compare against
    return f"=={version}"


def _score(cve: dict) -> tuple[Optional[float], Optional[Severity]]:
    metrics = cve.get("metrics") or {}
    for key in _METRIC_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        # NVD's own ("Primary") assessment wins over CNA-supplied ones.
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        label = Severity.from_label(data.get("baseSeverity") or entry.get("baseSeverity"))
        if score is not None:
            return float(score), label or Severity.from_cvss(float(score))
    return None, None


def parse_nvd_cve(cve: dict, products: dict[Product, list[Asset]]) -> Optional[Advisory]:
    """Parse one `vulnerabilities[].cve` object. Only cpeMatch entries for the
    given products become affected entries; returns None if there are none."""
    # (ecosystem, name) -> affected entry, built from every matching cpeMatch.
    affected: dict[tuple, dict] = {}
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                product = parse_cpe(match.get("criteria", ""))
                assets = products.get(product) if product else None
                if not assets:
                    continue
                constraint = _constraint(match)
                if constraint is None:
                    continue
                for asset in assets:
                    eco = asset.ecosystem or "cpe"
                    entry = affected.setdefault(
                        (eco, asset.name),
                        {"ecosystem": eco, "name": asset.name, "ranges": [], "fixed": []},
                    )
                    if constraint not in entry["ranges"]:
                        entry["ranges"].append(constraint)
                    fix = match.get("versionEndExcluding")
                    if fix and fix not in entry["fixed"]:
                        entry["fixed"].append(fix)
    if not affected:
        return None

    score, severity = _score(cve)
    description = next(
        (d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), ""
    )
    published = None
    if cve.get("published"):
        try:
            published = datetime.fromisoformat(cve["published"].replace("Z", "+00:00"))
        except ValueError:
            pass

    entries = list(affected.values())
    return Advisory(
        id=cve["id"],
        title=description.split(". ")[0][:200] or cve["id"],
        summary=description,
        severity=severity or Severity.MEDIUM,
        cvss=score,
        published=published,
        source="nvd",
        affected=entries,
        vulnerable_ranges=[r for e in entries for r in e["ranges"]],
        fixed_versions=[f for e in entries for f in e["fixed"]],
        references=[r["url"] for r in cve.get("references") or [] if r.get("url")],
    )


class NVDFeed(Feed):
    """CVEs from NVD for inventory assets that carry a CPE."""

    def __init__(
        self,
        assets: Iterable[Asset],
        api_key: Optional[str] = None,
        base_url: str = NVD_API,
        transport: Optional[Transport] = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.products = products_from_inventory(assets)
        self.api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY")
        self.base_url = base_url
        self._get: Transport = transport or (lambda url, headers: fetch_json(url, headers=headers))
        self._sleep = sleep
        self._clock = clock
        self._interval = _INTERVAL_WITH_KEY if self.api_key else _INTERVAL_NO_KEY
        self._last_request: Optional[float] = None

    def fetch(self) -> list[Advisory]:
        advisories: dict[str, Advisory] = {}
        for part, vendor, product in self.products:
            for cve in self._query(f"cpe:2.3:{part}:{vendor}:{product}"):
                if cve.get("id") in advisories or cve.get("vulnStatus") == "Rejected":
                    continue
                advisory = parse_nvd_cve(cve, self.products)
                if advisory is not None:
                    advisories[advisory.id] = advisory
        return list(advisories.values())

    def _query(self, match_string: str) -> list[dict]:
        cves: list[dict] = []
        start = 0
        for _ in range(_MAX_PAGES):
            params = urlencode({
                "virtualMatchString": match_string,
                "resultsPerPage": _PAGE_SIZE,
                "startIndex": start,
            })
            data = self._request(f"{self.base_url}?{params}").data or {}
            page = [v["cve"] for v in data.get("vulnerabilities") or [] if "cve" in v]
            cves.extend(page)
            start += len(page)
            if not page or start >= int(data.get("totalResults") or 0):
                break
        return cves

    def _request(self, url: str) -> Response:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        for attempt in range(_MAX_RETRIES + 1):
            self._throttle()
            resp = self._get(url, headers)
            if resp.ok:
                return resp
            if resp.status not in _RETRY_STATUSES or attempt == _MAX_RETRIES:
                break
            # Back off on top of the normal pacing before trying again.
            self._sleep(self._interval * (attempt + 1))
        hint = "" if self.api_key else " (set NVD_API_KEY for a higher rate limit)"
        raise NVDError(f"NVD request failed: HTTP {resp.status}{hint}")

    def _throttle(self) -> None:
        now = self._clock()
        if self._last_request is not None:
            wait = self._interval - (now - self._last_request)
            if wait > 0:
                self._sleep(wait)
                now += wait
        self._last_request = now
