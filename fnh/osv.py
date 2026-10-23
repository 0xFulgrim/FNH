"""OSV feed — real advisories from https://osv.dev.

OSV is a free, no-auth vulnerability database that aggregates GHSA, PyPA,
RustSec, Debian, and more. This feed discovers which advisories affect each
package in your inventory via the batch endpoint, fetches the full records
(caching them on disk), and parses them into our `Advisory` model. Our own
`Matcher` then does the version-range matching against the inventory.

Network access goes through the stdlib (`urllib`) so the package keeps zero
third-party dependencies. Both HTTP transports (POST and GET) are injectable,
so tests and dry-runs never touch the network, and an optional `OSVCache`
avoids re-fetching records whose `modified` timestamp hasn't changed.

Known simplification: our `Advisory` flattens vulnerable ranges into one list
rather than keying them per affected package. Because we query OSV one package
at a time and the matcher re-checks ecosystem+name before applying a range,
this is safe for single-package advisories (the common case). Multi-package
advisories keep only the ranges relevant to the queried package.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Optional

from .cvss import base_score
from .feed import Feed
from .matcher import _in_range
from .models import Advisory, Asset, Severity

OSV_API = "https://api.osv.dev"
_PROXY_CA_BUNDLE = "/root/.ccr/ca-bundle.crt"

# Our inventory's ecosystem labels -> OSV's canonical ecosystem names.
ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
    "go": "Go",
    "maven": "Maven",
    "nuget": "NuGet",
    "cargo": "crates.io",
    "rubygems": "RubyGems",
    "composer": "Packagist",
    "pub": "Pub",
    "hex": "Hex",
}

PostTransport = Callable[[str, dict], dict]
GetTransport = Callable[[str], dict]
# Backwards-compatible alias (the POST transport was once the only one).
Transport = PostTransport

_SEVERITY_WORDS = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


# Reverse: OSV name -> inventory label, so parsed advisories speak the same
# ecosystem vocabulary the inventory uses (e.g. "PyPI" -> "pypi").
REVERSE_ECOSYSTEM = {osv: inv for inv, osv in ECOSYSTEM_MAP.items()}


def from_osv_ecosystem(ecosystem: Optional[str]) -> Optional[str]:
    """Map an OSV ecosystem back to the inventory label; pass others through."""
    if ecosystem is None:
        return None
    return REVERSE_ECOSYSTEM.get(ecosystem, ecosystem)


def to_osv_ecosystem(ecosystem: Optional[str]) -> Optional[str]:
    """Map an inventory ecosystem to OSV's name; pass through known OSV names."""
    if not ecosystem:
        return None
    if ecosystem in ECOSYSTEM_MAP:
        return ECOSYSTEM_MAP[ecosystem]
    # Already an OSV ecosystem (e.g. "Debian:12", "Alpine:v3.18", "PyPI").
    if ecosystem in ECOSYSTEM_MAP.values() or ":" in ecosystem or ecosystem[:1].isupper():
        return ecosystem
    return None


def packages_from_inventory(assets: Iterable[Asset]) -> list[tuple[str, str]]:
    """Distinct (osv_ecosystem, name) pairs we can query OSV for."""
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for asset in assets:
        eco = to_osv_ecosystem(asset.ecosystem)
        if eco is None:
            continue
        key = (eco, asset.name)
        if key not in seen:
            seen.add(key)
            pairs.append(key)
    return pairs


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    # The agent proxy may terminate TLS; trust its CA bundle when present.
    if os.path.exists(_PROXY_CA_BUNDLE):
        try:
            ctx.load_verify_locations(_PROXY_CA_BUNDLE)
        except ssl.SSLError:
            pass
    return ctx


def _opener() -> urllib.request.OpenerDirector:
    # ProxyHandler() with no args reads HTTP(S)_PROXY from the environment.
    return urllib.request.build_opener(
        urllib.request.ProxyHandler(),
        urllib.request.HTTPSHandler(context=_ssl_context()),
    )


def _http_post(url: str, payload: dict, timeout: int = 20) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with _opener().open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_get(url: str, timeout: int = 20) -> dict:
    req = urllib.request.Request(url, method="GET")
    with _opener().open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _ranges_to_constraints(affected: dict) -> tuple[list[str], list[str]]:
    """Convert one OSV `affected` entry to (vulnerable_ranges, fixed_versions).

    OSV expresses ranges as ordered introduced/fixed/last_affected events.
    We turn each introduced..fixed window into a comma-joined constraint
    ("" / ">=X" and "<Y" or "<=Y") that our matcher understands.
    """
    constraints: list[str] = []
    fixed: list[str] = []
    for rng in affected.get("ranges", []):
        # GIT ranges are commit hashes, not versions; comparing them as
        # versions produces false matches and nonsense upgrade targets.
        if rng.get("type", "ECOSYSTEM") not in ("ECOSYSTEM", "SEMVER"):
            continue
        lower: Optional[str] = None
        for event in rng.get("events", []):
            if "introduced" in event:
                lower = event["introduced"]
            elif "fixed" in event:
                parts = []
                if lower and lower != "0":
                    parts.append(f">={lower}")
                parts.append(f"<{event['fixed']}")
                constraints.append(",".join(parts))
                fixed.append(event["fixed"])
                lower = None
            elif "last_affected" in event:
                parts = []
                if lower and lower != "0":
                    parts.append(f">={lower}")
                parts.append(f"<={event['last_affected']}")
                constraints.append(",".join(parts))
                lower = None
        if lower is not None:
            # An introduced with no closing event: everything from there on.
            constraints.append(f">={lower}" if lower != "0" else "")
    # Explicit affected versions: add any the ranges above don't already cover.
    # If every range was skipped (e.g. GIT-only), the version list is all we have.
    for version in affected.get("versions", []):
        eco = (affected.get("package") or {}).get("ecosystem")
        if not any(_in_range(version, c, eco) for c in constraints):
            constraints.append(f"=={version}")
    return constraints, fixed


def _resolve_severity(record: dict, cvss: Optional[float]) -> Severity:
    db = record.get("database_specific", {})
    word = str(db.get("severity", "")).upper()
    if word in _SEVERITY_WORDS:
        return _SEVERITY_WORDS[word]
    if cvss is not None:
        return Severity.from_cvss(cvss)
    return Severity.MEDIUM


def _best_cvss(record: dict) -> Optional[float]:
    for entry in record.get("severity", []):
        score = base_score(str(entry.get("score", "")))
        if score is not None:
            return score
    return None


def parse_osv_record(record: dict, queried_name: Optional[str] = None) -> Advisory:
    """Parse one OSV vulnerability record into an Advisory."""
    cvss = _best_cvss(record)
    affected_out: list[dict] = []
    ranges_out: list[str] = []
    fixed_out: list[str] = []
    for aff in record.get("affected", []):
        pkg = aff.get("package", {})
        name = pkg.get("name")
        # When querying a single package, keep only ranges for that package so
        # the flattened range list stays meaningful.
        if queried_name is not None and name is not None and name != queried_name:
            continue
        affected_out.append(
            {"ecosystem": from_osv_ecosystem(pkg.get("ecosystem")), "name": name}
        )
        ranges, fixed = _ranges_to_constraints(aff)
        ranges_out.extend(ranges)
        fixed_out.extend(fixed)

    published = None
    if record.get("published"):
        try:
            published = datetime.fromisoformat(record["published"].replace("Z", "+00:00"))
        except ValueError:
            # Older Pythons reject some valid RFC 3339 forms (e.g. nanoseconds);
            # a missing date shouldn't drop the advisory.
            published = None

    # Prefer a CVE alias as the id when present; it's what people recognize.
    vuln_id = record["id"]
    for alias in record.get("aliases", []):
        if alias.startswith("CVE-"):
            vuln_id = alias
            break

    return Advisory(
        id=vuln_id,
        title=record.get("summary", record["id"]),
        summary=record.get("details", record.get("summary", "")),
        severity=_resolve_severity(record, cvss),
        cvss=cvss,
        published=published,
        source="osv",
        affected=affected_out,
        # An "" entry means "all versions" (introduced:0 with no fix) and is
        # honored as a match-all constraint by the matcher.
        vulnerable_ranges=ranges_out,
        fixed_versions=sorted(set(fixed_out)),
        references=[r.get("url", "") for r in record.get("references", []) if r.get("url")],
    )


class OSVCache:
    """On-disk cache of full OSV records, keyed by vuln id.

    OSV records carry a `modified` timestamp. We store it alongside the record
    and treat a cached entry as valid only while the timestamp still matches
    what the batch query reports, so an updated advisory is re-fetched and
    anything unchanged is served from disk.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._data: dict[str, dict] = {}
        self._dirty = False
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def get(self, vuln_id: str, modified: Optional[str]) -> Optional[dict]:
        entry = self._data.get(vuln_id)
        if entry and (modified is None or entry.get("modified") == modified):
            return entry.get("record")
        return None

    def put(self, vuln_id: str, modified: Optional[str], record: dict) -> None:
        self._data[vuln_id] = {"modified": modified, "record": record}
        self._dirty = True

    def save(self) -> None:
        if not self._dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data))
        self._dirty = False


# Guard against a runaway pagination loop for a package with many advisories.
_MAX_PAGES = 50


class OSVFeed(Feed):
    """Query OSV for advisories affecting a fixed set of packages.

    Uses the batch endpoint (`/v1/querybatch`) to discover which advisories
    touch each package in a single round trip. That endpoint returns only
    `id` + `modified` per vuln, so full records are then fetched per id from
    `/v1/vulns/{id}` — served from the cache when the `modified` timestamp is
    unchanged. Set `batch=False` to fall back to per-package `/v1/query`
    (full records, one request each).
    """

    def __init__(
        self,
        packages: Iterable[tuple[str, str]],
        base_url: str = OSV_API,
        transport: Optional[PostTransport] = None,
        get_transport: Optional[GetTransport] = None,
        cache: Optional[OSVCache] = None,
        batch: bool = True,
    ):
        self.packages = list(packages)
        self.base_url = base_url.rstrip("/")
        self.cache = cache
        self.batch = batch
        self._post: PostTransport = transport or (lambda url, payload: _http_post(url, payload))
        self._get: GetTransport = get_transport or (lambda url: _http_get(url))

    def fetch(self) -> list[Advisory]:
        advisories = self._fetch_batch() if self.batch else self._fetch_single()
        if self.cache is not None:
            self.cache.save()
        return advisories

    # -- batch discovery + per-id detail (with caching) -------------------

    def _fetch_batch(self) -> list[Advisory]:
        if not self.packages:
            return []
        queries = [{"package": {"ecosystem": eco, "name": name}} for eco, name in self.packages]
        resp = self._post(f"{self.base_url}/v1/querybatch", {"queries": queries})
        results = resp.get("results", []) or []

        # Map each discovered vuln id -> (modified, the name we queried it under).
        discovered: dict[str, tuple[Optional[str], str]] = {}
        for (eco, name), result in zip(self.packages, results):
            for vuln in self._paged_vulns(eco, name, result):
                discovered.setdefault(vuln["id"], (vuln.get("modified"), name))

        advisories: dict[str, Advisory] = {}
        for vuln_id, (modified, name) in discovered.items():
            record = self._record(vuln_id, modified)
            advisory = parse_osv_record(record, queried_name=name)
            advisories.setdefault(advisory.id, advisory)
        return list(advisories.values())

    def _paged_vulns(self, eco: str, name: str, result: dict) -> list[dict]:
        """All (id, modified) vulns for one query, following pagination."""
        vulns = list(result.get("vulns", []) or [])
        token = result.get("next_page_token")
        pages = 0
        while token and pages < _MAX_PAGES:
            pages += 1
            page = self._post(
                f"{self.base_url}/v1/query",
                {"package": {"ecosystem": eco, "name": name}, "page_token": token},
            )
            vulns.extend(page.get("vulns", []) or [])
            token = page.get("next_page_token")
        return vulns

    def _record(self, vuln_id: str, modified: Optional[str]) -> dict:
        """Full OSV record for an id, from cache when the timestamp matches."""
        if self.cache is not None:
            cached = self.cache.get(vuln_id, modified)
            if cached is not None:
                return cached
        record = self._get(f"{self.base_url}/v1/vulns/{vuln_id}")
        if self.cache is not None:
            self.cache.put(vuln_id, record.get("modified", modified), record)
        return record

    # -- fallback: one full-record query per package ----------------------

    def _fetch_single(self) -> list[Advisory]:
        advisories: dict[str, Advisory] = {}
        for ecosystem, name in self.packages:
            resp = self._post(
                f"{self.base_url}/v1/query",
                {"package": {"ecosystem": ecosystem, "name": name}},
            )
            for record in resp.get("vulns", []) or []:
                # Full-record responses already carry `modified`; cache them too.
                if self.cache is not None and record.get("id"):
                    self.cache.put(record["id"], record.get("modified"), record)
                advisory = parse_osv_record(record, queried_name=name)
                advisories.setdefault(advisory.id, advisory)
        return list(advisories.values())
