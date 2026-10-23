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

Each affected package keeps its own ranges and fixed versions, so one record
covering several packages matches each of them correctly.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Optional

from .cvss import base_score
from .feed import Feed
from .httpclient import get_json, post_json
from .matcher import _in_range
from .models import Advisory, Asset, Severity

OSV_API = "https://api.osv.dev"

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
    label = Severity.from_label(record.get("database_specific", {}).get("severity"))
    if label is not None:
        return label
    if cvss is not None:
        return Severity.from_cvss(cvss)
    return Severity.MEDIUM


def _best_cvss(record: dict) -> Optional[float]:
    for entry in record.get("severity", []):
        score = base_score(str(entry.get("score", "")))
        if score is not None:
            return score
    return None


def parse_osv_record(record: dict) -> Advisory:
    """Parse one OSV vulnerability record into an Advisory."""
    cvss = _best_cvss(record)
    affected_out: list[dict] = []
    ranges_out: list[str] = []
    fixed_out: list[str] = []
    for aff in record.get("affected", []):
        pkg = aff.get("package", {})
        ranges, fixed = _ranges_to_constraints(aff)
        affected_out.append({
            "ecosystem": from_osv_ecosystem(pkg.get("ecosystem")),
            "name": pkg.get("name"),
            "ranges": ranges,
            "fixed": fixed,
        })
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
        # Matching uses the per-package lists above; these are the union, kept
        # for reporting. An "" range means "all versions".
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
# OSV rejects /v1/querybatch requests with more than 1000 queries.
_BATCH_LIMIT = 1000
# Concurrent /v1/vulns/{id} fetches. They're small, independent and I/O bound.
_FETCH_WORKERS = 8


class OSVFeed(Feed):
    """Query OSV for advisories affecting a fixed set of packages.

    Uses the batch endpoint (`/v1/querybatch`) to discover which advisories
    touch each package. That endpoint returns only `id` + `modified` per vuln,
    so full records are then fetched from `/v1/vulns/{id}` in parallel, served
    from the cache when the `modified` timestamp is unchanged. Set
    `batch=False` to fall back to one `/v1/query` per package (full records).
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
        self._post: PostTransport = transport or post_json
        self._get: GetTransport = get_transport or get_json

    def fetch(self) -> list[Advisory]:
        records = self._fetch_batch() if self.batch else self._fetch_single()
        if self.cache is not None:
            self.cache.save()
        return [parse_osv_record(r) for r in records]

    # -- batch discovery + per-id detail (with caching) -------------------

    def _fetch_batch(self) -> list[dict]:
        # vuln id -> modified timestamp, across every package queried.
        discovered: dict[str, Optional[str]] = {}
        for start in range(0, len(self.packages), _BATCH_LIMIT):
            chunk = self.packages[start:start + _BATCH_LIMIT]
            queries = [{"package": {"ecosystem": eco, "name": name}} for eco, name in chunk]
            resp = self._post(f"{self.base_url}/v1/querybatch", {"queries": queries})
            for (eco, name), result in zip(chunk, resp.get("results", []) or []):
                for vuln in self._paged_vulns(eco, name, result):
                    discovered.setdefault(vuln["id"], vuln.get("modified"))

        records: dict[str, dict] = {}
        missing = []
        for vuln_id, modified in discovered.items():
            cached = self.cache.get(vuln_id, modified) if self.cache is not None else None
            if cached is not None:
                records[vuln_id] = cached
            else:
                missing.append(vuln_id)

        if missing:
            with ThreadPoolExecutor(max_workers=min(_FETCH_WORKERS, len(missing))) as pool:
                fetched = pool.map(
                    lambda vid: self._get(f"{self.base_url}/v1/vulns/{vid}"), missing
                )
                for vuln_id, record in zip(missing, fetched):
                    records[vuln_id] = record
                    if self.cache is not None:
                        self.cache.put(vuln_id, record.get("modified", discovered[vuln_id]), record)
        # Keep discovery order so output is stable between runs.
        return [records[vid] for vid in discovered]

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

    # -- fallback: one full-record query per package ----------------------

    def _fetch_single(self) -> list[dict]:
        records: dict[str, dict] = {}
        for ecosystem, name in self.packages:
            resp = self._post(
                f"{self.base_url}/v1/query",
                {"package": {"ecosystem": ecosystem, "name": name}},
            )
            for record in resp.get("vulns", []) or []:
                if record.get("id") in records:
                    continue
                records[record["id"]] = record
                if self.cache is not None:
                    self.cache.put(record["id"], record.get("modified"), record)
        return list(records.values())
