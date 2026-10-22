"""OSV feed — real advisories from https://osv.dev.

OSV is a free, no-auth vulnerability database that aggregates GHSA, PyPA,
RustSec, Debian, and more. This feed queries it per package and returns the
advisories affecting those packages, parsed into our `Advisory` model. Our
own `Matcher` then does the version-range matching against the inventory.

Network access goes through the stdlib (`urllib`) so the package keeps zero
third-party dependencies. The HTTP transport is injectable, so tests and
dry-runs never touch the network.

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
from typing import Callable, Iterable, Optional

from .cvss import base_score
from .feed import Feed
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

Transport = Callable[[str, dict], dict]

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


def _http_post(url: str, payload: dict, timeout: int = 20) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    # ProxyHandler() with no args reads HTTP(S)_PROXY from the environment.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler(),
        urllib.request.HTTPSHandler(context=_ssl_context()),
    )
    with opener.open(req, timeout=timeout) as resp:
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
    # Explicit affected versions (no ranges): each becomes its own ==constraint.
    for version in affected.get("versions", []):
        if not any(f"<{version}" in c or f"=={version}" in c for c in constraints):
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
        published = datetime.fromisoformat(record["published"].replace("Z", "+00:00"))

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


class OSVFeed(Feed):
    """Query OSV for advisories affecting a fixed set of packages."""

    def __init__(
        self,
        packages: Iterable[tuple[str, str]],
        base_url: str = OSV_API,
        transport: Optional[Transport] = None,
    ):
        self.packages = list(packages)
        self.base_url = base_url.rstrip("/")
        self._post: Transport = transport or (lambda url, payload: _http_post(url, payload))

    def fetch(self) -> list[Advisory]:
        advisories: dict[str, Advisory] = {}
        for ecosystem, name in self.packages:
            resp = self._post(
                f"{self.base_url}/v1/query",
                {"package": {"ecosystem": ecosystem, "name": name}},
            )
            for record in resp.get("vulns", []) or []:
                advisory = parse_osv_record(record, queried_name=name)
                # Dedupe across packages by advisory id; keep the first seen.
                advisories.setdefault(advisory.id, advisory)
        return list(advisories.values())
