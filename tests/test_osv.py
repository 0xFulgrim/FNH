from vulnpilot.cvss import base_score
from vulnpilot.matcher import Matcher
from vulnpilot.models import Asset
from vulnpilot.osv import (
    OSVFeed,
    packages_from_inventory,
    parse_osv_record,
    to_osv_ecosystem,
)

# A trimmed OSV record shaped like a real api.osv.dev response.
SAMPLE = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "aliases": ["CVE-2026-0001"],
    "summary": "requests leaks Authorization header on cross-host redirect",
    "details": "Full writeup here.",
    "published": "2026-10-01T00:00:00Z",
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.32.0"}],
                }
            ],
        }
    ],
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    ],
    "references": [{"type": "WEB", "url": "https://example.test/ghsa"}],
    "database_specific": {"severity": "HIGH"},
}


def test_cvss_known_vectors():
    # The canonical "all high, network, no privileges" vector scores 9.8.
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    # A low-impact local vector.
    assert base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N") == 1.8
    # v4 vectors are not scored here.
    assert base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N") is None
    assert base_score("") is None


def test_ecosystem_mapping():
    assert to_osv_ecosystem("pypi") == "PyPI"
    assert to_osv_ecosystem("npm") == "npm"
    assert to_osv_ecosystem("PyPI") == "PyPI"
    assert to_osv_ecosystem("Debian:12") == "Debian:12"
    assert to_osv_ecosystem("os") is None  # no generic mapping


def test_parse_osv_record():
    adv = parse_osv_record(SAMPLE, queried_name="requests")
    assert adv.id == "CVE-2026-0001"  # CVE alias preferred over GHSA id
    assert adv.source == "osv"
    assert adv.severity.value == "high"
    assert adv.cvss == 9.8
    assert adv.vulnerable_ranges == ["<2.32.0"]
    assert adv.fixed_versions == ["2.32.0"]
    assert adv.affected == [{"ecosystem": "pypi", "name": "requests"}]


def test_osv_feed_with_fake_transport_matches_inventory():
    calls = []

    def fake(url, payload):
        calls.append(payload)
        return {"vulns": [SAMPLE]}

    feed = OSVFeed([("PyPI", "requests")], transport=fake)
    advisories = feed.fetch()
    assert len(advisories) == 1
    assert calls == [{"package": {"ecosystem": "PyPI", "name": "requests"}}]

    asset = Asset("svc", "requests", "package", ecosystem="pypi", version="2.31.0")
    matches = Matcher().match(advisories, [asset])
    assert len(matches) == 1
    assert matches[0].advisory.id == "CVE-2026-0001"


def test_osv_feed_dedupes_across_packages():
    feed = OSVFeed(
        [("PyPI", "requests"), ("PyPI", "requests")],
        transport=lambda url, payload: {"vulns": [SAMPLE]},
    )
    assert len(feed.fetch()) == 1


def test_range_with_introduced_and_last_affected():
    rec = {
        "id": "OSV-1",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pkg"},
                "ranges": [
                    {
                        "events": [
                            {"introduced": "1.24.0"},
                            {"last_affected": "1.27.2"},
                        ]
                    }
                ],
            }
        ],
    }
    adv = parse_osv_record(rec, queried_name="pkg")
    assert adv.vulnerable_ranges == [">=1.24.0,<=1.27.2"]


def test_packages_from_inventory_skips_unmappable():
    assets = [
        Asset("a", "requests", "package", ecosystem="pypi", version="2.31.0"),
        Asset("b", "nginx", "package", ecosystem="os", version="1.26.0"),
        Asset("c", "lodash", "package", ecosystem="npm", version="4.17.20"),
    ]
    pairs = packages_from_inventory(assets)
    assert ("PyPI", "requests") in pairs
    assert ("npm", "lodash") in pairs
    assert all(eco != "os" for eco, _ in pairs)  # os skipped
