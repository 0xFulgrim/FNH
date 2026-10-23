from fnh.cvss import base_score
from fnh.matcher import Matcher
from fnh.models import Asset
from fnh.osv import (
    OSVCache,
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
    adv = parse_osv_record(SAMPLE)
    assert adv.id == "CVE-2026-0001"  # CVE alias preferred over GHSA id
    assert adv.source == "osv"
    assert adv.severity.value == "high"
    assert adv.cvss == 9.8
    assert adv.vulnerable_ranges == ["<2.32.0"]
    assert adv.fixed_versions == ["2.32.0"]
    assert adv.affected == [{"ecosystem": "pypi", "name": "requests",
                             "ranges": ["<2.32.0"], "fixed": ["2.32.0"]}]


def _batch_transports(record=SAMPLE, modified="2026-10-01T00:00:00Z"):
    """Fake POST (batch discovery) + GET (detail) transports for one vuln."""
    posts, gets = [], []

    def post(url, payload):
        posts.append((url, payload))
        return {"results": [{"vulns": [{"id": record["id"], "modified": modified}]}]}

    def get(url):
        gets.append(url)
        return record

    return post, get, posts, gets


def test_osv_feed_batch_matches_inventory():
    post, get, posts, gets = _batch_transports()
    feed = OSVFeed([("PyPI", "requests")], transport=post, get_transport=get)
    advisories = feed.fetch()

    assert len(advisories) == 1
    # One batch POST to querybatch, then one detail GET for the vuln.
    assert posts[0][0].endswith("/v1/querybatch")
    assert posts[0][1] == {"queries": [{"package": {"ecosystem": "PyPI", "name": "requests"}}]}
    assert gets == ["https://api.osv.dev/v1/vulns/GHSA-xxxx-yyyy-zzzz"]

    asset = Asset("svc", "requests", "package", ecosystem="pypi", version="2.31.0")
    matches = Matcher().match(advisories, [asset])
    assert len(matches) == 1
    assert matches[0].advisory.id == "CVE-2026-0001"


def test_osv_feed_single_mode():
    feed = OSVFeed(
        [("PyPI", "requests")],
        transport=lambda url, payload: {"vulns": [SAMPLE]},
        batch=False,
    )
    advisories = feed.fetch()
    assert len(advisories) == 1
    assert advisories[0].id == "CVE-2026-0001"


def test_osv_feed_follows_pagination():
    def post(url, payload):
        if url.endswith("/v1/querybatch"):
            return {"results": [{"vulns": [{"id": "OSV-1", "modified": "m1"}],
                                 "next_page_token": "tok"}]}
        # Continuation page via /v1/query with the page token.
        assert payload.get("page_token") == "tok"
        return {"vulns": [{"id": "OSV-2", "modified": "m2"}]}

    got = []

    def get(url):
        got.append(url)
        return {"id": url.rsplit("/", 1)[-1], "affected": []}

    feed = OSVFeed([("PyPI", "pkg")], transport=post, get_transport=get)
    advisories = feed.fetch()
    assert {a.id for a in advisories} == {"OSV-1", "OSV-2"}
    assert len(got) == 2


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
    adv = parse_osv_record(rec)
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


def test_cache_avoids_refetch_when_unchanged(tmp_path):
    cache = OSVCache(tmp_path / "osv-cache.json")
    detail_calls = []

    def post(url, payload):
        return {"results": [{"vulns": [{"id": SAMPLE["id"], "modified": "2026-10-01T00:00:00Z"}]}]}

    def get(url):
        detail_calls.append(url)
        return SAMPLE

    # First run: cache miss -> one detail fetch, then persisted to disk.
    OSVFeed([("PyPI", "requests")], transport=post, get_transport=get, cache=cache).fetch()
    assert len(detail_calls) == 1
    assert (tmp_path / "osv-cache.json").exists()

    # Second run with a fresh cache object reading the same file: no detail GET.
    cache2 = OSVCache(tmp_path / "osv-cache.json")
    OSVFeed([("PyPI", "requests")], transport=post, get_transport=get, cache=cache2).fetch()
    assert len(detail_calls) == 1  # unchanged


def test_cache_refetches_when_modified_changes(tmp_path):
    cache = OSVCache(tmp_path / "osv-cache.json")
    detail_calls = []

    def make_post(modified):
        return lambda url, payload: {
            "results": [{"vulns": [{"id": SAMPLE["id"], "modified": modified}]}]
        }

    def get(url):
        detail_calls.append(url)
        return dict(SAMPLE, modified="new")

    OSVFeed([("PyPI", "requests")], transport=make_post("v1"), get_transport=get, cache=cache).fetch()
    assert len(detail_calls) == 1

    # The advisory was updated upstream (new modified) -> cache invalidated.
    cache2 = OSVCache(tmp_path / "osv-cache.json")
    OSVFeed([("PyPI", "requests")], transport=make_post("v2"), get_transport=get, cache=cache2).fetch()
    assert len(detail_calls) == 2


def test_cache_tolerates_corrupt_file(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    cache = OSVCache(p)  # must not raise
    assert cache.get("anything", None) is None
