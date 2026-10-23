from urllib.parse import parse_qs, urlparse

import pytest

from fnh.ghsa import GHSAError, GHSAFeed, packages_from_inventory, parse_ghsa_advisory
from fnh.httpclient import Response
from fnh.matcher import Matcher
from fnh.models import Asset
from fnh.planner import Planner

# Trimmed from GET https://api.github.com/advisories?ghsa_id=GHSA-jfh8-c2jp-5v3q
LOG4SHELL = {
    "ghsa_id": "GHSA-jfh8-c2jp-5v3q",
    "cve_id": "CVE-2021-44228",
    "html_url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
    "summary": "Remote code injection in Log4j",
    "description": "Apache Log4j2 JNDI features ...",
    "type": "reviewed",
    "severity": "critical",
    "published_at": "2021-12-10T00:40:56Z",
    "withdrawn_at": None,
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    "vulnerabilities": [
        {"package": {"ecosystem": "maven", "name": "org.apache.logging.log4j:log4j-core"},
         "vulnerable_version_range": ">= 2.13.0, < 2.15.0", "first_patched_version": "2.15.0"},
        {"package": {"ecosystem": "maven", "name": "org.apache.logging.log4j:log4j-core"},
         "vulnerable_version_range": ">= 2.0-beta9, < 2.3.1", "first_patched_version": "2.3.1"},
    ],
    "cvss": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "score": 10.0},
}

LODASH = {
    "ghsa_id": "GHSA-35jh-r3h4-6jhm", "cve_id": "CVE-2021-23337",
    "summary": "Command Injection in lodash", "severity": "high",
    "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "lodash"},
                         "vulnerable_version_range": "< 4.17.21",
                         "first_patched_version": {"identifier": "4.17.21"}}],
}


def test_parse_advisory_merges_rows_per_package():
    adv = parse_ghsa_advisory(LOG4SHELL)
    assert adv.id == "CVE-2021-44228"
    assert adv.source == "ghsa"
    assert adv.severity.value == "critical"
    assert adv.cvss == 10.0
    (entry,) = adv.affected
    assert entry["ecosystem"] == "maven"
    assert entry["ranges"] == [">=2.13.0,<2.15.0", ">=2.0-beta9,<2.3.1"]
    assert entry["fixed"] == ["2.15.0", "2.3.1"]
    assert adv.references[0] == LOG4SHELL["html_url"]


def test_parse_handles_nested_first_patched_and_maps_ecosystem():
    adv = parse_ghsa_advisory(LODASH)
    assert adv.affected == [{"ecosystem": "npm", "name": "lodash",
                             "ranges": ["<4.17.21"], "fixed": ["4.17.21"]}]
    pip = parse_ghsa_advisory({"ghsa_id": "GHSA-x", "severity": "moderate", "vulnerabilities": [
        {"package": {"ecosystem": "pip", "name": "requests"},
         "vulnerable_version_range": "< 2.32.0", "first_patched_version": "2.32.0"}]})
    assert pip.id == "GHSA-x" and pip.severity.value == "medium"
    assert pip.affected[0]["ecosystem"] == "pypi"


def test_matches_and_plans_against_inventory():
    advisories = [parse_ghsa_advisory(LOG4SHELL), parse_ghsa_advisory(LODASH)]
    assets = [
        Asset("api", "org.apache.logging.log4j:log4j-core", "package", ecosystem="maven", version="2.14.1"),
        Asset("old", "org.apache.logging.log4j:log4j-core", "package", ecosystem="maven", version="2.2"),
        Asset("ok", "org.apache.logging.log4j:log4j-core", "package", ecosystem="maven", version="2.17.1"),
        Asset("web", "lodash", "package", ecosystem="npm", version="4.17.20"),
    ]
    matches = {m.asset.id: m for m in Matcher().match(advisories, assets)}
    assert set(matches) == {"api", "old", "web"}
    assert Planner().plan(matches["old"]).target_version == "2.3.1"
    assert Planner().plan(matches["web"]).target_version == "4.17.21"


def test_packages_from_inventory():
    assets = [Asset("a", "requests", "package", ecosystem="pypi"),
              Asset("b", "requests", "package", ecosystem="pypi"),
              Asset("c", "nginx", "package", ecosystem="Debian:12")]
    assert packages_from_inventory(assets) == [("pip", "requests")]


class FakeGitHub:
    def __init__(self, pages):
        self.pages = pages  # list of (data, headers) per call
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, headers))
        data, resp_headers = self.pages[len(self.calls) - 1]
        return Response(200, data, resp_headers)


def test_feed_queries_by_ecosystem_follows_pages_and_skips_withdrawn():
    withdrawn = {**LODASH, "ghsa_id": "GHSA-gone", "withdrawn_at": "2022-01-01T00:00:00Z"}
    gh = FakeGitHub([
        ([LODASH], {"link": '<https://api.github.com/advisories?after=abc>; rel="next"'}),
        ([withdrawn, LODASH], {}),
    ])
    feed = GHSAFeed([("npm", "lodash"), ("npm", "@babel/core")], token="t", transport=gh)
    advisories = feed.fetch()
    assert [a.id for a in advisories] == ["CVE-2021-23337"]
    first_url, headers = gh.calls[0]
    query = parse_qs(urlparse(first_url).query)
    assert query["ecosystem"] == ["npm"] and query["type"] == ["reviewed"]
    assert query["affects"] == ["lodash,@babel/core"]
    assert headers["Authorization"] == "Bearer t"
    assert gh.calls[1][0] == "https://api.github.com/advisories?after=abc"


def test_feed_chunks_large_package_lists():
    calls = []

    def transport(url, headers):
        calls.append(parse_qs(urlparse(url).query)["affects"][0].count(",") + 1)
        return Response(200, [], {})

    GHSAFeed([("npm", f"p{i}") for i in range(250)], token="", transport=transport).fetch()
    assert calls == [100, 100, 50]


def test_rate_limit_waits_once_then_errors_with_hint():
    slept = []
    responses = iter([
        Response(403, {"message": "API rate limit exceeded"}, {"retry-after": "2"}),
        Response(403, {"message": "API rate limit exceeded"}, {"retry-after": "2"}),
    ])
    feed = GHSAFeed([("npm", "x")], token="", transport=lambda u, h: next(responses),
                    sleep=slept.append)
    with pytest.raises(GHSAError, match="GITHUB_TOKEN"):
        feed.fetch()
    assert slept == [2.0]
