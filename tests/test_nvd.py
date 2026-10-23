from urllib.parse import parse_qs, urlparse

import pytest

from fnh.httpclient import Response
from fnh.inventory import FileInventory
from fnh.matcher import Matcher
from fnh.models import Asset
from fnh.nvd import NVDError, NVDFeed, parse_cpe, parse_nvd_cve, products_from_inventory
from fnh.planner import Planner

# Trimmed from GET .../rest/json/cves/2.0?cveId=CVE-2021-23017
NGINX_RESOLVER = {
    "id": "CVE-2021-23017",
    "published": "2021-06-01T13:15:07.853",
    "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "en", "value": "A security issue in nginx resolver was "
                      "identified, which might allow an attacker to cause 1-byte memory "
                      "overwrite. More text."}],
    "metrics": {
        "cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
            "version": "3.1", "baseScore": 7.7, "baseSeverity": "HIGH",
            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:H"}}],
        "cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary",
                          "cvssData": {"version": "2.0", "baseScore": 6.8}, "baseSeverity": "MEDIUM"}],
    },
    "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
         "versionStartIncluding": "0.6.18", "versionEndExcluding": "1.20.1"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:f5:njs:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "0.5.3"},
    ]}]}],
    "references": [{"url": "http://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html"}],
}


def _assets():
    return [
        Asset("edge", "nginx", "binary", ecosystem="cpe", version="1.18.0", cpe="cpe:2.3:a:f5:nginx"),
        Asset("new", "nginx", "binary", ecosystem="cpe", version="1.21.0", cpe="f5:nginx"),
    ]


@pytest.mark.parametrize("cpe,expected", [
    ("cpe:2.3:a:f5:nginx", ("a", "f5", "nginx")),
    ("cpe:2.3:a:F5:NGINX:1.18.0:*:*:*:*:*:*:*", ("a", "f5", "nginx")),
    ("f5:nginx", ("a", "f5", "nginx")),
    (r"cpe:2.3:a:vendor:prod\:uct", ("a", "vendor", "prod:uct")),
    ("cpe:2.3:a:*:nginx", None),
    ("nonsense", None),
])
def test_parse_cpe(cpe, expected):
    assert parse_cpe(cpe) == expected


def test_parse_cve_builds_ranges_for_matching_product_only():
    adv = parse_nvd_cve(NGINX_RESOLVER, products_from_inventory(_assets()))
    assert adv.id == "CVE-2021-23017"
    assert adv.source == "nvd"
    assert adv.cvss == 7.7 and adv.severity.value == "high"  # v3.1 preferred over v2
    assert adv.affected == [{"ecosystem": "cpe", "name": "nginx",
                             "ranges": [">=0.6.18,<1.20.1"], "fixed": ["1.20.1"]}]
    assert adv.title.startswith("A security issue in nginx resolver")


def test_parse_cve_without_our_products_is_none():
    assert parse_nvd_cve(NGINX_RESOLVER, {}) is None


@pytest.mark.parametrize("match,constraint", [
    ({"versionStartExcluding": "1.0", "versionEndIncluding": "2.0"}, ">1.0,<=2.0"),
    ({"criteria": "cpe:2.3:a:f5:nginx:1.19.0:*:*:*:*:*:*:*"}, "==1.19.0"),
    ({"criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}, ""),
    ({"criteria": "cpe:2.3:a:f5:nginx:-:*:*:*:*:*:*:*"}, None),
])
def test_cpe_match_constraints(match, constraint):
    from fnh.nvd import _constraint
    assert _constraint(match) == constraint


def test_matches_and_plans():
    assets = _assets()
    adv = parse_nvd_cve(NGINX_RESOLVER, products_from_inventory(assets))
    matches = Matcher().match([adv], assets)
    assert [m.asset.id for m in matches] == ["edge"]
    plan = Planner().plan(matches[0])
    # A CPE-only asset has no package manager to drive: a human applies it.
    assert plan.target_version == "1.20.1" and plan.steps == [] and plan.confidence == 0.0


def test_negated_and_non_vulnerable_entries_are_ignored():
    cve = {"id": "CVE-X", "configurations": [{"nodes": [
        {"negate": True, "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:*"}]},
        {"cpeMatch": [{"vulnerable": False, "criteria": "cpe:2.3:a:f5:nginx:*"}]},
    ]}]}
    assert parse_nvd_cve(cve, products_from_inventory(_assets())) is None


def test_file_inventory_reads_cpe_and_defaults_ecosystem(tmp_path):
    p = tmp_path / "inv.json"
    p.write_text('[{"id": "fw", "name": "fortios", "version": "7.0.1", '
                 '"cpe": "cpe:2.3:o:fortinet:fortios"}]')
    (asset,) = FileInventory(p).assets()
    assert asset.ecosystem == "cpe" and asset.cpe == "cpe:2.3:o:fortinet:fortios"
    assert list(products_from_inventory([asset])) == [("o", "fortinet", "fortios")]


class FakeNVD:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, headers))
        return self.responses.pop(0)


def _page(cves, total, start=0):
    return Response(200, {"totalResults": total, "startIndex": start,
                          "vulnerabilities": [{"cve": c} for c in cves]})


def test_feed_pages_paces_requests_and_skips_rejected():
    rejected = {**NGINX_RESOLVER, "id": "CVE-R", "vulnStatus": "Rejected"}
    nvd = FakeNVD([_page([NGINX_RESOLVER], 2), _page([rejected], 2, start=1)])
    slept, now = [], [100.0]
    feed = NVDFeed(_assets(), api_key="", transport=nvd, sleep=slept.append,
                   clock=lambda: now[0])
    advisories = feed.fetch()
    assert [a.id for a in advisories] == ["CVE-2021-23017"]
    query = parse_qs(urlparse(nvd.calls[0][0]).query)
    assert query["virtualMatchString"] == ["cpe:2.3:a:f5:nginx"]
    assert query["resultsPerPage"] == ["2000"] and query["startIndex"] == ["0"]
    assert parse_qs(urlparse(nvd.calls[1][0]).query)["startIndex"] == ["1"]
    assert nvd.calls[0][1] == {}  # no key, no header
    assert slept == [6.0]  # second request waits for the no-key rate limit


def test_api_key_header_and_faster_pacing():
    nvd = FakeNVD([_page([], 0)])
    feed = NVDFeed(_assets(), api_key="k", transport=nvd, sleep=lambda s: None)
    feed.fetch()
    assert nvd.calls[0][1] == {"apiKey": "k"}
    assert feed._interval == 0.6


def test_retries_then_fails_with_hint():
    nvd = FakeNVD([Response(503, None)] * 4)
    feed = NVDFeed(_assets(), api_key="", transport=nvd, sleep=lambda s: None)
    with pytest.raises(NVDError, match="NVD_API_KEY"):
        feed.fetch()
    assert len(nvd.calls) == 4  # first try + 3 retries


def test_assets_without_cpe_are_not_queried():
    nvd = FakeNVD([])
    NVDFeed([Asset("a", "requests", "package", ecosystem="pypi", version="1")],
            transport=nvd).fetch()
    assert nvd.calls == []
