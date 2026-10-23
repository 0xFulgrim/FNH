"""Regression tests for bugs found in the repo review."""

import json
import shlex

import pytest

from fnh.__main__ import main
from fnh.executor import (
    CommandResult,
    DefaultValidator,
    DryRunner,
    Executor,
    VersionValidator,
)
from fnh.feed import Feed
from fnh.inventory import Inventory
from fnh.matcher import Matcher
from fnh.models import Advisory, Asset, Match, Remediation, RemediationKind, Severity
from fnh.osv import parse_osv_record
from fnh.pipeline import Pipeline
from fnh.planner import MitigationLibrary, Planner
from fnh.promote import FilePromoter
from fnh.safety import SafetyPolicy


class _Feed(Feed):
    def __init__(self, advisories):
        self._a = advisories

    def fetch(self):
        return self._a


class _Inv(Inventory):
    def __init__(self, assets):
        self._a = assets

    def assets(self):
        return self._a


def _validator():
    return DefaultValidator()


def _match(eco="pypi", name="requests", version="2.31.0", fixed=("2.32.0",), env="staging"):
    adv = Advisory("CVE-1", "t", "s", Severity.HIGH,
                   affected=[{"ecosystem": eco, "name": name}],
                   vulnerable_ranges=["<99"], fixed_versions=list(fixed))
    return Match(adv, Asset("a", name, "package", ecosystem=eco, version=version,
                            environment=env), "r")


# -- promotion must not bypass the plan checks ------------------------------

def test_promotion_path_enforces_plan_checks(tmp_path):
    lib = tmp_path / "m.json"
    lib.write_text(json.dumps({"CVE-X": {"steps": ["rm -rf / --no-preserve-root"],
                                         "confidence": 0.1}}))
    adv = Advisory("CVE-X", "t", "s", Severity.LOW,
                   affected=[{"ecosystem": "pypi", "name": "p"}])
    asset = Asset("p", "p", "package", ecosystem="pypi", version="1", environment="production")
    runner = DryRunner()
    pipeline = Pipeline(
        _Feed([adv]), _Inv([asset]), Planner(MitigationLibrary(lib)),
        Executor(runner, _validator()), SafetyPolicy(),
        promoter=FilePromoter(tmp_path / "promos"),
    )
    out = pipeline.run()[0]
    assert out.status.value == "needs_review"
    assert runner.log == []  # nothing was sent to staging
    assert FilePromoter(tmp_path / "promos").requests() == []


# -- OSV GIT ranges ----------------------------------------------------------

def test_osv_git_ranges_are_not_compared_as_versions():
    rec = {"id": "OSV-G", "affected": [{
        "package": {"ecosystem": "PyPI", "name": "pkg"},
        "ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "5f3a9c1"}]}],
        "versions": ["1.0.0", "1.0.1"],
    }]}
    adv = parse_osv_record(rec)
    assert adv.fixed_versions == []
    assert adv.vulnerable_ranges == ["==1.0.0", "==1.0.1"]
    asset = Asset("x", "pkg", "package", ecosystem="pypi", version="2.0")
    assert Matcher().match([adv], [asset]) == []


def test_osv_explicit_version_outside_ranges_is_kept():
    rec = {"id": "OSV-V", "affected": [{
        "package": {"ecosystem": "PyPI", "name": "pkg"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "1.5"}, {"fixed": "1.20"}]}],
        "versions": ["1.2"],
    }]}
    adv = parse_osv_record(rec)
    assert "==1.2" in adv.vulnerable_ranges


def test_osv_unparseable_published_date_does_not_drop_record():
    rec = {"id": "OSV-D", "published": "not-a-date", "affected": []}
    assert parse_osv_record(rec).published is None


# -- planner commands ---------------------------------------------------------

def test_patch_steps_quote_feed_supplied_versions():
    evil = "2.0'; touch /tmp/pwned; echo '"
    rem = Planner().plan(_match(version="1.0", fixed=(evil,)))
    (step,) = rem.steps
    # The whole requirement is one shell word: no command separator escapes.
    assert shlex.split(step)[-1] == f"requests=={evil}"


def test_patch_rollback_reinstalls_previous_version():
    rem = Planner().plan(_match())
    assert rem.rollback == ["python3 -m pip install requests==2.31.0"]


def test_debian_asset_gets_pinned_apt_upgrade_and_downgrade_rollback():
    rem = Planner().plan(_match(eco="Debian:12", name="nginx", version="1.22.1-9",
                                fixed=("1.22.1-9+deb12u1",)))
    assert rem.steps == ["apt-get install -y --only-upgrade nginx=1.22.1-9+deb12u1"]
    assert rem.rollback == ["apt-get install -y --allow-downgrades nginx=1.22.1-9"]
    assert rem.confidence == 0.9


def test_unknown_ecosystem_patch_is_not_automated():
    m = _match(eco="maven", name="log4j-core", version="2.14.0", fixed=("2.17.1",))
    rem = Planner().plan(m)
    assert rem.steps == []
    assert rem.confidence == 0.0
    allowed, _ = SafetyPolicy().may_act_automatically(m, rem)
    assert not allowed


# -- validation ----------------------------------------------------------------

def test_dry_run_validates_against_planned_target():
    m = _match(version="2.0", fixed=("1.2.5", "2.3.1"))
    rem = Planner().plan(m)
    assert rem.target_version == "2.3.1"
    assert VersionValidator().is_closed(m, rem, DryRunner())


class _Runner:
    def __init__(self, stdout, rc=0):
        self.stdout, self.rc, self.ran = stdout, rc, []

    def run(self, command):
        self.ran.append(command)
        return CommandResult(command, self.rc, stdout=self.stdout)


def test_version_validator_reads_npm_versions():
    m = _match(eco="npm", name="lodash", version="4.17.20", fixed=("4.17.21",))
    rem = Planner().plan(m)
    runner = _Runner(json.dumps({"dependencies": {"lodash": {"version": "4.17.21"}}}))
    assert VersionValidator().is_closed(m, rem, runner)


def test_version_validator_reads_dpkg_versions():
    m = _match(eco="Debian:12", name="nginx", version="1.22.1", fixed=("1.22.2",))
    rem = Planner().plan(m)
    assert VersionValidator().is_closed(m, rem, _Runner("1.22.2"))
    assert not VersionValidator().is_closed(m, rem, _Runner("1.22.1"))
    assert not VersionValidator().is_closed(m, rem, _Runner("", rc=1))


# -- production runner ---------------------------------------------------------

def _prod_pipeline(production_runner):
    adv = Advisory("CVE-P", "t", "s", Severity.CRITICAL,
                   affected=[{"ecosystem": "pypi", "name": "requests"}],
                   vulnerable_ranges=["<2.32.0"], fixed_versions=["2.32.0"])
    asset = Asset("prod", "requests", "package", ecosystem="pypi",
                  version="2.31.0", environment="production")
    policy = SafetyPolicy()
    policy.autonomous_environments.add("production")
    policy.require_human_approval_for_production = False
    staging = DryRunner()
    executor = Executor(staging, _validator(), production_runner=production_runner)
    return Pipeline(_Feed([adv]), _Inv([asset]), Planner(), executor, policy), staging


def test_production_changes_never_run_on_staging_runner():
    pipeline, staging = _prod_pipeline(production_runner=None)
    out = pipeline.run()[0]
    assert out.status.value == "needs_review"
    assert staging.log == []


def test_production_changes_use_production_runner():
    prod = DryRunner()
    pipeline, staging = _prod_pipeline(production_runner=prod)
    out = pipeline.run()[0]
    assert out.status.value == "patched"
    assert staging.log == []
    assert prod.log == ["python3 -m pip install requests==2.32.0"]


def test_cli_allow_production_requires_prod_host():
    with pytest.raises(SystemExit, match="--prod-host"):
        main(["run", "--dry-run", "--allow-production"])


# -- promotion ids -------------------------------------------------------------

def test_promotion_ids_cannot_escape_directory(tmp_path):
    with pytest.raises(ValueError):
        FilePromoter(tmp_path).load("../../etc/passwd")
    assert main(["promote", "--promote-dir", str(tmp_path), "--apply", "../x"]) == 2


def test_executor_refuses_remediation_without_steps():
    m = _match()
    rem = Remediation(RemediationKind.PATCH, "manual", target_version="2.32.0", confidence=1.0)
    closed, notes = Executor(DryRunner(), _validator()).apply_and_validate(m, rem)
    assert not closed
    assert "no automated steps" in notes[0]


# -- Debian version ordering ---------------------------------------------------

@pytest.mark.parametrize("a,b,expected", [
    ("1.22.1-9", "1.22.1-9+deb12u1", -1),   # security revision bump
    ("1:2.0", "3.0", 1),                    # epoch wins
    ("1.0~rc1", "1.0", -1),                 # tilde sorts before release
    ("1.0", "1.0-1", -1),                   # missing revision sorts first
    ("2.36-9+deb12u4", "2.36-9+deb12u10", -1),
    ("1.2.3", "1.2.3", 0),
])
def test_dpkg_version_ordering(a, b, expected):
    from fnh.matcher import _cmp
    assert _cmp(a, b, "Debian:12") == expected
    assert _cmp(b, a, "Debian:12") == -expected


def test_debian_revision_fix_is_detected_and_planned():
    adv = Advisory("CVE-D", "t", "s", Severity.HIGH,
                   affected=[{"ecosystem": "Debian:12", "name": "nginx"}],
                   vulnerable_ranges=["<1.22.1-9+deb12u1"],
                   fixed_versions=["1.22.1-9+deb12u1"])
    asset = Asset("n", "nginx", "package", ecosystem="Debian:12", version="1.22.1-9")
    (match,) = Matcher().match([adv], [asset])
    assert Planner().plan(match).target_version == "1.22.1-9+deb12u1"


def test_non_debian_comparison_unchanged():
    from fnh.matcher import _cmp
    assert _cmp("2.31.0", "2.32.0", "pypi") == -1
    assert _cmp("10.0", "9.0", "npm") == 1


# -- PEP 440 / SemVer pre-releases ------------------------------------------

@pytest.mark.parametrize("a,b,expected", [
    ("1.0rc1", "1.0", -1),
    ("1.0.dev0", "1.0a1", -1),
    ("1.0a1", "1.0b1", -1),
    ("1.0", "1.0.post1", -1),
    ("1.0.post1.dev0", "1.0.post1", -1),
    ("1!1.0", "2.0", 1),
    ("1.0", "1.0.0", 0),
    ("1.0+local", "1.0", 1),
    ("2.32.0rc1", "2.32.0", -1),
])
def test_pep440_ordering(a, b, expected):
    from fnh.matcher import _cmp
    assert _cmp(a, b, "pypi") == expected
    assert _cmp(b, a, "pypi") == -expected


@pytest.mark.parametrize("a,b,expected", [
    ("1.0.0-alpha", "1.0.0-alpha.1", -1),
    ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1),
    ("1.0.0-beta.2", "1.0.0-beta.11", -1),
    ("1.0.0-rc.1", "1.0.0", -1),
    ("1.0.0+build.1", "1.0.0", 0),
    ("v1.2.3", "1.2.3", 0),
    ("4.17.21", "4.17.20", 1),
])
def test_semver_ordering(a, b, expected):
    from fnh.matcher import _cmp
    assert _cmp(a, b, "npm") == expected
    assert _cmp(b, a, "npm") == -expected


def test_installed_prerelease_below_fix_is_vulnerable():
    adv = Advisory("CVE-R", "t", "s", Severity.HIGH,
                   affected=[{"ecosystem": "pypi", "name": "requests"}],
                   vulnerable_ranges=["<2.32.0"], fixed_versions=["2.32.0"])
    asset = Asset("r", "requests", "package", ecosystem="pypi", version="2.32.0rc1")
    (match,) = Matcher().match([adv], [asset])
    assert Planner().plan(match).target_version == "2.32.0"


def test_unparseable_versions_fall_back_to_numeric():
    from fnh.matcher import _cmp
    assert _cmp("not a version 2", "1.0", "pypi") == -1
    assert _cmp("1.2.x", "1.2.0", "npm") == 0


# -- multi-package and duplicate OSV records ----------------------------------

def _osv_record(osv_id, cve, packages, modified="m"):
    return {"id": osv_id, "aliases": [cve], "modified": modified, "affected": [
        {"package": {"ecosystem": eco, "name": name},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fix}]}]}
        for eco, name, fix in packages
    ]}


def _osv_feed(records, packages):
    from fnh.osv import OSVFeed
    by_id = {r["id"]: r for r in records}

    def post(url, payload):
        results = []
        for q in payload["queries"]:
            pkg = q["package"]
            results.append({"vulns": [
                {"id": r["id"], "modified": r["modified"]} for r in records
                if any(a["package"] == pkg for a in r["affected"])
            ]})
        return {"results": results}

    return OSVFeed(packages, transport=post, get_transport=lambda url: by_id[url.rsplit("/", 1)[1]])


def test_osv_advisory_covering_two_packages_matches_both():
    rec = _osv_record("GHSA-1", "CVE-M", [("PyPI", "urllib3", "2.0.0"), ("PyPI", "requests", "2.32.0")])
    advisories = _osv_feed([rec], [("PyPI", "urllib3"), ("PyPI", "requests")]).fetch()
    assets = [Asset("u", "urllib3", "package", ecosystem="pypi", version="1.26.0"),
              Asset("r", "requests", "package", ecosystem="pypi", version="2.31.0")]
    matches = Matcher().match(advisories, assets)
    targets = {m.asset.name: Planner().plan(m).target_version for m in matches}
    assert targets == {"urllib3": "2.0.0", "requests": "2.32.0"}


def test_same_cve_from_two_databases_matches_both_packages():
    pypi = _osv_record("PYSEC-1", "CVE-D", [("PyPI", "lib", "2.0")])
    deb = _osv_record("DSA-1", "CVE-D", [("Debian:12", "python3-lib", "2.0-1")])
    advisories = _osv_feed([pypi, deb], [("PyPI", "lib"), ("Debian:12", "python3-lib")]).fetch()
    assets = [Asset("a", "lib", "package", ecosystem="pypi", version="1.0"),
              Asset("b", "python3-lib", "package", ecosystem="Debian:12", version="1.0-1")]
    assert {m.asset.id for m in Matcher().match(advisories, assets)} == {"a", "b"}


def test_duplicate_records_for_one_package_match_once():
    ghsa = _osv_record("GHSA-2", "CVE-X", [("PyPI", "lib", "2.0")])
    pysec = _osv_record("PYSEC-2", "CVE-X", [("PyPI", "lib", "2.0")])
    advisories = _osv_feed([ghsa, pysec], [("PyPI", "lib")]).fetch()
    asset = Asset("a", "lib", "package", ecosystem="pypi", version="1.0")
    assert len(Matcher().match(advisories, [asset])) == 1


def test_querybatch_is_split_at_osv_limit():
    from fnh.osv import OSVFeed
    sizes = []

    def post(url, payload):
        sizes.append(len(payload["queries"]))
        return {"results": [{} for _ in payload["queries"]]}

    OSVFeed([("PyPI", f"p{i}") for i in range(2500)], transport=post).fetch()
    assert sizes == [1000, 1000, 500]


# -- safety and recommendations -------------------------------------------------

@pytest.mark.parametrize("field", ["rollback", "verify"])
def test_forbidden_tokens_checked_in_rollback_and_verify(field):
    m = _match()
    rem = Remediation(RemediationKind.MITIGATION, "x", steps=["true"], confidence=1.0)
    setattr(rem, field, ["rm -rf /"] if field == "rollback" else "rm -rf /")
    allowed, reason = SafetyPolicy().check_plan(m, rem)
    assert not allowed and "forbidden" in reason


def test_held_patch_does_not_claim_failed_validation():
    from fnh.recommend import recommendations_for
    m = _match()
    rem = Planner().plan(m)
    recs = recommendations_for(m, rem, False, "severity low below auto threshold")
    assert not any("did not validate" in r for r in recs)


def test_direct_production_patch_is_not_told_to_promote():
    prod = DryRunner()
    pipeline, _ = _prod_pipeline(production_runner=prod)
    out = pipeline.run()[0]
    assert out.status.value == "patched"
    assert not any("promote" in r.lower() for r in out.recommendations)


def test_bad_probe_spec_fails_when_library_loads(tmp_path):
    lib = tmp_path / "m.json"
    lib.write_text(json.dumps({"CVE-B": {"steps": ["x"], "verify": {"probe": "nope"}}}))
    with pytest.raises(ValueError, match="CVE-B"):
        MitigationLibrary(lib)


# -- runners and inventory -------------------------------------------------------

def test_shell_runner_timeout_is_a_failed_result():
    from fnh.executor import ShellRunner
    result = ShellRunner(timeout=1).run("sleep 5")
    assert result.returncode == 124 and not result.ok


def test_live_inventory_collects_once():
    from fnh.inventory import LiveInventory, PipCollector
    runner = _Runner(json.dumps([{"name": "requests", "version": "2.31.0"}]))
    inv = LiveInventory(runner, [PipCollector()])
    assert inv.assets() == inv.assets()
    assert len(runner.ran) == 1


# -- promotion -----------------------------------------------------------------

def _patch_request(**kw):
    from fnh.promote import PromotionRequest
    return PromotionRequest(
        "CVE-1", "a", "production", "Upgrade requests to 2.32.0",
        steps=["python3 -m pip install requests==2.32.0"],
        rollback=["python3 -m pip install requests==2.31.0"],
        ecosystem="pypi", package="requests", target_version="2.32.0",
        approved=True, **kw,
    )


def test_promoted_patch_is_verified_by_installed_version():
    from fnh.promote import apply_promotion
    req = _patch_request()
    ok, _ = apply_promotion(req, _Runner("2.32.0"))
    assert ok and req.result == "applied"

    req = _patch_request()
    runner = _Runner("2.31.0")
    ok, notes = apply_promotion(req, runner)
    assert not ok and req.result == "failed"
    assert "python3 -m pip install requests==2.31.0" in runner.ran  # rolled back


def test_applied_promotion_cannot_be_reapplied():
    from fnh.promote import PromotionRefused, apply_promotion
    req = _patch_request(result="applied")
    with pytest.raises(PromotionRefused):
        apply_promotion(req, _Runner("2.32.0"))


def test_repeat_runs_reuse_pending_promotion_request(tmp_path):
    promoter = FilePromoter(tmp_path)
    pipeline = Pipeline(
        _Feed([Advisory("CVE-9", "t", "s", Severity.CRITICAL,
                        affected=[{"ecosystem": "pypi", "name": "requests"}],
                        vulnerable_ranges=["<2.32.0"], fixed_versions=["2.32.0"])]),
        _Inv([Asset("prod", "requests", "package", ecosystem="pypi",
                    version="2.31.0", environment="production")]),
        Planner(), Executor(DryRunner()), SafetyPolicy(), promoter=promoter,
    )
    first = pipeline.run()[0]
    second = pipeline.run()[0]
    assert len(promoter.requests()) == 1
    assert first.notes[-1] == second.notes[-1]


# -- multiple advisory sources ---------------------------------------------------

def test_same_cve_from_two_sources_is_remediated_once_using_first():
    from fnh.feed import MultiFeed
    from fnh.ghsa import parse_ghsa_advisory
    osv_adv = parse_osv_record({"id": "PYSEC-1", "aliases": ["CVE-S"], "affected": [{
        "package": {"ecosystem": "PyPI", "name": "requests"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}]}]})
    ghsa_adv = parse_ghsa_advisory({"ghsa_id": "GHSA-s", "cve_id": "CVE-S", "severity": "high",
        "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "requests"},
                             "vulnerable_version_range": "< 2.33.0",
                             "first_patched_version": "2.33.0"}]})
    feed = MultiFeed([_Feed([osv_adv]), _Feed([ghsa_adv])])
    asset = Asset("r", "requests", "package", ecosystem="pypi", version="2.31.0")
    (match,) = Matcher().match(feed.fetch(), [asset])
    assert match.advisory.source == "osv"
    assert Planner().plan(match).target_version == "2.32.0"


def test_source_flag_orders_and_builds_feeds():
    import argparse
    from fnh.__main__ import _build_feed, _parse_sources
    from fnh.feed import MultiFeed
    from fnh.ghsa import GHSAFeed
    from fnh.nvd import NVDFeed
    from fnh.osv import OSVFeed

    assert _parse_sources("nvd, OSV,ghsa") == ["osv", "ghsa", "nvd"]
    with pytest.raises(argparse.ArgumentTypeError):
        _parse_sources("osv,nope")
    args = argparse.Namespace(source=["osv", "ghsa", "nvd"], cache=None, no_batch=False)
    feed = _build_feed(args, _Inv([Asset("a", "x", "package", ecosystem="pypi", version="1")]))
    assert isinstance(feed, MultiFeed)
    assert [type(f) for f in feed.feeds] == [OSVFeed, GHSAFeed, NVDFeed]


def test_feed_failure_exits_2_with_message(monkeypatch, capsys):
    import fnh.__main__ as cli
    from fnh.nvd import NVDError

    class Boom:
        def run(self):
            raise NVDError("NVD request failed: HTTP 503")

    monkeypatch.setattr(cli, "build_pipeline", lambda args: Boom())
    assert cli.main(["run", "--dry-run"]) == 2
    assert "advisory feed failed: NVD request failed" in capsys.readouterr().err
