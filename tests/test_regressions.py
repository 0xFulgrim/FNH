"""Regression tests for bugs found in the repo review."""

import json
import shlex

import pytest

from fnh.__main__ import main
from fnh.executor import (
    ChainValidator,
    CommandResult,
    DryRunner,
    Executor,
    MitigationValidator,
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
    return ChainValidator([VersionValidator(), MitigationValidator()])


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
    adv = parse_osv_record(rec, "pkg")
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
    adv = parse_osv_record(rec, "pkg")
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
