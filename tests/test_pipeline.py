from pathlib import Path

from vulnpilot.executor import (
    ChainValidator,
    DryRunner,
    Executor,
    MitigationValidator,
    VersionValidator,
)
from vulnpilot.feed import FileFeed
from vulnpilot.inventory import FileInventory
from vulnpilot.matcher import Matcher, _cmp, _in_range
from vulnpilot.models import OutcomeStatus
from vulnpilot.pipeline import Pipeline
from vulnpilot.planner import MitigationLibrary, Planner
from vulnpilot.safety import SafetyPolicy

EX = Path(__file__).parent.parent / "examples"


def test_version_compare():
    assert _cmp("2.31.0", "2.32.0") < 0
    assert _cmp("1.27.3", "1.27.3") == 0
    assert _cmp("4.17.21", "4.17.20") > 0


def test_range_matching():
    assert _in_range("2.31.0", "<2.32.0")
    assert not _in_range("2.32.0", "<2.32.0")
    assert _in_range("1.26.0", ">=1.24.0,<1.27.3")
    assert not _in_range("1.27.3", ">=1.24.0,<1.27.3")


def _pipeline(**overrides):
    policy = SafetyPolicy()
    policy.__dict__.update(overrides)
    return Pipeline(
        feed=FileFeed(EX / "advisories.json"),
        inventory=FileInventory(EX / "inventory.json"),
        planner=Planner(MitigationLibrary(EX / "mitigations.json")),
        executor=Executor(
            DryRunner(), ChainValidator([VersionValidator(), MitigationValidator()])
        ),
        policy=policy,
    )


def test_patch_on_staging_is_applied_and_validated():
    outcomes = {o.match.advisory.id: o for o in _pipeline().run()}
    patched = outcomes["CVE-2026-0001"]
    assert patched.status == OutcomeStatus.PATCHED
    assert patched.validated
    assert patched.remediation.target_version == "2.32.0"


def test_mitigation_used_when_no_patch():
    outcomes = {o.match.advisory.id: o for o in _pipeline().run()}
    mitigated = outcomes["CVE-2026-0002"]
    assert mitigated.status == OutcomeStatus.MITIGATED
    assert mitigated.validated


def test_no_patch_no_mitigation_needs_review_with_recommendations():
    outcomes = {o.match.advisory.id: o for o in _pipeline().run()}
    stuck = outcomes["CVE-2026-0003"]
    assert stuck.status == OutcomeStatus.NEEDS_REVIEW
    assert stuck.recommendations


def test_production_requires_human_approval():
    # lodash asset is production; even if there were a fix it must not auto-apply.
    outcomes = {o.match.advisory.id: o for o in _pipeline().run()}
    prod = outcomes["CVE-2026-0003"]
    assert prod.match.asset.environment == "production"
    assert prod.status == OutcomeStatus.NEEDS_REVIEW


def test_safety_blocks_forbidden_steps():
    from vulnpilot.models import (
        Advisory,
        Asset,
        Match,
        Remediation,
        RemediationKind,
        Severity,
    )

    policy = SafetyPolicy()
    match = Match(
        advisory=Advisory("CVE-X", "t", "s", Severity.CRITICAL),
        asset=Asset("a", "pkg", "package", environment="staging"),
        reason="test",
    )
    bad = Remediation(RemediationKind.MITIGATION, "danger", steps=["rm -rf /"], confidence=0.99)
    allowed, reason = policy.may_act_automatically(match, bad)
    assert not allowed
    assert "forbidden" in reason
