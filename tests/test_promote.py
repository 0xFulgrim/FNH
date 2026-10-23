import pytest

from fnh.executor import ChainValidator, CommandResult, DryRunner, Executor, VersionValidator, MitigationValidator
from fnh.feed import Feed
from fnh.inventory import Inventory
from fnh.models import Advisory, Asset, Severity
from fnh.pipeline import Pipeline
from fnh.planner import Planner
from fnh.promote import FilePromoter, PromotionRefused, PromotionRequest, apply_promotion
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


def _prod_pipeline(promoter):
    advisory = Advisory(
        id="CVE-2026-9999", title="t", summary="s", severity=Severity.CRITICAL,
        affected=[{"ecosystem": "pypi", "name": "requests"}],
        vulnerable_ranges=["<2.32.0"], fixed_versions=["2.32.0"],
    )
    asset = Asset("prod-req", "requests", "package", ecosystem="pypi",
                  version="2.31.0", environment="production")
    executor = Executor(DryRunner(), ChainValidator([VersionValidator(), MitigationValidator()]))
    return Pipeline(
        feed=_Feed([advisory]), inventory=_Inv([asset]), planner=Planner(),
        executor=executor, policy=SafetyPolicy(), promoter=promoter,
    )


def test_production_fix_queued_for_promotion(tmp_path):
    promoter = FilePromoter(tmp_path / "promos")
    outcomes = _prod_pipeline(promoter).run()
    assert len(outcomes) == 1
    out = outcomes[0]
    assert out.status.value == "awaiting_promotion"
    assert out.validated
    # A request file was written and is pending approval.
    requests = promoter.requests()
    assert len(requests) == 1
    assert requests[0].advisory_id == "CVE-2026-9999"
    assert requests[0].approved is False


def test_no_promoter_leaves_needs_review():
    outcomes = _prod_pipeline(promoter=None).run()
    assert outcomes[0].status.value == "needs_review"


def test_filepromoter_roundtrip(tmp_path):
    promoter = FilePromoter(tmp_path)
    req = PromotionRequest(
        advisory_id="CVE-1", asset_id="a", environment="production",
        description="d", steps=["echo hi"], rollback=["echo back"], verify="true",
    )
    promoter.save(req)
    loaded = promoter.load(req.id)
    assert loaded.steps == ["echo hi"]
    assert loaded.verify == "true"
    assert loaded.approved is False


class ListRunner:
    def __init__(self, fail_on=None):
        self.fail_on = fail_on
        self.ran = []

    def run(self, command):
        self.ran.append(command)
        rc = 1 if (self.fail_on and self.fail_on in command) else 0
        return CommandResult(command, returncode=rc)


def test_apply_promotion_refuses_unapproved():
    req = PromotionRequest("CVE-1", "a", "production", "d", steps=["echo hi"])
    with pytest.raises(PromotionRefused):
        apply_promotion(req, ListRunner())


def test_apply_promotion_runs_approved_with_verify():
    req = PromotionRequest("CVE-1", "a", "production", "d",
                           steps=["pip install x"], verify="probe", approved=True)
    runner = ListRunner()
    ok, notes = apply_promotion(req, runner)
    assert ok
    assert runner.ran == ["pip install x", "probe"]
    assert any("closed" in n for n in notes)


def test_apply_promotion_rolls_back_on_failed_verify():
    req = PromotionRequest("CVE-1", "a", "production", "d",
                           steps=["pip install x"], rollback=["pip install old"],
                           verify="probe", approved=True)
    runner = ListRunner(fail_on="probe")
    ok, notes = apply_promotion(req, runner)
    assert not ok
    assert "pip install old" in runner.ran  # rollback ran
    assert any("STILL OPEN" in n for n in notes)


def test_apply_promotion_rolls_back_on_failed_step():
    req = PromotionRequest("CVE-1", "a", "production", "d",
                           steps=["bad step"], rollback=["undo"], approved=True)
    runner = ListRunner(fail_on="bad step")
    ok, notes = apply_promotion(req, runner)
    assert not ok
    assert "undo" in runner.ran
