"""The orchestrator: feed -> inventory -> match -> plan -> act -> recommend.

Each match gets a plan (patch, else mitigation). Plans that pass the safety
policy are applied and validated; production fixes are validated on staging
and queued for approval when a promoter is set; everything else is reported
with next steps.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .executor import Executor
from .feed import Feed
from .inventory import Inventory
from .matcher import Matcher
from .models import Match, Outcome, OutcomeStatus, RemediationKind
from .planner import Planner
from .promote import Promoter
from .recommend import recommendations_for
from .safety import SafetyPolicy


@dataclass
class Pipeline:
    feed: Feed
    inventory: Inventory
    planner: Planner
    executor: Executor
    policy: SafetyPolicy
    matcher: Matcher = Matcher()
    # When set, a production fix that validates on staging is queued for
    # promotion instead of being left as a bare "needs review".
    promoter: Optional[Promoter] = None

    def run(self) -> list[Outcome]:
        advisories = self.feed.fetch()
        assets = self.inventory.assets()
        matches = self.matcher.match(advisories, assets)

        outcomes: list[Outcome] = []
        for match in matches:
            outcomes.append(self._handle(match))
        return outcomes

    def _handle(self, match) -> Outcome:
        remediation = self.planner.plan(match)

        # No automated path at all.
        if remediation.kind == RemediationKind.NONE:
            return Outcome(
                match=match,
                status=OutcomeStatus.NEEDS_REVIEW,
                remediation=remediation,
                recommendations=recommendations_for(match, remediation, False, None),
            )

        # Safety gate: may we act on this automatically?
        allowed, reason = self.policy.may_act_automatically(match, remediation)
        if not allowed:
            # A production change we can't auto-apply, but could validate on a
            # staging mirror and then queue for human approval.
            if self._promotable(match, remediation):
                plan_ok, plan_reason = self.policy.check_plan(match, remediation)
                if plan_ok:
                    return self._validate_for_promotion(match, remediation)
                reason = plan_reason
            return self._held(match, remediation, reason)

        runner = self.executor.runner_for(match.asset.environment)
        if runner is None:
            return self._held(
                match, remediation,
                f"no runner configured for environment '{match.asset.environment}'",
            )

        # Apply on the asset's environment and validate.
        closed, notes = self.executor.apply_and_validate(match, remediation, runner)
        if closed:
            status = (
                OutcomeStatus.PATCHED
                if remediation.kind == RemediationKind.PATCH
                else OutcomeStatus.MITIGATED
            )
            return Outcome(
                match=match,
                status=status,
                remediation=remediation,
                validated=True,
                notes=notes,
                recommendations=recommendations_for(match, remediation, True, None),
            )

        return Outcome(
            match=match,
            status=OutcomeStatus.FAILED,
            remediation=remediation,
            validated=False,
            notes=notes,
            recommendations=recommendations_for(match, remediation, False, None),
        )

    def _held(self, match: Match, remediation, reason: str) -> Outcome:
        return Outcome(
            match=match,
            status=OutcomeStatus.NEEDS_REVIEW,
            remediation=remediation,
            notes=[f"held: {reason}"],
            recommendations=recommendations_for(match, remediation, False, reason),
        )

    def _promotable(self, match: Match, remediation) -> bool:
        return (
            self.promoter is not None
            and self.policy.validate_production_on_staging
            and match.asset.environment == "production"
            and remediation.kind != RemediationKind.NONE
        )

    def _validate_for_promotion(self, match: Match, remediation) -> Outcome:
        """Validate a production fix on the staging runner, then queue it."""
        closed, notes = self.executor.apply_and_validate(
            match, remediation, self.executor.runner
        )
        if not closed:
            notes.append("staging validation failed; not queuing for promotion")
            return Outcome(
                match=match,
                status=OutcomeStatus.NEEDS_REVIEW,
                remediation=remediation,
                validated=False,
                notes=notes,
                recommendations=recommendations_for(match, remediation, False, None),
            )

        outcome = Outcome(
            match=match,
            status=OutcomeStatus.AWAITING_PROMOTION,
            remediation=remediation,
            validated=True,
            notes=notes,
        )
        request = self.promoter.promote(outcome)
        outcome.notes.append(f"promotion request queued: {request.id}")
        outcome.recommendations.append(
            f"Validated on staging. Approve promotion request {request.id} to apply "
            f"'{remediation.description}' to production ({match.asset.id})."
        )
        return outcome
