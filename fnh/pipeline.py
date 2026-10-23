"""The orchestrator: feed -> inventory -> match -> plan -> act -> recommend.

This is the top-level flow described as:
    news feed > agent checks infra > deploys patches
    (no patch) > mitigation > test on staging > verify > recommend next steps
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
                return self._validate_for_promotion(match, remediation)
            return Outcome(
                match=match,
                status=OutcomeStatus.NEEDS_REVIEW,
                remediation=remediation,
                notes=[f"held: {reason}"],
                recommendations=recommendations_for(match, remediation, False, reason),
            )

        # Apply on staging and validate.
        closed, notes = self.executor.apply_and_validate(match, remediation)
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

    def _promotable(self, match: Match, remediation) -> bool:
        return (
            self.promoter is not None
            and self.policy.validate_production_on_staging
            and match.asset.environment == "production"
            and remediation.kind != RemediationKind.NONE
        )

    def _validate_for_promotion(self, match: Match, remediation) -> Outcome:
        """Validate a production fix on the staging runner, then queue it."""
        closed, notes = self.executor.apply_and_validate(match, remediation)
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
