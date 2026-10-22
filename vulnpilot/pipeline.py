"""The orchestrator: feed -> inventory -> match -> plan -> act -> recommend.

This is the top-level flow described as:
    news feed > agent checks infra > deploys patches
    (no patch) > mitigation > test on staging > verify > recommend next steps
"""

from __future__ import annotations

from dataclasses import dataclass

from .executor import Executor
from .feed import Feed
from .inventory import Inventory
from .matcher import Matcher
from .models import Outcome, OutcomeStatus, RemediationKind
from .planner import Planner
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
