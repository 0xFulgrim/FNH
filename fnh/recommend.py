"""Stage 5 — recommend next steps.

When the pipeline can't close something out on its own (no patch, no
mitigation, validation failed, or a production change needs sign-off), it
produces concrete next-step recommendations instead of silently stopping.
"""

from __future__ import annotations

from .models import Match, Outcome, OutcomeStatus, Remediation, RemediationKind


def recommendations_for(
    match: Match, remediation: Remediation, validated: bool, blocked_reason: str | None
) -> list[str]:
    recs: list[str] = []
    adv = match.advisory

    if blocked_reason:
        recs.append(f"Automation blocked ({blocked_reason}) — queue for human approval.")

    if remediation.kind == RemediationKind.NONE:
        recs.append("No fixed version is published yet. Track the advisory for a patch.")
        recs.append(
            f"Assess exposure for {match.asset.name}: is the vulnerable code path reachable "
            f"in {match.asset.environment}? Consider temporary network/WAF controls."
        )
        if adv.references:
            recs.append(f"Review upstream guidance: {adv.references[0]}")
    elif remediation.kind == RemediationKind.MITIGATION and not validated:
        recs.append(
            "Mitigation did not hold on staging — do not apply to production. "
            "Escalate to the owning team with the staging notes."
        )
    elif remediation.kind == RemediationKind.PATCH and not validated:
        recs.append(
            f"Patch to {remediation.target_version} failed validation on staging. "
            "Inspect build/test logs before retrying."
        )

    if match.asset.environment == "production" and validated:
        recs.append(
            f"Staging validated. Schedule the change window to promote "
            f"'{remediation.description}' to production."
        )

    return recs


def summarize(outcomes: list[Outcome]) -> str:
    lines = ["# Vulnerability remediation report", ""]
    counts: dict[str, int] = {}
    for o in outcomes:
        counts[o.status.value] = counts.get(o.status.value, 0) + 1
    lines.append("## Summary")
    for status, n in sorted(counts.items()):
        lines.append(f"- {status}: {n}")
    lines.append("")

    for o in outcomes:
        lines.append(f"## {o.match.advisory.id} — {o.match.asset.name} [{o.status.value}]")
        lines.append(f"- severity: {o.match.advisory.severity.value}")
        lines.append(f"- why: {o.match.reason}")
        if o.remediation:
            lines.append(f"- remediation: {o.remediation.description} "
                         f"(kind={o.remediation.kind.value}, validated={o.validated})")
        for note in o.notes:
            lines.append(f"  - {note}")
        for rec in o.recommendations:
            lines.append(f"  → {rec}")
        lines.append("")
    return "\n".join(lines)
