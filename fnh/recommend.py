"""Stage 5 — recommend next steps.

When the pipeline can't close something out on its own (no patch, no
mitigation, validation failed, or a production change needs sign-off), it
produces concrete next-step recommendations instead of silently stopping.
"""

from __future__ import annotations

from .models import Match, Outcome, Remediation, RemediationKind


def recommendations_for(
    match: Match, remediation: Remediation, validated: bool, blocked_reason: str | None
) -> list[str]:
    recs: list[str] = []
    adv = match.advisory

    if blocked_reason:
        recs.append(f"Automation blocked ({blocked_reason}). Review and apply by hand.")

    if remediation.kind == RemediationKind.NONE:
        recs.append("No fixed version is published yet. Track the advisory for a patch.")
        recs.append(
            f"Assess exposure for {match.asset.name}: is the vulnerable code path reachable "
            f"in {match.asset.environment}? Consider temporary network/WAF controls."
        )
        if adv.references:
            recs.append(f"Review upstream guidance: {adv.references[0]}")
    elif not validated and not blocked_reason:
        # Only report a failed validation when something actually ran.
        if remediation.kind == RemediationKind.MITIGATION:
            recs.append(
                "Mitigation did not hold. Do not apply it to production; "
                "escalate to the owning team with the notes above."
            )
        else:
            recs.append(
                f"Patch to {remediation.target_version} did not validate. "
                "Check the step output above before retrying."
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
