"""Safety guardrails.

The whole point of an autonomous remediation tool is that it *acts*. These
gates decide what it is allowed to do on its own and what must stop for a
human. Keep them strict by default; loosen deliberately in config.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Match, Remediation, Severity


@dataclass
class SafetyPolicy:
    # Environments the tool may change on its own.
    autonomous_environments: set[str] = field(default_factory=lambda: {"staging"})
    # Production always requires a human sign-off unless explicitly disabled.
    require_human_approval_for_production: bool = True
    # Never run remediation steps containing these tokens automatically.
    forbidden_tokens: tuple[str, ...] = (
        "rm -rf /",
        "mkfs",
        ":(){",       # fork bomb
        "dd if=",
        "> /dev/sd",
    )
    # Only auto-apply patches/mitigations at or above this confidence.
    min_confidence: float = 0.75
    # Only auto-act on advisories at/above this severity (lower ones are queued).
    min_auto_severity: Severity = Severity.HIGH
    # Validate a production fix on the staging runner, then queue it for human
    # approval, rather than leaving it a bare "needs review". Still never
    # applies to production autonomously.
    validate_production_on_staging: bool = True

    def may_act_automatically(self, match: Match, remediation: Remediation) -> tuple[bool, str]:
        """Return (allowed, reason). A single 'no' blocks automation."""
        env = match.asset.environment
        if env not in self.autonomous_environments:
            if env == "production" and self.require_human_approval_for_production:
                return False, "production change requires human approval"
            return False, f"environment '{env}' not in autonomous set"

        if remediation.confidence < self.min_confidence:
            return False, (
                f"confidence {remediation.confidence:.2f} < "
                f"threshold {self.min_confidence:.2f}"
            )

        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        if order.index(match.advisory.severity) < order.index(self.min_auto_severity):
            return False, f"severity {match.advisory.severity.value} below auto threshold"

        for step in remediation.steps:
            for token in self.forbidden_tokens:
                if token in step:
                    return False, f"remediation step contains forbidden token: {token!r}"

        return True, "ok"
