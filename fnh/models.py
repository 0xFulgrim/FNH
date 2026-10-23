"""Core data models shared across the pipeline stages.

These are deliberately plain dataclasses so each stage has a stable, typed
contract to pass along. Nothing here talks to the network or the OS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_label(cls, label: object) -> Optional["Severity"]:
        """Map a feed's severity word ("MODERATE", "high", ...) or None."""
        word = str(label or "").strip().lower()
        return {
            "low": cls.LOW,
            "moderate": cls.MEDIUM,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
        }.get(word)

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        return cls.LOW


@dataclass
class Advisory:
    """A single vulnerability advisory pulled from a feed (NVD, OSV, GHSA...)."""

    id: str  # e.g. "CVE-2026-12345"
    title: str
    summary: str
    severity: Severity
    cvss: Optional[float] = None
    published: Optional[datetime] = None
    source: str = "unknown"
    # Affected packages, e.g. {"ecosystem": "pypi", "name": "requests"}. An entry
    # may carry its own "ranges" and "fixed" lists, which then override the
    # advisory-wide ones below for that package.
    affected: list[dict] = field(default_factory=list)
    # Advisory-wide vulnerable ranges; empty means every version is affected.
    vulnerable_ranges: list[str] = field(default_factory=list)
    # Advisory-wide versions that resolve the issue.
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class Asset:
    """A thing in your infrastructure that could be affected.

    Kept generic on purpose: a host, container image, package, or service.
    """

    id: str
    name: str
    kind: str  # "host" | "image" | "package" | "service"
    ecosystem: Optional[str] = None  # "pypi", "npm", "os", ...
    version: Optional[str] = None
    environment: str = "production"  # "staging" | "production" | ...
    tags: dict = field(default_factory=dict)
    # NVD product identifier, e.g. "cpe:2.3:a:nginx:nginx" or "nginx:nginx".
    cpe: Optional[str] = None


@dataclass
class Match:
    """An advisory determined to affect a specific asset."""

    advisory: Advisory
    asset: Asset
    reason: str  # human-readable explanation of why it matched
    # The `advisory.affected` entry that matched, when known.
    affected: Optional[dict] = None

    @property
    def fixed_versions(self) -> list[str]:
        if self.affected is not None and "fixed" in self.affected:
            return self.affected["fixed"]
        return self.advisory.fixed_versions


class RemediationKind(str, Enum):
    PATCH = "patch"
    MITIGATION = "mitigation"
    NONE = "none"


@dataclass
class Remediation:
    """A proposed way to address a match."""

    kind: RemediationKind
    description: str
    # For patches: target version to move the asset to.
    target_version: Optional[str] = None
    # Shell/config steps, declarative where possible. Treated as a plan, not
    # auto-executed until it passes the safety gate and staging validation.
    steps: list[str] = field(default_factory=list)
    rollback: list[str] = field(default_factory=list)
    confidence: float = 0.0  # 0..1
    # A command whose exit code is the verdict for a mitigation: 0 == the
    # vulnerability is confirmed closed. Built from a probe spec (see probes.py)
    # or supplied verbatim in the mitigation library.
    verify: Optional[str] = None


class OutcomeStatus(str, Enum):
    PATCHED = "patched"            # fix deployed + validated
    MITIGATED = "mitigated"        # mitigation applied + validated on staging
    AWAITING_PROMOTION = "awaiting_promotion"  # validated on staging; prod change queued for approval
    NEEDS_REVIEW = "needs_review"  # no safe automated path; human action required
    FAILED = "failed"             # attempted remediation did not hold


@dataclass
class Outcome:
    match: Match
    status: OutcomeStatus
    remediation: Optional[Remediation] = None
    # Did validation on staging confirm the gap is closed?
    validated: bool = False
    notes: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
