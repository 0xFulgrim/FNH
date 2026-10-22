"""vulnpilot — an autonomous vulnerability-management pipeline for your own infra.

Pipeline: advisory feed -> asset inventory -> match -> plan (patch|mitigation)
-> apply & validate on staging -> recommend next steps. Production changes are
gated behind an explicit safety policy and human approval.
"""

from .models import Advisory, Asset, Match, Outcome, OutcomeStatus, Remediation, Severity
from .pipeline import Pipeline

__all__ = [
    "Advisory",
    "Asset",
    "Match",
    "Outcome",
    "OutcomeStatus",
    "Remediation",
    "Severity",
    "Pipeline",
]

__version__ = "0.1.0"
