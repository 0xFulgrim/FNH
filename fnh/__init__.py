"""Friendly Neighborhood Helminth (fnh).

An autonomous vulnerability-management pipeline for your own infrastructure.
Like a benign gut symbiont, it lives inside your estate and quietly keeps it
healthy: advisory feed -> asset inventory -> match -> plan (patch|mitigation)
-> apply & validate on staging -> promote to production (human-gated) ->
recommend next steps. Production changes stay behind an explicit safety policy
and human approval.
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
