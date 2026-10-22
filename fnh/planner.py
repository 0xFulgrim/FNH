"""Stage 3 — decide how to remediate each match.

Prefers a patch (a fixed version the advisory names). If none exists, falls
back to a mitigation from a knowledge base. Produces a *plan* only; nothing
is executed here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .matcher import _cmp
from .models import Match, Remediation, RemediationKind
from .probes import build_verify


def _best_fixed_version(match: Match) -> Optional[str]:
    """Lowest fixed version that is strictly newer than the current one."""
    current = match.asset.version
    candidates = [
        v for v in match.advisory.fixed_versions if current is None or _cmp(v, current) > 0
    ]
    return sorted(candidates, key=lambda v: tuple(_cmp(v, o) for o in candidates))[0] if candidates else None


class MitigationLibrary:
    """Maps advisory id (or package name) to a known mitigation recipe.

    Backed by a JSON file for dev/test. Each entry supplies steps, a rollback,
    a confidence score, and an optional `verify` hint for the validator.
    """

    def __init__(self, path: Optional[str | Path] = None):
        self._data: dict = {}
        if path and Path(path).exists():
            self._data = json.loads(Path(path).read_text())

    def lookup(self, match: Match) -> Optional[Remediation]:
        entry = self._data.get(match.advisory.id) or self._data.get(match.asset.name)
        if not entry:
            return None
        return Remediation(
            kind=RemediationKind.MITIGATION,
            description=entry.get("description", "mitigation from library"),
            steps=entry.get("steps", []),
            rollback=entry.get("rollback", []),
            confidence=float(entry.get("confidence", 0.5)),
            verify=build_verify(entry.get("verify")),
        )


class Planner:
    def __init__(self, mitigations: Optional[MitigationLibrary] = None):
        self.mitigations = mitigations or MitigationLibrary()

    def plan(self, match: Match) -> Remediation:
        target = _best_fixed_version(match)
        if target is not None:
            eco = match.asset.ecosystem
            return Remediation(
                kind=RemediationKind.PATCH,
                description=f"Upgrade {match.asset.name} to {target}",
                target_version=target,
                steps=self._patch_steps(match, target),
                rollback=[f"# redeploy {match.asset.name}=={match.asset.version}"],
                confidence=0.9,
            )

        mitigation = self.mitigations.lookup(match)
        if mitigation is not None:
            return mitigation

        return Remediation(
            kind=RemediationKind.NONE,
            description="No patch and no known mitigation",
            confidence=0.0,
        )

    @staticmethod
    def _patch_steps(match: Match, target: str) -> list[str]:
        eco = match.asset.ecosystem
        name = match.asset.name
        if eco == "pypi":
            return [f"pip install --upgrade '{name}=={target}'"]
        if eco == "npm":
            return [f"npm install {name}@{target}"]
        if eco == "os":
            return [f"apt-get install --only-upgrade -y {name}"]
        return [f"# upgrade {name} to {target} via {eco or 'package manager'}"]
