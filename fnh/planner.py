"""Stage 3 — decide how to remediate each match.

Prefers a patch (a fixed version the advisory names). If none exists, falls
back to a mitigation from a knowledge base. Produces a *plan* only; nothing
is executed here.
"""

from __future__ import annotations

import json
import shlex
from functools import cmp_to_key
from pathlib import Path
from typing import Optional

from .matcher import _cmp
from .matcher import _uses_dpkg_versions as is_apt_ecosystem
from .models import Match, Remediation, RemediationKind
from .probes import build_verify


def _best_fixed_version(match: Match) -> Optional[str]:
    """Lowest fixed version that is strictly newer than the current one."""
    current = match.asset.version
    eco = match.asset.ecosystem
    candidates = [
        v for v in match.fixed_versions
        if current is None or _cmp(v, current, eco) > 0
    ]
    if not candidates:
        return None
    return min(candidates, key=cmp_to_key(lambda a, b: _cmp(a, b, eco)))


class MitigationLibrary:
    """Maps advisory id (or package name) to a known mitigation recipe.

    Backed by a JSON file. Each entry supplies steps, a rollback, a confidence
    score and an optional `verify` probe. Probe specs are resolved on load, so
    a bad entry fails before anything runs rather than halfway through a run.
    """

    def __init__(self, path: Optional[str | Path] = None):
        self._data: dict[str, dict] = {}
        if path and Path(path).exists():
            for key, entry in json.loads(Path(path).read_text()).items():
                try:
                    verify = build_verify(entry.get("verify"))
                except ValueError as exc:
                    raise ValueError(f"mitigation {key!r}: {exc}") from None
                self._data[key] = {**entry, "verify": verify}

    def lookup(self, match: Match) -> Optional[Remediation]:
        entry = self._data.get(match.advisory.id) or self._data.get(match.asset.name)
        if not entry:
            return None
        return Remediation(
            kind=RemediationKind.MITIGATION,
            description=entry.get("description", "mitigation from library"),
            steps=list(entry.get("steps", [])),
            rollback=list(entry.get("rollback", [])),
            confidence=float(entry.get("confidence", 0.5)),
            verify=entry["verify"],
        )


class Planner:
    def __init__(self, mitigations: Optional[MitigationLibrary] = None):
        self.mitigations = mitigations or MitigationLibrary()

    def plan(self, match: Match) -> Remediation:
        target = _best_fixed_version(match)
        if target is not None:
            steps = self._install_steps(match, target, upgrade=True)
            if not steps:
                # No package manager we know how to drive: leave it to a human
                # rather than "running" a placeholder that always succeeds.
                return Remediation(
                    kind=RemediationKind.PATCH,
                    description=(
                        f"Upgrade {match.asset.name} to {target} "
                        f"(no automated upgrade for ecosystem {match.asset.ecosystem!r})"
                    ),
                    target_version=target,
                    confidence=0.0,
                )
            current = match.asset.version
            return Remediation(
                kind=RemediationKind.PATCH,
                description=f"Upgrade {match.asset.name} to {target}",
                target_version=target,
                steps=steps,
                rollback=self._install_steps(match, current, upgrade=False) if current else [],
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
    def _install_steps(match: Match, version: str, upgrade: bool) -> list[str]:
        """Commands that install `version` of the asset's package.

        Names and versions come from inventories and advisory feeds, so every
        value is shell-quoted. `upgrade=False` builds the rollback, which has to
        be allowed to move the package back down.
        """
        eco = match.asset.ecosystem
        name = match.asset.name
        if eco == "pypi":
            return [f"python3 -m pip install {shlex.quote(f'{name}=={version}')}"]
        if eco == "npm":
            return [f"npm install {shlex.quote(f'{name}@{version}')}"]
        if eco == "os":
            # Advisory versions for a generic "os" asset are not distro package
            # versions, so upgrade to whatever the archive offers.
            if upgrade:
                return [f"apt-get install -y --only-upgrade {shlex.quote(name)}"]
            return [f"apt-get install -y --allow-downgrades {shlex.quote(f'{name}={version}')}"]
        if is_apt_ecosystem(eco):
            flag = "--only-upgrade" if upgrade else "--allow-downgrades"
            return [f"apt-get install -y {flag} {shlex.quote(f'{name}={version}')}"]
        return []
