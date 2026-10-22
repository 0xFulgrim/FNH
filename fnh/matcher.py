"""Stage 2 (part b) — match advisories against the inventory.

Decides which assets each advisory actually affects. Version comparison here
is intentionally small and dependency-free: it handles dotted numeric
versions and simple range expressions like ">=1.0,<1.4.2". For production
use, swap `_in_range` for `packaging.version` / `semver` per ecosystem.
"""

from __future__ import annotations

import re

from .models import Advisory, Asset, Match


def _parse_version(v: str) -> tuple:
    # Keep only the leading numeric-dotted part; "1.4.2-rc1" -> (1, 4, 2).
    head = re.split(r"[^0-9.]", v.strip(), maxsplit=1)[0]
    parts = [p for p in head.split(".") if p != ""]
    return tuple(int(p) for p in parts) if parts else (0,)


def _cmp(a: str, b: str) -> int:
    va, vb = _parse_version(a), _parse_version(b)
    length = max(len(va), len(vb))
    va += (0,) * (length - len(va))
    vb += (0,) * (length - len(vb))
    return (va > vb) - (va < vb)


_OP_RE = re.compile(r"^(<=|>=|<|>|==|=)?\s*(.+)$")


def _satisfies(version: str, constraint: str) -> bool:
    m = _OP_RE.match(constraint.strip())
    if not m:
        return False
    op, target = m.group(1) or "==", m.group(2).strip()
    c = _cmp(version, target)
    return {
        "<": c < 0,
        "<=": c <= 0,
        ">": c > 0,
        ">=": c >= 0,
        "==": c == 0,
        "=": c == 0,
    }[op]


def _in_range(version: str, range_expr: str) -> bool:
    """A range is comma-separated constraints, all of which must hold."""
    return all(_satisfies(version, part) for part in range_expr.split(",") if part.strip())


def _affects(advisory: Advisory, asset: Asset) -> tuple[bool, str]:
    if asset.ecosystem is None or asset.version is None:
        return False, ""
    for aff in advisory.affected:
        if aff.get("ecosystem") != asset.ecosystem:
            continue
        if aff.get("name") != asset.name and aff.get("name") != asset.id:
            continue
        # Matched the package; now check version ranges (empty == all versions).
        if not advisory.vulnerable_ranges:
            return True, f"{asset.name} is {asset.ecosystem}, all versions affected"
        for rng in advisory.vulnerable_ranges:
            if _in_range(asset.version, rng):
                return True, f"{asset.name} {asset.version} satisfies vulnerable range '{rng}'"
    return False, ""


class Matcher:
    def match(self, advisories: list[Advisory], assets: list[Asset]) -> list[Match]:
        matches: list[Match] = []
        for advisory in advisories:
            for asset in assets:
                affected, reason = _affects(advisory, asset)
                if affected:
                    matches.append(Match(advisory=advisory, asset=asset, reason=reason))
        return matches
