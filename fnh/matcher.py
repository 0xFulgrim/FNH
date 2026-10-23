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


def _cmp_numeric(a: str, b: str) -> int:
    va, vb = _parse_version(a), _parse_version(b)
    length = max(len(va), len(vb))
    va += (0,) * (length - len(va))
    vb += (0,) * (length - len(vb))
    return (va > vb) - (va < vb)


def _dpkg_order(ch: str) -> int:
    # dpkg ordering for non-digit characters: "~" sorts before everything,
    # including the end of the string; letters sort before other symbols.
    if ch == "~":
        return -1
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _verrevcmp(a: str, b: str) -> int:
    """dpkg's comparison for an upstream version or a revision."""
    i = j = 0
    while i < len(a) or j < len(b):
        # Non-digit prefix, compared character by character.
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _dpkg_order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        # Digit run, compared numerically.
        si = i
        while i < len(a) and a[i].isdigit():
            i += 1
        sj = j
        while j < len(b) and b[j].isdigit():
            j += 1
        na, nb = int(a[si:i] or 0), int(b[sj:j] or 0)
        if na != nb:
            return -1 if na < nb else 1
    return 0


def _split_dpkg(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    upstream, _, revision = v.rpartition("-") if "-" in v else (v, "", "")
    return epoch, upstream, revision


def _cmp_dpkg(a: str, b: str) -> int:
    ea, ua, ra = _split_dpkg(a)
    eb, ub, rb = _split_dpkg(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


def _uses_dpkg_versions(ecosystem: str | None) -> bool:
    """Generic "os" or an OSV Debian/Ubuntu ecosystem like "Debian:12"."""
    return bool(ecosystem) and (
        ecosystem == "os" or ecosystem.split(":", 1)[0] in ("Debian", "Ubuntu")
    )


def _cmp(a: str, b: str, ecosystem: str | None = None) -> int:
    if _uses_dpkg_versions(ecosystem):
        return _cmp_dpkg(a, b)
    return _cmp_numeric(a, b)


_OP_RE = re.compile(r"^(<=|>=|<|>|==|=)?\s*(.+)$")


def _satisfies(version: str, constraint: str, ecosystem: str | None = None) -> bool:
    m = _OP_RE.match(constraint.strip())
    if not m:
        return False
    op, target = m.group(1) or "==", m.group(2).strip()
    c = _cmp(version, target, ecosystem)
    return {
        "<": c < 0,
        "<=": c <= 0,
        ">": c > 0,
        ">=": c >= 0,
        "==": c == 0,
        "=": c == 0,
    }[op]


def _in_range(version: str, range_expr: str, ecosystem: str | None = None) -> bool:
    """A range is comma-separated constraints, all of which must hold."""
    return all(
        _satisfies(version, part, ecosystem) for part in range_expr.split(",") if part.strip()
    )


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
            if _in_range(asset.version, rng, asset.ecosystem):
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
