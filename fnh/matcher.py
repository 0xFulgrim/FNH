"""Stage 2 (part b) — match advisories against the inventory.

Decides which assets each advisory actually affects, using range expressions
like ">=1.0,<1.4.2". Versions are compared per ecosystem without third-party
dependencies: dpkg ordering for Debian/Ubuntu, PEP 440 for PyPI, SemVer 2.0 for
npm, and the leading dotted numeric part for everything else.
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


# PEP 440 (PyPI). Mirrors the ordering in `packaging.version` without the
# dependency: epoch, release (trailing zeros ignored), pre, post, dev, local.
_PEP440_RE = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?:-(?P<post_n1>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)
_PRE_ORDER = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
# Sentinels that sort below / above any real (0, ...) segment key.
_LOW, _HIGH = (-1,), (1,)


def _pep440_key(v: str) -> tuple | None:
    m = _PEP440_RE.match(v)
    if not m:
        return None
    release = [int(p) for p in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre_l, post, dev = m.group("pre_l"), None, None
    if m.group("post_n1") is not None:
        post = int(m.group("post_n1"))
    elif m.group("post_l"):
        post = int(m.group("post_n2") or 0)
    if m.group("dev_l"):
        dev = int(m.group("dev_n") or 0)

    if pre_l:
        pre = (0, _PRE_ORDER[pre_l.lower()], int(m.group("pre_n") or 0))
    elif post is None and dev is not None:
        pre = _LOW  # 1.0.dev0 sorts before 1.0a0
    else:
        pre = _HIGH  # a final release sorts after its pre-releases
    local = m.group("local")
    return (
        int(m.group("epoch") or 0),
        tuple(release),
        pre,
        _LOW if post is None else (0, post),
        _HIGH if dev is None else (0, dev),
        _LOW if local is None else (0, tuple(
            (1, int(s), "") if s.isdigit() else (0, 0, s.lower())
            for s in re.split(r"[-_.]", local)
        )),
    )


# SemVer 2.0 (npm). Build metadata is ignored; a missing minor/patch is 0.
_SEMVER_RE = re.compile(
    r"^\s*[v=]?\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?\s*$"
)


def _cmp_semver(a: str, b: str) -> int | None:
    ma, mb = _SEMVER_RE.match(a), _SEMVER_RE.match(b)
    if not ma or not mb:
        return None
    core_a = tuple(int(x or 0) for x in ma.group(1, 2, 3))
    core_b = tuple(int(x or 0) for x in mb.group(1, 2, 3))
    if core_a != core_b:
        return -1 if core_a < core_b else 1
    pa, pb = ma.group(4), mb.group(4)
    if pa == pb:
        return 0
    if pa is None or pb is None:
        return 1 if pa is None else -1  # a release sorts after its pre-releases
    for x, y in zip(pa.split("."), pb.split(".")):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return -1 if int(x) < int(y) else 1
        if x.isdigit() != y.isdigit():
            return -1 if x.isdigit() else 1  # numeric identifiers sort first
        return -1 if x < y else 1
    na, nb = len(pa.split(".")), len(pb.split("."))
    return (na > nb) - (na < nb)


def _uses_dpkg_versions(ecosystem: str | None) -> bool:
    """Generic "os" or an OSV Debian/Ubuntu ecosystem like "Debian:12"."""
    return bool(ecosystem) and (
        ecosystem == "os" or ecosystem.split(":", 1)[0] in ("Debian", "Ubuntu")
    )


def _cmp(a: str, b: str, ecosystem: str | None = None) -> int:
    eco = (ecosystem or "").lower()
    if _uses_dpkg_versions(ecosystem):
        return _cmp_dpkg(a, b)
    if eco == "pypi":
        ka, kb = _pep440_key(a), _pep440_key(b)
        if ka is not None and kb is not None:
            return (ka > kb) - (ka < kb)
    elif eco == "npm":
        c = _cmp_semver(a, b)
        if c is not None:
            return c
    # Unknown ecosystem or an unparseable version: numeric prefix only.
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


def _match_reason(advisory: Advisory, aff: dict, asset: Asset) -> str | None:
    """Why `asset` is affected under one `advisory.affected` entry, or None."""
    # Per-package ranges win; an empty list means every version is affected.
    ranges = aff["ranges"] if "ranges" in aff else advisory.vulnerable_ranges
    if not ranges:
        return f"{asset.name} is {asset.ecosystem}, all versions affected"
    for rng in ranges:
        if _in_range(asset.version, rng, asset.ecosystem):
            return f"{asset.name} {asset.version} satisfies vulnerable range '{rng}'"
    return None


class Matcher:
    def match(self, advisories: list[Advisory], assets: list[Asset]) -> list[Match]:
        # Index assets by package so each affected entry is a dict lookup
        # instead of a scan over the whole inventory. An entry's name may also
        # refer to an asset id.
        index: dict[tuple, list[Asset]] = {}
        for asset in assets:
            if asset.ecosystem is None or asset.version is None:
                continue
            index.setdefault((asset.ecosystem, asset.name), []).append(asset)
            if asset.id != asset.name:
                index.setdefault((asset.ecosystem, asset.id), []).append(asset)

        matches: list[Match] = []
        # Feeds can return the same CVE from several databases (e.g. GHSA and
        # PYSEC); remediate each advisory/asset pair once.
        seen: set[tuple[str, str]] = set()
        for advisory in advisories:
            for aff in advisory.affected:
                for asset in index.get((aff.get("ecosystem"), aff.get("name")), ()):
                    key = (advisory.id, asset.id)
                    if key in seen:
                        continue
                    reason = _match_reason(advisory, aff, asset)
                    if reason is not None:
                        seen.add(key)
                        matches.append(Match(advisory, asset, reason, affected=aff))
        return matches
