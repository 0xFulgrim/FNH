"""Compact CVSS v3.0/3.1 base-score calculator.

OSV records carry a CVSS *vector* (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/
C:H/I:H/A:H"), not a numeric score. This turns a v3 vector into the base
score per the FIRST.org specification so it can feed Severity.from_cvss.

v4.0 vectors are not scored here (the v4 formula is substantially different);
callers fall back to a database-provided severity label in that case.
"""

from __future__ import annotations

import math
from typing import Optional

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    # CVSS 3.1 roundup: smallest one-decimal number >= value (with fp slack).
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000
    return (math.floor(scaled / 10000) + 1) / 10.0


def base_score(vector: str) -> Optional[float]:
    """Return the CVSS v3.x base score for a vector string, or None."""
    if not vector:
        return None
    parts = vector.split("/")
    if not parts or not parts[0].upper().startswith("CVSS:3"):
        return None
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key.upper()] = val.upper()

    try:
        scope_changed = metrics["S"] == "C"
        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploitability = (
            8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]]
            * pr_table[metrics["PR"]] * _UI[metrics["UI"]]
        )
    except KeyError:
        return None

    if impact <= 0:
        return 0.0
    raw = (impact + exploitability) * (1.08 if scope_changed else 1.0)
    return _roundup(min(raw, 10.0))
