"""Stage 1 — the news feed.

Pulls vulnerability advisories from a source. The base class defines the
contract; `FileFeed` reads a local JSON file, and `osv.OSVFeed` queries
osv.dev on the same interface.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .models import Advisory, Severity


class Feed(ABC):
    @abstractmethod
    def fetch(self) -> list[Advisory]:
        """Return advisories newly seen since the last run."""
        raise NotImplementedError


def _parse_advisory(raw: dict) -> Advisory:
    cvss = raw.get("cvss")
    severity = (
        Severity(raw["severity"])
        if raw.get("severity")
        else Severity.from_cvss(float(cvss or 0))
    )
    published = None
    if raw.get("published"):
        published = datetime.fromisoformat(raw["published"].replace("Z", "+00:00"))
    return Advisory(
        id=raw["id"],
        title=raw.get("title", raw["id"]),
        summary=raw.get("summary", ""),
        severity=severity,
        cvss=float(cvss) if cvss is not None else None,
        published=published,
        source=raw.get("source", "file"),
        affected=raw.get("affected", []),
        vulnerable_ranges=raw.get("vulnerable_ranges", []),
        fixed_versions=raw.get("fixed_versions", []),
        references=raw.get("references", []),
    )


class FileFeed(Feed):
    """Read advisories from a local JSON file (list of advisory objects)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def fetch(self) -> list[Advisory]:
        data = json.loads(self.path.read_text())
        items: Iterable[dict] = data if isinstance(data, list) else data.get("advisories", [])
        return [_parse_advisory(raw) for raw in items]
