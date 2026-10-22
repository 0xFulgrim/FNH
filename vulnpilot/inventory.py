"""Stage 2 (part a) — check the infrastructure.

Builds the asset inventory the advisories are matched against. The base
class is the contract; `FileInventory` loads a static inventory for dev/test.
Real sources would be a CMDB, cloud asset API, SBOM, or `pip list`/`dpkg`
output collected from hosts.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path

from .models import Asset


class Inventory(ABC):
    @abstractmethod
    def assets(self) -> list[Asset]:
        raise NotImplementedError


class FileInventory(Inventory):
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def assets(self) -> list[Asset]:
        data = json.loads(self.path.read_text())
        items = data if isinstance(data, list) else data.get("assets", [])
        return [
            Asset(
                id=a["id"],
                name=a.get("name", a["id"]),
                kind=a.get("kind", "package"),
                ecosystem=a.get("ecosystem"),
                version=a.get("version"),
                environment=a.get("environment", "production"),
                tags=a.get("tags", {}),
            )
            for a in items
        ]
