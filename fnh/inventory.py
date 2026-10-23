"""Stage 2 (part a) — check the infrastructure.

Builds the asset inventory the advisories are matched against. The base class
is the contract; `FileInventory` loads a static inventory for dev/test, and
`LiveInventory` collects installed packages from a real host by running
commands through a `CommandRunner` (local or SSH) — the same runner the
executor uses, so you inventory and remediate the same box.
"""

from __future__ import annotations

import json
import shlex
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Protocol

from .models import Asset


class _Runner(Protocol):
    # Structural type: anything with .run(cmd) -> result(ok, stdout) fits,
    # which is exactly executor.CommandRunner. Avoids a hard import cycle.
    def run(self, command: str): ...


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


class Collector(ABC):
    """Turns a package manager's output on a host into assets."""

    @abstractmethod
    def collect(self, runner: _Runner, environment: str) -> list[Asset]:
        raise NotImplementedError


class PipCollector(Collector):
    """Installed Python packages via `pip list --format=json`."""

    def __init__(self, python: str = "python3"):
        self.python = python

    def collect(self, runner: _Runner, environment: str) -> list[Asset]:
        result = runner.run(f"{self.python} -m pip list --format=json")
        if not result.ok:
            return []
        try:
            packages = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        return [
            Asset(
                id=f"{environment}:pypi:{p['name']}",
                name=p["name"],
                kind="package",
                ecosystem="pypi",
                version=p.get("version"),
                environment=environment,
            )
            for p in packages
            if p.get("name")
        ]


class DpkgCollector(Collector):
    """Installed Debian/Ubuntu OS packages via `dpkg-query`.

    OS packages need an OSV ecosystem like "Debian:12" or "Ubuntu:22.04" to
    match advisories, so pass the one for the host's distro release.
    """

    def __init__(self, osv_ecosystem: str = "Debian"):
        self.osv_ecosystem = osv_ecosystem

    def collect(self, runner: _Runner, environment: str) -> list[Asset]:
        result = runner.run(
            r"dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\n'"
        )
        if not result.ok:
            return []
        assets: list[Asset] = []
        for line in result.stdout.splitlines():
            fields = line.split("\t")
            if len(fields) != 3:
                continue
            status, name, version = (f.strip() for f in fields)
            # Only "ii" is installed; "rc" etc. are removed packages whose
            # config files remain and would show up as false positives.
            if not name or not status.startswith("ii"):
                continue
            assets.append(
                Asset(
                    id=f"{environment}:os:{name}",
                    name=name,
                    kind="package",
                    ecosystem=self.osv_ecosystem,
                    version=version or None,
                    environment=environment,
                )
            )
        return assets


class NpmCollector(Collector):
    """Installed npm packages via `npm ls --json --depth=0`."""

    def __init__(self, prefix: str | None = None, global_: bool = False):
        self.prefix = prefix
        self.global_ = global_

    def collect(self, runner: _Runner, environment: str) -> list[Asset]:
        cmd = ["npm", "ls", "--json", "--depth=0"]
        if self.global_:
            cmd.append("-g")
        if self.prefix:
            cmd += ["--prefix", shlex.quote(self.prefix)]
        # npm exits non-zero on peer-dep warnings but still prints valid JSON,
        # so parse stdout regardless of the exit code.
        result = runner.run(" ".join(cmd))
        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return []
        deps = data.get("dependencies", {}) or {}
        return [
            Asset(
                id=f"{environment}:npm:{name}",
                name=name,
                kind="package",
                ecosystem="npm",
                version=(info or {}).get("version"),
                environment=environment,
            )
            for name, info in deps.items()
        ]


# Collectors selectable by name on the CLI.
COLLECTORS = {
    "pip": PipCollector,
    "dpkg": DpkgCollector,
    "npm": NpmCollector,
}


class LiveInventory(Inventory):
    """Collect assets from a host by running collectors through a runner."""

    def __init__(
        self,
        runner: _Runner,
        collectors: list[Collector],
        environment: str = "staging",
    ):
        self.runner = runner
        self.collectors = collectors
        self.environment = environment

    def assets(self) -> list[Asset]:
        out: list[Asset] = []
        for collector in self.collectors:
            out.extend(collector.collect(self.runner, self.environment))
        return out
