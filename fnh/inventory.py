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
from typing import Optional, Protocol

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
                # Assets known only by CPE (appliances, binaries) still need an
                # ecosystem for matching; NVD advisories use "cpe" for them.
                ecosystem=a.get("ecosystem") or ("cpe" if a.get("cpe") else None),
                version=a.get("version"),
                environment=a.get("environment", "production"),
                tags=a.get("tags", {}),
                cpe=a.get("cpe"),
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


def detect_os_ecosystem(os_release: str) -> Optional[str]:
    """OSV ecosystem for a host from its /etc/os-release, e.g. "Debian:12" or
    "Ubuntu:24.04:LTS" (OSV marks Ubuntu LTS releases). None if unknown."""
    fields = {}
    for line in os_release.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key.strip()] = value.strip().strip('"')
    distro, release = fields.get("ID", "").lower(), fields.get("VERSION_ID", "")
    if not release:
        return None
    if distro == "debian":
        return f"Debian:{release.split('.')[0]}"
    if distro == "ubuntu":
        lts = ":LTS" if "LTS" in fields.get("VERSION", "") else ""
        return f"Ubuntu:{release}{lts}"
    return None


class DpkgCollector(Collector):
    """Installed Debian/Ubuntu OS packages via `dpkg-query`.

    Debian and Ubuntu advisories name *source* packages (openssl, glibc),
    while hosts install *binary* packages built from them (libssl3, libc6).
    Assets are therefore one per source package, with the installed binaries
    and their versions in `tags["binaries"]` for the upgrade commands.

    The OSV ecosystem ("Debian:12", "Ubuntu:24.04:LTS") is read from the
    host's /etc/os-release unless given. If it can't be determined, assets get
    the generic "os" ecosystem, which file advisories can still match.
    """

    def __init__(self, osv_ecosystem: Optional[str] = None):
        self.osv_ecosystem = osv_ecosystem

    def collect(self, runner: _Runner, environment: str) -> list[Asset]:
        ecosystem = self.osv_ecosystem
        if ecosystem is None:
            release = runner.run("cat /etc/os-release")
            ecosystem = (detect_os_ecosystem(release.stdout) if release.ok else None) or "os"
        result = runner.run(DPKG_QUERY)
        if not result.ok:
            return []

        # source package -> (source version, {binary: binary version})
        sources: dict[str, tuple[str, dict[str, str]]] = {}
        for line in result.stdout.splitlines():
            fields = [f.strip() for f in line.split("\t")]
            if len(fields) != 5:
                continue
            status, binary, version, source, source_version = fields
            # Only "ii" is installed; "rc" etc. are removed packages whose
            # config files remain and would show up as false positives.
            if not binary or not status.startswith("ii"):
                continue
            source = source or binary
            _, binaries = sources.setdefault(source, (source_version or version, {}))
            binaries[binary] = version

        return [
            Asset(
                id=f"{environment}:os:{source}",
                name=source,
                kind="package",
                ecosystem=ecosystem,
                version=version or None,
                environment=environment,
                tags={"binaries": binaries},
            )
            for source, (version, binaries) in sources.items()
        ]


DPKG_QUERY = (
    r"dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}"
    r"\t${source:Package}\t${source:Version}\n'"
)


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
        self._assets: list[Asset] | None = None

    def assets(self) -> list[Asset]:
        # Collected once per instance: a run reads the inventory twice (to pick
        # OSV packages and to match), and each read is a round trip to the host.
        if self._assets is None:
            self._assets = []
            for collector in self.collectors:
                self._assets.extend(collector.collect(self.runner, self.environment))
        return list(self._assets)
