import json

from fnh.executor import CommandResult
import pytest

from fnh.inventory import (
    DpkgCollector,
    LiveInventory,
    NpmCollector,
    PipCollector,
    detect_os_ecosystem,
)


class FakeRunner:
    """Returns canned output per command substring."""

    def __init__(self, responses):
        self.responses = responses  # list of (substr, CommandResult)
        self.calls = []

    def run(self, command):
        self.calls.append(command)
        for substr, result in self.responses:
            if substr in command:
                return result
        return CommandResult(command, returncode=1, stderr="no match")


def _ok(stdout):
    return CommandResult("c", returncode=0, stdout=stdout)


def test_pip_collector():
    runner = FakeRunner([("pip list", _ok(json.dumps(
        [{"name": "requests", "version": "2.31.0"}, {"name": "flask", "version": "3.0.0"}]
    )))])
    assets = PipCollector().collect(runner, "staging")
    assert {a.name for a in assets} == {"requests", "flask"}
    assert all(a.ecosystem == "pypi" and a.environment == "staging" for a in assets)
    req = next(a for a in assets if a.name == "requests")
    assert req.version == "2.31.0"
    assert req.id == "staging:pypi:requests"


def test_pip_collector_handles_failure():
    runner = FakeRunner([("pip list", CommandResult("c", returncode=1))])
    assert PipCollector().collect(runner, "staging") == []


def test_dpkg_collector_groups_binaries_by_source_package():
    out = (
        "ii \tlibssl3\t3.0.11-1~deb12u2\topenssl\t3.0.11-1~deb12u2\n"
        "ii \topenssl\t3.0.11-1~deb12u2\topenssl\t3.0.11-1~deb12u2\n"
        "ii \tnginx\t1.22.1-9\tnginx\t1.22.1-9\n"
        "rc \told-pkg\t1.0\told-pkg\t1.0\n"
        "\t\n"
    )
    runner = FakeRunner([("dpkg-query", _ok(out))])
    assets = {a.name: a for a in DpkgCollector(osv_ecosystem="Debian:12").collect(runner, "production")}
    assert set(assets) == {"openssl", "nginx"}  # removed "rc" package skipped
    assert assets["openssl"].version == "3.0.11-1~deb12u2"
    assert assets["openssl"].tags["binaries"] == {
        "libssl3": "3.0.11-1~deb12u2", "openssl": "3.0.11-1~deb12u2"}
    assert all(a.ecosystem == "Debian:12" for a in assets.values())


@pytest.mark.parametrize("os_release,expected", [
    ('ID=debian\nVERSION_ID="12"\nVERSION="12 (bookworm)"', "Debian:12"),
    ('ID=ubuntu\nVERSION_ID="24.04"\nVERSION="24.04.1 LTS (Noble Numbat)"', "Ubuntu:24.04:LTS"),
    ('ID=ubuntu\nVERSION_ID="23.10"\nVERSION="23.10 (Mantic Minotaur)"', "Ubuntu:23.10"),
    ('ID=debian\nPRETTY_NAME="Debian GNU/Linux trixie/sid"', None),
    ('ID=fedora\nVERSION_ID=40', None),
])
def test_detect_os_ecosystem(os_release, expected):
    assert detect_os_ecosystem(os_release) == expected


def test_dpkg_collector_detects_ecosystem_from_host():
    runner = FakeRunner([
        ("os-release", _ok('ID=ubuntu\nVERSION_ID="22.04"\nVERSION="22.04.4 LTS (Jammy Jellyfish)"')),
        ("dpkg-query", _ok("ii \tcurl\t7.81.0-1ubuntu1.16\tcurl\t7.81.0-1ubuntu1.16\n")),
    ])
    (asset,) = DpkgCollector().collect(runner, "staging")
    assert asset.ecosystem == "Ubuntu:22.04:LTS"


def test_dpkg_collector_falls_back_to_generic_os():
    runner = FakeRunner([("dpkg-query", _ok("ii \tcurl\t7.81.0\tcurl\t7.81.0\n"))])
    (asset,) = DpkgCollector().collect(runner, "staging")
    assert asset.ecosystem == "os"


def test_npm_collector_parses_despite_nonzero_exit():
    payload = {"dependencies": {"lodash": {"version": "4.17.20"}, "express": {"version": "4.19.2"}}}
    # npm often exits non-zero but still prints JSON.
    runner = FakeRunner([("npm ls", CommandResult("c", returncode=1, stdout=json.dumps(payload)))])
    assets = NpmCollector().collect(runner, "staging")
    assert {a.name: a.version for a in assets} == {"lodash": "4.17.20", "express": "4.19.2"}
    assert all(a.ecosystem == "npm" for a in assets)


def test_live_inventory_merges_collectors():
    runner = FakeRunner([
        ("pip list", _ok(json.dumps([{"name": "requests", "version": "2.31.0"}]))),
        ("dpkg-query", _ok("ii \tnginx\t1.26.0\tnginx\t1.26.0\n")),
    ])
    inv = LiveInventory(runner, [PipCollector(), DpkgCollector()], environment="staging")
    assets = inv.assets()
    assert {a.name for a in assets} == {"requests", "nginx"}
