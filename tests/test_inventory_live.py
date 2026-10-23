import json

from fnh.executor import CommandResult
from fnh.inventory import DpkgCollector, LiveInventory, NpmCollector, PipCollector


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


def test_dpkg_collector():
    out = "nginx\t1.26.0\nopenssl\t3.0.11-1\n\t\n"
    runner = FakeRunner([("dpkg-query", _ok(out))])
    assets = DpkgCollector(osv_ecosystem="Debian:12").collect(runner, "production")
    names = {a.name: a.version for a in assets}
    assert names == {"nginx": "1.26.0", "openssl": "3.0.11-1"}
    assert all(a.ecosystem == "Debian:12" for a in assets)


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
        ("dpkg-query", _ok("nginx\t1.26.0\n")),
    ])
    inv = LiveInventory(runner, [PipCollector(), DpkgCollector()], environment="staging")
    assets = inv.assets()
    assert {a.name for a in assets} == {"requests", "nginx"}
