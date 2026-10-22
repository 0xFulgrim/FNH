"""CLI entry point: `python -m vulnpilot run --dry-run`.

Wires the file-backed reference implementations together so the whole flow
is runnable offline. Swap in real Feed/Inventory/Runner implementations for a
live deployment.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .executor import (
    ChainValidator,
    DryRunner,
    Executor,
    MitigationValidator,
    ShellRunner,
    SSHRunner,
    VersionValidator,
)
from .feed import FileFeed
from .inventory import FileInventory
from .osv import OSVCache, OSVFeed, packages_from_inventory
from .pipeline import Pipeline
from .planner import MitigationLibrary, Planner
from .recommend import summarize
from .safety import SafetyPolicy

EXAMPLES = Path(__file__).parent.parent / "examples"


def _build_runner(args: argparse.Namespace):
    if args.dry_run:
        return DryRunner()
    if args.staging_host:
        return SSHRunner(
            host=args.staging_host,
            user=args.staging_user,
            port=args.staging_port,
            identity_file=args.ssh_identity,
            known_hosts=args.ssh_known_hosts,
            strict_host_key_checking="accept-new" if args.ssh_trust_new else "yes",
        )
    # No staging host: run locally (e.g. a local staging container).
    return ShellRunner()


def build_pipeline(args: argparse.Namespace) -> Pipeline:
    inventory = FileInventory(args.inventory)
    if args.source == "osv":
        # Watch exactly the packages we actually run. OSV returns their known
        # advisories; our matcher then applies version ranges to the inventory.
        packages = packages_from_inventory(inventory.assets())
        cache = OSVCache(args.cache) if args.cache else None
        feed = OSVFeed(packages, cache=cache, batch=not args.no_batch)
    else:
        feed = FileFeed(args.advisories)
    planner = Planner(MitigationLibrary(args.mitigations))
    runner = _build_runner(args)
    validator = ChainValidator([VersionValidator(), MitigationValidator()])
    executor = Executor(runner=runner, validator=validator)
    policy = SafetyPolicy()
    if args.allow_production:
        # Opt-in only; still requires the change to validate on staging first.
        policy.autonomous_environments.add("production")
        policy.require_human_approval_for_production = False
    return Pipeline(
        feed=feed, inventory=inventory, planner=planner, executor=executor, policy=policy
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnpilot")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run the remediation pipeline")
    run.add_argument(
        "--source",
        choices=["file", "osv"],
        default="file",
        help="advisory source: 'file' (offline example) or 'osv' (live osv.dev)",
    )
    run.add_argument("--advisories", default=str(EXAMPLES / "advisories.json"))
    run.add_argument("--inventory", default=str(EXAMPLES / "inventory.json"))
    run.add_argument(
        "--cache",
        default=None,
        help="path to an OSV record cache file (osv source only)",
    )
    run.add_argument(
        "--no-batch",
        action="store_true",
        help="use one /v1/query per package instead of the batch endpoint",
    )
    run.add_argument("--mitigations", default=str(EXAMPLES / "mitigations.json"))
    run.add_argument("--dry-run", action="store_true", help="never execute commands")
    staging = run.add_argument_group("remote staging (ssh)")
    staging.add_argument("--staging-host", default=None, help="run steps on this host over ssh")
    staging.add_argument("--staging-user", default=None)
    staging.add_argument("--staging-port", type=int, default=22)
    staging.add_argument("--ssh-identity", default=None, help="private key file (-i)")
    staging.add_argument("--ssh-known-hosts", default=None, help="pinned known_hosts file")
    staging.add_argument(
        "--ssh-trust-new",
        action="store_true",
        help="trust-on-first-use host keys (StrictHostKeyChecking=accept-new)",
    )
    run.add_argument(
        "--allow-production",
        action="store_true",
        help="opt in to acting on production (still staging-validated first)",
    )

    args = parser.parse_args(argv)
    if args.command == "run":
        pipeline = build_pipeline(args)
        outcomes = pipeline.run()
        print(summarize(outcomes))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
