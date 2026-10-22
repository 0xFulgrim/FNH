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
    VersionValidator,
)
from .feed import FileFeed
from .inventory import FileInventory
from .pipeline import Pipeline
from .planner import MitigationLibrary, Planner
from .recommend import summarize
from .safety import SafetyPolicy

EXAMPLES = Path(__file__).parent.parent / "examples"


def build_pipeline(args: argparse.Namespace) -> Pipeline:
    feed = FileFeed(args.advisories)
    inventory = FileInventory(args.inventory)
    planner = Planner(MitigationLibrary(args.mitigations))
    runner = DryRunner() if args.dry_run else ShellRunner()
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
    run.add_argument("--advisories", default=str(EXAMPLES / "advisories.json"))
    run.add_argument("--inventory", default=str(EXAMPLES / "inventory.json"))
    run.add_argument("--mitigations", default=str(EXAMPLES / "mitigations.json"))
    run.add_argument("--dry-run", action="store_true", help="never execute commands")
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
