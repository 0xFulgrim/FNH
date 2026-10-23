"""CLI entry point.

    fnh run      — feed -> inventory -> match -> plan -> apply/validate -> queue
    fnh promote  — list and (with approval) apply queued production promotions

Wires the reference implementations together so the whole flow is runnable
offline. Swap in real Feed/Inventory/Runner implementations for a live deploy.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .executor import DryRunner, Executor, ShellRunner, SSHRunner
from .feed import FileFeed
from .inventory import COLLECTORS, FileInventory, LiveInventory
from .osv import OSVCache, OSVFeed, packages_from_inventory
from .pipeline import Pipeline
from .planner import MitigationLibrary, Planner
from .promote import FilePromoter, PromotionRefused, apply_promotion
from .recommend import summarize
from .safety import SafetyPolicy

EXAMPLES = Path(__file__).parent.parent / "examples"


def _ssh_runner(host, user, port, identity, known_hosts, trust_new):
    return SSHRunner(
        host=host,
        user=user,
        port=port,
        identity_file=identity,
        known_hosts=known_hosts,
        strict_host_key_checking="accept-new" if trust_new else "yes",
    )


def _staging_runner(args: argparse.Namespace):
    if args.staging_host:
        return _ssh_runner(
            args.staging_host, args.staging_user, args.staging_port,
            args.ssh_identity, args.ssh_known_hosts, args.ssh_trust_new,
        )
    # No staging host: run locally (e.g. a local staging container).
    return ShellRunner()


def _production_runner(args: argparse.Namespace):
    if not args.allow_production:
        return None
    if not args.prod_host:
        raise SystemExit("--allow-production requires --prod-host")
    if args.dry_run:
        return DryRunner()
    return _ssh_runner(
        args.prod_host, args.prod_user, args.prod_port,
        args.ssh_identity, args.ssh_known_hosts, args.ssh_trust_new,
    )


def _build_inventory(args: argparse.Namespace, runner):
    if args.inventory_source == "live":
        names = [c.strip() for c in args.collect.split(",") if c.strip()]
        collectors = []
        for name in names:
            if name not in COLLECTORS:
                raise SystemExit(f"unknown collector: {name!r} (have {sorted(COLLECTORS)})")
            kwargs = {"osv_ecosystem": args.dpkg_ecosystem} if name == "dpkg" else {}
            collectors.append(COLLECTORS[name](**kwargs))
        return LiveInventory(runner, collectors, environment=args.environment)
    return FileInventory(args.inventory)


def build_pipeline(args: argparse.Namespace) -> Pipeline:
    staging = _staging_runner(args)
    # Collecting inventory only reads package lists, so it uses the real host
    # even under --dry-run; only remediation is replaced by a DryRunner.
    inventory = _build_inventory(args, staging)
    runner = DryRunner() if args.dry_run else staging
    if args.source == "osv":
        # Watch exactly the packages we actually run. OSV returns their known
        # advisories; our matcher then applies version ranges to the inventory.
        packages = packages_from_inventory(inventory.assets())
        cache = OSVCache(args.cache) if args.cache else None
        feed = OSVFeed(packages, cache=cache, batch=not args.no_batch)
    else:
        feed = FileFeed(args.advisories)
    planner = Planner(MitigationLibrary(args.mitigations))
    executor = Executor(runner=runner, production_runner=_production_runner(args))
    policy = SafetyPolicy()
    if args.allow_production:
        # Production assets are changed directly on --prod-host, subject to the
        # same plan checks (confidence, severity, forbidden commands).
        policy.autonomous_environments.add("production")
        policy.require_human_approval_for_production = False
    promoter = FilePromoter(args.promote_dir) if args.promote_dir else None
    return Pipeline(
        feed=feed, inventory=inventory, planner=planner, executor=executor,
        policy=policy, promoter=promoter,
    )


def _add_run_parser(sub) -> None:
    run = sub.add_parser("run", help="run the remediation pipeline")
    run.add_argument("--source", choices=["file", "osv"], default="file",
                     help="advisory source: 'file' (offline example) or 'osv' (live osv.dev)")
    run.add_argument("--advisories", default=str(EXAMPLES / "advisories.json"))
    run.add_argument("--mitigations", default=str(EXAMPLES / "mitigations.json"))
    run.add_argument("--cache", default=None, help="OSV record cache file (osv source only)")
    run.add_argument("--no-batch", action="store_true",
                     help="use one /v1/query per package instead of the batch endpoint")
    run.add_argument("--dry-run", action="store_true", help="never execute commands")
    run.add_argument("--allow-production", action="store_true",
                     help="change production assets directly on --prod-host")
    run.add_argument("--promote-dir", default=None,
                     help="queue validated production fixes here for approval")

    inv = run.add_argument_group("inventory")
    inv.add_argument("--inventory-source", choices=["file", "live"], default="file")
    inv.add_argument("--inventory", default=str(EXAMPLES / "inventory.json"),
                     help="inventory file (file source)")
    inv.add_argument("--collect", default="pip",
                     help="comma-separated collectors for the live source: "
                          + ",".join(sorted(COLLECTORS)))
    inv.add_argument("--environment", default="staging",
                     help="environment label for collected assets")
    inv.add_argument("--dpkg-ecosystem", default="Debian",
                     help="OSV ecosystem for dpkg assets, e.g. 'Debian:12'")

    staging = run.add_argument_group("remote staging (ssh)")
    staging.add_argument("--staging-host", default=None, help="run steps on this host over ssh")
    staging.add_argument("--staging-user", default=None)
    staging.add_argument("--staging-port", type=int, default=22)
    staging.add_argument("--ssh-identity", default=None, help="private key file (-i)")
    staging.add_argument("--ssh-known-hosts", default=None, help="pinned known_hosts file")
    staging.add_argument("--ssh-trust-new", action="store_true",
                         help="trust-on-first-use host keys (StrictHostKeyChecking=accept-new)")

    prod = run.add_argument_group("production (ssh, with --allow-production)")
    prod.add_argument("--prod-host", default=None, help="production host for direct changes")
    prod.add_argument("--prod-user", default=None)
    prod.add_argument("--prod-port", type=int, default=22)


def _add_promote_parser(sub) -> None:
    pr = sub.add_parser("promote", help="list or apply queued production promotions")
    pr.add_argument("--promote-dir", required=True, help="directory of queued promotion requests")
    pr.add_argument("--apply", metavar="ID", default=None,
                    help="apply a specific promotion request to production")
    pr.add_argument("--approve", action="store_true",
                    help="required to actually run the promotion on production")
    pr.add_argument("--approved-by", default=None, help="who approved this promotion")
    prod = pr.add_argument_group("production target (ssh)")
    prod.add_argument("--prod-host", default=None, help="production host (ssh); local if omitted")
    prod.add_argument("--prod-user", default=None)
    prod.add_argument("--prod-port", type=int, default=22)
    prod.add_argument("--ssh-identity", default=None)
    prod.add_argument("--ssh-known-hosts", default=None)
    prod.add_argument("--ssh-trust-new", action="store_true")


def _cmd_promote(args: argparse.Namespace) -> int:
    promoter = FilePromoter(args.promote_dir)
    requests = promoter.requests()

    if not args.apply:
        pending = [r for r in requests if r.result is None]
        print(f"{len(requests)} promotion request(s), {len(pending)} pending:")
        for r in requests:
            status = (r.result or "pending").upper()
            print(f"  [{status}] {r.id}  {r.advisory_id} -> {r.asset_id}  ({r.description})")
        return 0

    try:
        request = promoter.load(args.apply)
    except (FileNotFoundError, ValueError):
        print(f"no such promotion request: {args.apply}", file=sys.stderr)
        return 2

    if request.result == "applied":
        print(f"promotion {request.id} has already been applied", file=sys.stderr)
        return 1

    if not args.approve:
        print(f"Refusing to apply {request.id} to production without --approve.")
        print("Review the steps, then re-run with --approve:")
        for step in request.steps:
            print(f"  $ {step}")
        return 1

    request.approved = True
    request.approved_by = args.approved_by
    if args.prod_host:
        runner = _ssh_runner(args.prod_host, args.prod_user, args.prod_port,
                             args.ssh_identity, args.ssh_known_hosts, args.ssh_trust_new)
    else:
        runner = ShellRunner()

    try:
        ok, notes = apply_promotion(request, runner)
    except PromotionRefused as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        # Persist the approval and result even if the run raised part-way.
        promoter.save(request)
    for note in notes:
        print(note)
    print(f"promotion {request.id}: {'APPLIED' if ok else 'FAILED'}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fnh", description="Friendly Neighborhood Helminth — vuln-management pipeline"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    _add_run_parser(sub)
    _add_promote_parser(sub)

    args = parser.parse_args(argv)
    if args.command == "run":
        print(summarize(build_pipeline(args).run()))
        return 0
    if args.command == "promote":
        return _cmd_promote(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
