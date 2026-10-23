# Friendly Neighborhood Helminth (`fnh`)

[![CI](https://github.com/0xFulgrim/FNH/actions/workflows/ci.yml/badge.svg)](https://github.com/0xFulgrim/FNH/actions/workflows/ci.yml)

An autonomous vulnerability-management pipeline for **your own infrastructure**.
Like a benign gut symbiont, it lives inside your estate and quietly keeps it
healthy — watching advisories, checking what you run, and closing gaps on
staging before anything reaches production.

```
advisory feed  →  check infra (asset inventory)  →  match
      │
      ├─ patch available?  → apply on staging → validate → (prod) queue promotion for approval
      │
      └─ no patch?         → find mitigation   → apply on staging → probe that the gap is closed
                                                        │
                                                        └─ still open / nothing to do → recommend next steps
```

This is the flow you described: *news feed → agent checks infra → deploys
patches; if no patch, check mitigations, test on staging, confirm the gap is
closed, otherwise recommend next steps* — with a human-gated promotion step to
carry a staging-validated fix into production.

## Design principles

- **Staging first, always.** Every change is applied and validated on staging
  before anything is proposed for production.
- **Production is gated.** The tool never changes production on its own. A
  production fix that validates on staging becomes a **promotion request** a
  human must approve (`fnh promote`); without a promoter it's `needs_review`.
- **Validate, don't assume.** A remediation only counts as done when a
  validator confirms on staging that the vulnerability is actually closed
  (version assertion for patches; a real probe for mitigations, see `probes.py`).
- **Plans, not blind execution.** The planner emits steps and a rollback; the
  safety policy vets them (confidence threshold, severity floor, forbidden
  commands) before the executor runs anything.
- **Pluggable stages.** Each stage is an interface with a reference
  implementation, so the whole pipeline runs offline.

## Try it

```bash
# Offline: example advisories, no network, no command execution.
python -m fnh run --dry-run

# Live advisories from osv.dev for the packages in your inventory, cached.
python -m fnh run --source osv --cache .osv-cache.json --dry-run

# Inventory a real host and queue any production fixes for approval.
python -m fnh run --source osv \
  --inventory-source live --collect pip,dpkg --environment production \
  --staging-host staging.internal --staging-user deploy \
  --promote-dir ./promotions

# Review and apply queued production promotions (human-gated).
python -m fnh promote --promote-dir ./promotions
python -m fnh promote --promote-dir ./promotions --apply <id> --approve \
  --prod-host prod.internal --prod-user deploy
```

## Stages

| Stage | File | Role |
|-------|------|------|
| 1. Feed | `feed.py`, `osv.py` | Ingest advisories. `FileFeed` (offline) or `OSVFeed` (live). |
| 2a. Inventory | `inventory.py` | `FileInventory`, or `LiveInventory` collecting from a host. |
| 2b. Match | `matcher.py` | Map advisories to affected assets by version range. |
| 3. Plan | `planner.py` | Choose a patch, else a mitigation (with a verify probe). |
| 4. Apply+validate | `executor.py` | Run on staging, confirm the gap is closed, roll back on failure. |
| 5. Recommend | `recommend.py` | Next steps + a Markdown report when automation can't finish. |
| 6. Promote | `promote.py` | Queue a staging-validated prod fix for human approval; apply when approved. |
| Guardrails | `safety.py` | What may run automatically vs. needs a human. |
| CVSS / Probes | `cvss.py`, `probes.py` | Score vectors; build "is it closed?" checks. |
| Orchestrator | `pipeline.py` | Wires the stages together. |

## Live advisory source: OSV (`--source osv`)

`osv.py` queries [osv.dev](https://osv.dev) — a free, no-auth database
aggregating GHSA, PyPA, RustSec, Debian, and more. It discovers advisories for
all inventory packages in **one batch request** (`/v1/querybatch`, following
pagination), fetches each full record from `/v1/vulns/{id}` served from an
optional **on-disk cache** (`--cache`) keyed on the record's `modified`
timestamp, maps ecosystems (`pypi` → `PyPI`), converts OSV ranges into the
matcher's constraints, and computes a CVSS base score from the vector
(`cvss.py`). `--no-batch` falls back to one `/v1/query` per package.

> **Network note:** a live OSV fetch needs outbound access to `api.osv.dev`;
> in a restricted environment that host must be allowlisted in the network
> policy, or the request is denied at the proxy.

## Live inventory (`--inventory-source live`)

`LiveInventory` collects installed packages from a host by running collectors
through the same `CommandRunner` the executor uses (local or over SSH), so you
inventory and remediate the same box:

- `pip` — `pip list --format=json` (ecosystem `pypi`)
- `dpkg` — `dpkg-query` (pass `--dpkg-ecosystem Debian:12` to match OSV)
- `npm` — `npm ls --json --depth=0` (ecosystem `npm`)

## Remote staging runner (SSH)

`SSHRunner` (`executor.py`) runs remediation steps on a remote staging host via
the system `ssh` client — no third-party deps. The command is passed as a
single argument, so there's no local shell to inject into, and host-key
checking is strict by default (pin a `known_hosts` file; `--ssh-trust-new` is
trust-on-first-use). Local `ShellRunner` is the default; `DryRunner` previews.

## Mitigation probes (`probes.py`)

A mitigation is only trusted once a probe confirms it. A probe is a small, safe
command run against *your own* staging service whose exit code is the verdict
(0 = closed). The mitigation library declares one instead of hand-writing shell:

```json
"CVE-2026-0002": {
  "steps": ["..."],
  "verify": {"probe": "http_status", "url": "https://stg/", "expect": 400}
}
```

Built-ins: `http_status`, `http_header_absent`, `port_closed`, `command_fails`.
A raw string `verify` is also honored verbatim.

## Promotion (`fnh promote`)

Production changes never happen autonomously. When a production fix validates on
staging, it's recorded as a `PromotionRequest` (think "open a change ticket").
`fnh promote` lists pending requests; `--apply <id> --approve` executes an
**approved** request against production (`apply_promotion` refuses anything not
approved), running the verify probe and rolling back on failure.

Everything above production stays behind `SafetyPolicy`. Keep it that way.

## Zero dependencies

Pure Python standard library at runtime (`pytest` only for the test suite).
Every network and command boundary is injectable, so `python -m pytest` runs
the whole thing offline.
