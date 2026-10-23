# FNH (Friendly Neighborhood Helminth)

[![CI](https://github.com/0xFulgrim/FNH/actions/workflows/ci.yml/badge.svg)](https://github.com/0xFulgrim/FNH/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

FNH matches vulnerability advisories against the software you run, applies
patches or mitigations on a staging host, checks that the fix worked, and
queues validated production changes for approval.

It is meant for infrastructure you own and operate.

## Features

- Advisories from [OSV](https://osv.dev) (batch queries, on-disk cache) or a local JSON file
- Inventory from a JSON file, or collected live from a host with `pip`, `dpkg` and `npm`
- Version-range matching and CVSS v3 base scoring
- Patch selection, with a fallback to a mitigation library
- Remediation runs locally or on a remote staging host over SSH
- Post-fix validation: version checks for patches, HTTP/TCP probes for mitigations
- Automatic rollback when a step or validation fails
- Production changes are written out as promotion requests and applied only with `--approve`
- No runtime dependencies outside the Python standard library

## Installation

Requires Python 3.10 or later.

```bash
git clone https://github.com/0xFulgrim/FNH.git
cd FNH
pip install -e .
```

This installs the `fnh` command. `python -m fnh` also works.

The remote runner uses the system `ssh` client. Mitigation probes use `curl`
and `bash` on the staging host.

## Quick start

Run against the bundled examples. `--dry-run` prints the commands without
executing anything:

```bash
fnh run --dry-run
```

```
## Summary
- mitigated: 1
- needs_review: 1
- patched: 1

## CVE-2026-0001 — requests [patched]
- severity: high
- why: requests 2.31.0 satisfies vulnerable range '<2.32.0'
- remediation: Upgrade requests to 2.32.0 (kind=patch, validated=True)
...
```

## Usage

### Scan and remediate

```bash
# OSV advisories for the packages in an inventory file
fnh run --source osv --inventory inventory.json --cache .osv-cache.json

# Collect packages from a staging host and remediate there
fnh run --source osv \
  --inventory-source live --collect pip,dpkg --dpkg-ecosystem Debian:12 \
  --staging-host staging.internal --staging-user deploy \
  --ssh-identity ~/.ssh/fnh --ssh-known-hosts ./known_hosts

# Queue production fixes that pass on staging
fnh run --source osv --inventory inventory.json --promote-dir ./promotions
```

| Flag | Description |
|------|-------------|
| `--source {file,osv}` | Advisory source (default `file`) |
| `--advisories PATH` | Advisory file for `--source file` |
| `--cache PATH` | OSV record cache file |
| `--no-batch` | One OSV `/v1/query` per package instead of `/v1/querybatch` |
| `--inventory-source {file,live}` | Inventory source (default `file`) |
| `--inventory PATH` | Inventory file for `--inventory-source file` |
| `--collect LIST` | Live collectors: `pip`, `dpkg`, `npm` (default `pip`) |
| `--environment NAME` | Environment label for collected assets (default `staging`) |
| `--dpkg-ecosystem NAME` | OSV ecosystem for dpkg packages, e.g. `Debian:12` |
| `--mitigations PATH` | Mitigation library |
| `--staging-host HOST` | Run steps on this host over SSH (local if omitted) |
| `--staging-user`, `--staging-port` | SSH user and port |
| `--ssh-identity PATH` | SSH private key |
| `--ssh-known-hosts PATH` | Pinned known_hosts file |
| `--ssh-trust-new` | Accept unknown host keys on first connect |
| `--promote-dir DIR` | Write promotion requests here |
| `--allow-production` | Change production assets directly on `--prod-host` |
| `--prod-host HOST` | Production host over SSH (required with `--allow-production`) |
| `--prod-user`, `--prod-port` | SSH user and port for the production host |
| `--dry-run` | Print commands, execute nothing |

### Promote to production

```bash
# List requests
fnh promote --promote-dir ./promotions

# Show the steps for one request
fnh promote --promote-dir ./promotions --apply 3f1c9a2b7d10

# Apply it
fnh promote --promote-dir ./promotions --apply 3f1c9a2b7d10 --approve \
  --approved-by alice --prod-host prod.internal --prod-user deploy
```

Without `--approve`, `promote --apply` prints the steps and exits 1. With it,
the steps run on the production host and the result is checked: the verify
probe for mitigations, the installed version for patches. The rollback runs if
either fails. The outcome is saved on the request, and an applied request
can't be applied again. Repeated `fnh run`s reuse a pending request instead of
queuing duplicates.

## Input formats

### Inventory

```json
[
  {"id": "api-requests", "name": "requests", "ecosystem": "pypi",
   "version": "2.31.0", "environment": "staging"}
]
```

Supported `ecosystem` values for OSV lookups: `pypi`, `npm`, `go`, `maven`,
`nuget`, `cargo`, `rubygems`, `composer`, `pub`, `hex`, or any OSV ecosystem
name such as `Debian:12`.

### Advisories (`--source file`)

```json
[
  {"id": "CVE-2026-0001", "cvss": 8.1,
   "affected": [{"ecosystem": "pypi", "name": "requests"}],
   "vulnerable_ranges": ["<2.32.0"], "fixed_versions": ["2.32.0"]}
]
```

When an advisory covers several packages with different ranges, give each
`affected` entry its own `"ranges"` and `"fixed"` lists; they override the
advisory-wide ones for that package.

### Mitigation library

Entries are keyed by advisory ID or package name. `verify` is a probe spec
or a shell command. Exit status 0 means the issue is closed.

```json
{
  "CVE-2026-0002": {
    "description": "Reject malformed chunked bodies at the edge",
    "steps": ["cp hardening.conf /etc/nginx/conf.d/", "nginx -t", "nginx -s reload"],
    "rollback": ["rm /etc/nginx/conf.d/hardening.conf", "nginx -s reload"],
    "confidence": 0.8,
    "verify": {"probe": "http_status", "url": "https://staging.internal/",
               "method": "POST", "header": "Transfer-Encoding: chunked",
               "data": "malformed", "expect": 400}
  }
}
```

| Probe | Passes when | Fields |
|-------|-------------|--------|
| `http_status` | Response code equals `expect` | `url`, `expect`, `method`, `header`, `data`, `insecure`, `timeout` |
| `http_header_absent` | Response lacks `header` | `url`, `header`, `insecure`, `timeout` |
| `port_closed` | TCP connect fails | `host`, `port`, `timeout` |
| `command_fails` | `cmd` exits non-zero | `cmd` |

## How it works

1. Load advisories and inventory.
2. Match advisories to assets by ecosystem, name and version range.
3. Plan a remediation: the lowest fixed version above the installed one,
   otherwise a mitigation library entry, otherwise none.
4. Check the plan against the safety policy.
5. Apply on staging, validate, and roll back on failure.
6. For production assets, write a promotion request if a promoter is configured.
7. Print a Markdown report with next steps for anything left open.

Outcome states: `patched`, `mitigated`, `awaiting_promotion`, `needs_review`, `failed`.

## Safety defaults

Defined in `fnh/safety.py`:

- Steps run automatically only for `staging` assets.
- Production needs approval through `fnh promote`, unless `--allow-production` is
  set with a `--prod-host`. Production commands never run on the staging host.
- The plan checks below also apply to fixes validated on staging for promotion.
- Plans need confidence of at least 0.75 and severity of at least `high`.
- Steps containing `rm -rf /`, `mkfs`, `dd if=`, `> /dev/sd` or a fork bomb are refused.
- Without a probe, a mitigation on a live host is not counted as validated.
- SSH runs with `BatchMode=yes` and `StrictHostKeyChecking=yes` by default.

## Limitations

- Versions are compared with dpkg ordering for Debian and Ubuntu, PEP 440 for
  PyPI and SemVer 2.0 for npm. Other ecosystems, and versions that don't parse,
  fall back to the leading dotted numeric part, so their pre-releases compare
  equal to the release.
- Automated patching covers pip, npm and apt. Other ecosystems get a plan that
  needs a human.
- CVSS v4 vectors are not scored. FNH falls back to the severity label in the
  OSV record.
- Inventory entries with a generic `os` ecosystem are skipped for OSV lookups.
  Use a specific ecosystem like `Debian:12`.
- Live OSV queries need outbound HTTPS to `api.osv.dev`.

## Development

```bash
pip install -e ".[dev]"
python -m pyflakes fnh tests
python -m pytest
```

Tests use injected transports and runners, so they run without network access or SSH.

| Module | Purpose |
|--------|---------|
| `feed.py`, `osv.py` | Advisory sources |
| `inventory.py` | File and live inventory |
| `matcher.py` | Version-range matching |
| `planner.py` | Patch or mitigation selection |
| `executor.py` | Runners and validators |
| `probes.py` | Verify command builders |
| `promote.py` | Promotion requests |
| `safety.py` | Safety policy |
| `cvss.py` | CVSS v3 scoring |
| `recommend.py` | Report output |
| `pipeline.py` | Orchestration |

## License

MIT. See [LICENSE](LICENSE).
