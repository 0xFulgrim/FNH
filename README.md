# vulnpilot

An autonomous vulnerability-management pipeline for **your own infrastructure**.

```
advisory feed  →  check infra (asset inventory)  →  match
      │
      ├─ patch available?  → stage the upgrade → validate on staging → (gate) promote to prod
      │
      └─ no patch?         → find mitigation    → apply on staging → verify it closes the gap
                                                        │
                                                        └─ still open / nothing to do → recommend next steps
```

This is the flow you described: *news feed → agent checks infra → deploys
patches; if no patch, check mitigations, test on staging, confirm the gap is
closed, otherwise recommend next steps.*

## Design principles

- **Staging first, always.** Every change is applied and validated on staging
  before anything is proposed for production.
- **Production is gated.** By default the tool never changes production on its
  own — those outcomes become `needs_review` with concrete recommendations.
  See `vulnpilot/safety.py`.
- **Validate, don't assume.** A remediation only counts as done when a
  validator confirms on staging that the vulnerability is actually closed
  (version assertion for patches; a targeted probe for mitigations).
- **Plans, not blind execution.** The planner emits steps and a rollback;
  the safety policy vets them (confidence threshold, severity floor, forbidden
  commands) before the executor runs anything.
- **Pluggable stages.** Each stage is an interface with a file-backed
  reference implementation so the whole pipeline runs offline.

## Try it

```bash
python -m vulnpilot run --dry-run
```

Runs against `examples/` with no network and no command execution. You'll see
three outcomes: a patch applied+validated, a mitigation applied+validated, and
one with no remediation that produces next-step recommendations.

## Modules

| Stage | File | Role |
|-------|------|------|
| 1. Feed | `feed.py` | Ingest advisories (CVE/OSV/GHSA). `FileFeed` for offline. |
| 2a. Inventory | `inventory.py` | Build the asset inventory (CMDB/SBOM/cloud API). |
| 2b. Match | `matcher.py` | Map advisories to affected assets by version range. |
| 3. Plan | `planner.py` | Choose a patch, else a mitigation from the library. |
| 4. Apply+validate | `executor.py` | Run on staging, confirm the gap is closed, roll back on failure. |
| 5. Recommend | `recommend.py` | Next steps + a Markdown report when automation can't finish. |
| Guardrails | `safety.py` | What may run automatically vs. needs a human. |
| Orchestrator | `pipeline.py` | Wires the stages together. |

## Going live

Swap the file-backed reference pieces for real ones on the same interfaces:

- `Feed` → an HTTPS client for OSV / NVD / GHSA.
- `Inventory` → your CMDB, cloud asset API, or collected SBOMs.
- `CommandRunner` → the `ShellRunner` (or a remote runner hitting staging over
  SSH / an orchestration API). Keep `DryRunner` for change previews.
- `Validator` → version checks per ecosystem plus mitigation probes that send
  safe, targeted requests to *your own* staging services.

Everything above production stays behind `SafetyPolicy`. Keep it that way.
