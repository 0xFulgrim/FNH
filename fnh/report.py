"""Machine-readable run reports, the dashboard's data source.

`fnh run --report-dir DIR` writes one JSON file per run. Reports are plain
data: advisory text comes from external feeds, so anything rendering them
(like the dashboard) must treat every string as untrusted.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from .models import Outcome

SCHEMA_VERSION = 1
# run-20261023T044012.123456Z.json; sortable by name, safe to serve by name.
REPORT_NAME = re.compile(r"run-\d{8}T\d{6}\.\d{6}Z\.json")
# Keep reports small: references and notes are context, not the data.
_MAX_REFERENCES = 10


def build_report(outcomes: Iterable[Outcome], *, sources: list[str],
                 inventory_source: str, dry_run: bool,
                 generated_at: Optional[datetime] = None) -> dict:
    outcomes = list(outcomes)
    generated_at = generated_at or datetime.now(timezone.utc)
    return {
        "schema": SCHEMA_VERSION,
        "generated_at": generated_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "sources": list(sources),
        "inventory_source": inventory_source,
        "dry_run": dry_run,
        "summary": {
            "total": len(outcomes),
            "by_status": dict(Counter(o.status.value for o in outcomes)),
            "by_severity": dict(Counter(o.match.advisory.severity.value for o in outcomes)),
        },
        "outcomes": [_outcome(o) for o in outcomes],
    }


def _outcome(o: Outcome) -> dict:
    adv, asset, rem = o.match.advisory, o.match.asset, o.remediation
    return {
        "advisory": {
            "id": adv.id,
            "title": adv.title,
            "severity": adv.severity.value,
            "cvss": adv.cvss,
            "source": adv.source,
            "references": adv.references[:_MAX_REFERENCES],
        },
        "asset": {
            "id": asset.id,
            "name": asset.name,
            "ecosystem": asset.ecosystem,
            "version": asset.version,
            "environment": asset.environment,
        },
        "status": o.status.value,
        "validated": o.validated,
        "reason": o.match.reason,
        "remediation": None if rem is None else {
            "kind": rem.kind.value,
            "description": rem.description,
            "target_version": rem.target_version,
            "steps": list(rem.steps),
        },
        "notes": list(o.notes),
        "recommendations": list(o.recommendations),
    }


def write_report(report: dict, directory: str | Path) -> Path:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.strptime(report["generated_at"], "%Y-%m-%dT%H:%M:%S.%fZ")
    path = directory / f"run-{stamp.strftime('%Y%m%dT%H%M%S.%f')}Z.json"
    # Write then rename, so a dashboard reading the directory never sees half a file.
    tmp = path.with_suffix(".json.tmp")
    # Compact: reports are machine-read, and this parses noticeably faster.
    tmp.write_text(json.dumps(report, separators=(",", ":")))
    tmp.replace(path)
    return path


def list_reports(directory: str | Path) -> list[Path]:
    """Report files in `directory`, oldest first."""
    directory = Path(directory)
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.iterdir() if REPORT_NAME.fullmatch(p.name))


def load_report(directory: str | Path, name: str) -> Optional[dict]:
    """A report by file name, or None. Names that aren't report names are
    rejected, so a caller can't read other files through this."""
    if not REPORT_NAME.fullmatch(name):
        return None
    path = Path(directory) / name
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
