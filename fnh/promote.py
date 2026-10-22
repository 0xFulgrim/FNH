"""Stage 6 — promote a staging-validated fix to production (human-gated).

The autonomous pipeline never changes production on its own. When a fix is
validated on staging for a production asset, it is turned into a
`PromotionRequest` and recorded for a human to approve — think "open a change
ticket / PR", not "push to prod". Applying an *approved* request to production
is a separate, explicit action (`apply_promotion`) that refuses anything not
marked approved.
"""

from __future__ import annotations

import json
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from .models import Outcome


@dataclass
class PromotionRequest:
    advisory_id: str
    asset_id: str
    environment: str
    description: str
    steps: list[str]
    rollback: list[str] = field(default_factory=list)
    verify: Optional[str] = None
    created: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    approved: bool = False
    approved_by: Optional[str] = None

    @classmethod
    def from_outcome(cls, outcome: Outcome) -> "PromotionRequest":
        rem = outcome.remediation
        return cls(
            advisory_id=outcome.match.advisory.id,
            asset_id=outcome.match.asset.id,
            environment=outcome.match.asset.environment,
            description=rem.description if rem else "",
            steps=list(rem.steps) if rem else [],
            rollback=list(rem.rollback) if rem else [],
            verify=rem.verify if rem else None,
        )

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "PromotionRequest":
        known = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**known)


class Promoter(ABC):
    @abstractmethod
    def promote(self, outcome: Outcome) -> PromotionRequest:
        """Record a request to promote this validated fix to production."""
        raise NotImplementedError


class FilePromoter(Promoter):
    """Writes each promotion request to a directory as JSON (safe default).

    Nothing here touches production — it only records what *should* happen,
    for a human to review and approve.
    """

    def __init__(self, directory: str | Path):
        self.directory = Path(directory)

    def promote(self, outcome: Outcome) -> PromotionRequest:
        request = PromotionRequest.from_outcome(outcome)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._path(request.id).write_text(json.dumps(request.to_dict(), indent=2))
        return request

    def _path(self, request_id: str) -> Path:
        return self.directory / f"{request_id}.json"

    def load(self, request_id: str) -> PromotionRequest:
        return PromotionRequest.from_dict(json.loads(self._path(request_id).read_text()))

    def save(self, request: PromotionRequest) -> None:
        self._path(request.id).write_text(json.dumps(request.to_dict(), indent=2))

    def requests(self) -> list[PromotionRequest]:
        if not self.directory.exists():
            return []
        out = []
        for path in sorted(self.directory.glob("*.json")):
            try:
                out.append(PromotionRequest.from_dict(json.loads(path.read_text())))
            except (json.JSONDecodeError, OSError):
                continue
        return out


class PromotionRefused(Exception):
    """Raised when an unapproved request is handed to apply_promotion."""


def apply_promotion(request: PromotionRequest, runner) -> tuple[bool, list[str]]:
    """Execute an APPROVED promotion request against production via `runner`.

    Refuses outright unless `request.approved` is True. Runs the steps, then the
    verify probe if present; on any failure it runs the rollback and reports.
    """
    if not request.approved:
        raise PromotionRefused(
            f"promotion {request.id} ({request.advisory_id} -> {request.asset_id}) "
            "is not approved; refusing to touch production"
        )
    notes: list[str] = []
    for step in request.steps:
        result = runner.run(step)
        notes.append(f"$ {step} -> rc={result.returncode}")
        if not result.ok:
            notes.append(f"  step failed: {result.stderr.strip()[:200]}")
            _rollback(request, runner, notes)
            return False, notes

    if request.verify:
        result = runner.run(request.verify)
        ok = result.ok
        notes.append(f"verify -> {'closed' if ok else 'STILL OPEN'}")
        if not ok:
            _rollback(request, runner, notes)
            return False, notes

    return True, notes


def _rollback(request: PromotionRequest, runner, notes: list[str]) -> None:
    for step in request.rollback:
        result = runner.run(step)
        notes.append(f"rollback $ {step} -> rc={result.returncode}")
