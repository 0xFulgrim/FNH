"""Stage 4 — apply on staging and validate.

Flow for one match:
  1. Apply the remediation steps on the *staging* copy of the asset.
  2. Run a validator that checks whether the vulnerability is still present.
     This is the authorized "does the fix actually hold?" check — a version
     assertion and/or a safe reproduction probe against your own staging
     service. If the gap is confirmed closed, the remediation is sound.
  3. Nothing here ever touches production; promotion is a separate, gated
     step (see pipeline + safety).

All command execution goes through `CommandRunner` so dry-run and tests never
shell out.
"""

from __future__ import annotations

import shlex
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .matcher import _cmp
from .models import Match, Remediation, RemediationKind


@dataclass
class CommandResult:
    command: str
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandRunner(ABC):
    @abstractmethod
    def run(self, command: str) -> CommandResult:
        raise NotImplementedError


class DryRunner(CommandRunner):
    """Records commands instead of executing them."""

    def __init__(self) -> None:
        self.log: list[str] = []

    def run(self, command: str) -> CommandResult:
        self.log.append(command)
        return CommandResult(command=command, returncode=0, stdout="[dry-run]")


class ShellRunner(CommandRunner):
    """Executes against a real (staging) target. Use with a safety policy."""

    def __init__(self, timeout: int = 300):
        self.timeout = timeout

    def run(self, command: str) -> CommandResult:
        proc = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=self.timeout
        )
        return CommandResult(
            command=command,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )


@dataclass
class SSHRunner(CommandRunner):
    """Executes commands on a remote *staging* host over the ssh CLI.

    Uses the system `ssh` client (no third-party deps). The remediation
    command is passed as a single argument, so there is no local shell to
    inject into; ssh hands it to the remote login shell exactly as written —
    the same execution model as ShellRunner, but on the staging box.

    Host-key checking is on by default. Point `known_hosts` at a pinned file
    for the strongest guarantee; `strict_host_key_checking="accept-new"` will
    trust-on-first-use, and only an explicit opt-out disables checking.

    Intended for staging only. Combined with SafetyPolicy (which restricts
    autonomous changes to staging environments and vets every step), this
    runner never reaches production on its own.
    """

    host: str
    user: str | None = None
    port: int = 22
    identity_file: str | None = None
    known_hosts: str | None = None
    # "yes" (require known host), "accept-new" (TOFU), or "no" (opt-out).
    strict_host_key_checking: str = "yes"
    connect_timeout: int = 15
    timeout: int = 300
    extra_opts: list[str] = field(default_factory=list)

    @property
    def target(self) -> str:
        return f"{self.user}@{self.host}" if self.user else self.host

    def _argv(self, command: str) -> list[str]:
        argv = [
            "ssh",
            "-o", "BatchMode=yes",  # never block on a password/passphrase prompt
            "-o", f"ConnectTimeout={self.connect_timeout}",
            "-o", f"StrictHostKeyChecking={self.strict_host_key_checking}",
        ]
        if self.known_hosts:
            argv += ["-o", f"UserKnownHostsFile={shlex.quote(self.known_hosts)}"]
        if self.identity_file:
            argv += ["-i", self.identity_file, "-o", "IdentitiesOnly=yes"]
        if self.port != 22:
            argv += ["-p", str(self.port)]
        argv += list(self.extra_opts)
        # The remote command is one argv element; ssh runs it via the remote shell.
        argv += [self.target, command]
        return argv

    def run(self, command: str) -> CommandResult:
        try:
            proc = subprocess.run(
                self._argv(command),
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(command, returncode=124, stderr="ssh timed out")
        return CommandResult(
            command=command,
            returncode=proc.returncode,  # ssh returns 255 on connection failure
            stdout=proc.stdout,
            stderr=proc.stderr,
        )


class Validator(ABC):
    """Answers: after remediation, is the asset still vulnerable?"""

    @abstractmethod
    def is_closed(self, match: Match, remediation: Remediation, runner: CommandRunner) -> bool:
        """Return True if the vulnerability is confirmed closed on staging."""
        raise NotImplementedError


class VersionValidator(Validator):
    """For patches: confirm the installed version is now at/above the fix."""

    def is_closed(self, match: Match, remediation: Remediation, runner: CommandRunner) -> bool:
        if remediation.kind != RemediationKind.PATCH or not remediation.target_version:
            # Nothing version-based to assert; defer to another validator.
            return False
        installed = self._installed_version(match, runner)
        if installed is None:
            return False
        return _cmp(installed, remediation.target_version) >= 0

    @staticmethod
    def _installed_version(match: Match, runner: CommandRunner) -> str | None:
        # Under dry-run there is no live target to query; report the version the
        # patch would have produced so the flow validates end to end.
        if isinstance(runner, DryRunner):
            return match.advisory.fixed_versions[0] if match.advisory.fixed_versions else None
        eco, name = match.asset.ecosystem, match.asset.name
        if eco == "pypi":
            r = runner.run(f"pip show {name} | awk '/^Version:/ {{print $2}}'")
            return r.stdout.strip() or None
        # Other ecosystems: extend as needed.
        return None


class MitigationValidator(Validator):
    """For mitigations: run a `verify` probe against staging.

    A probe sends a safe, targeted request to your own staging service and
    asserts the now-hardened response — a single command whose exit code is the
    verdict (0 == closed). The command comes from the remediation itself (built
    from the mitigation library's probe spec, see probes.py); a fallback probe
    may be supplied to the constructor. Under a DryRunner there is nothing to
    probe, so an applied mitigation is assumed to hold for reporting purposes.

    `assume_closed_without_probe` controls the live-runner behavior when no
    probe is configured: False (default, strict) refuses to claim closure it
    cannot prove; True trusts the applied steps.
    """

    def __init__(
        self,
        verify_command: str | None = None,
        assume_closed_without_probe: bool = False,
    ):
        self.verify_command = verify_command
        self.assume_closed_without_probe = assume_closed_without_probe

    def is_closed(self, match: Match, remediation: Remediation, runner: CommandRunner) -> bool:
        if remediation.kind != RemediationKind.MITIGATION:
            return False
        if isinstance(runner, DryRunner):
            return True
        probe = remediation.verify or self.verify_command
        if not probe:
            # No probe configured — only claim closure if explicitly trusted.
            return self.assume_closed_without_probe
        return runner.run(probe).ok


class ChainValidator(Validator):
    """First validator that can speak to this remediation kind wins."""

    def __init__(self, validators: list[Validator]):
        self.validators = validators

    def is_closed(self, match: Match, remediation: Remediation, runner: CommandRunner) -> bool:
        patch_like = remediation.kind == RemediationKind.PATCH
        for v in self.validators:
            if patch_like and isinstance(v, VersionValidator):
                return v.is_closed(match, remediation, runner)
            if not patch_like and isinstance(v, MitigationValidator):
                return v.is_closed(match, remediation, runner)
        return False


class Executor:
    def __init__(self, runner: CommandRunner, validator: Validator):
        self.runner = runner
        self.validator = validator

    def apply_and_validate(self, match: Match, remediation: Remediation) -> tuple[bool, list[str]]:
        """Apply steps on staging, then validate. Returns (closed, notes)."""
        notes: list[str] = []
        for step in remediation.steps:
            result = self.runner.run(step)
            notes.append(f"$ {step} -> rc={result.returncode}")
            if not result.ok:
                notes.append(f"  step failed: {result.stderr.strip()[:200]}")
                self._rollback(remediation, notes)
                return False, notes

        closed = self.validator.is_closed(match, remediation, self.runner)
        notes.append(f"validation: {'closed' if closed else 'STILL OPEN'}")
        if not closed:
            # Remediation did not hold on staging; undo it so staging is clean.
            self._rollback(remediation, notes)
        return closed, notes

    def _rollback(self, remediation: Remediation, notes: list[str]) -> None:
        for step in remediation.rollback:
            result = self.runner.run(step)
            notes.append(f"rollback $ {step} -> rc={result.returncode}")
