"""Stage 4 — apply a remediation and validate it.

For one match:
  1. Run the remediation steps through a `CommandRunner` (staging by default).
  2. Ask a validator whether the vulnerability is still present: a version
     check for patches, the verify probe for mitigations.
  3. Roll back if a step fails or validation doesn't confirm the fix.

All command execution goes through `CommandRunner` so dry-run and tests never
shell out. Production is only touched through an explicit production runner.
"""

from __future__ import annotations

import atexit
import json
import os
import shlex
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from functools import cmp_to_key

from .matcher import _cmp
from .models import Match, Remediation, RemediationKind
from .planner import is_apt_ecosystem


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
        try:
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=self.timeout
            )
        except subprocess.TimeoutExpired:
            return CommandResult(command, returncode=124, stderr="command timed out")
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

    Commands share one connection (OpenSSH multiplexing) through a control
    socket in a private temporary directory, so a run pays for one SSH
    handshake instead of one per command. The master connection closes when
    the process exits. Set `multiplex=False` to open a connection per command.
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
    multiplex: bool = True
    control_persist: int = 60  # seconds the shared connection outlives its last use
    _control_dir: str | None = field(default=None, init=False, repr=False)

    @property
    def target(self) -> str:
        return f"{self.user}@{self.host}" if self.user else self.host

    def _control_path(self) -> str:
        if self._control_dir is None:
            # mkdtemp is private (0700): nobody else can use our socket.
            self._control_dir = tempfile.mkdtemp(prefix="fnh-ssh-")
            atexit.register(self.close)
        # %C is a hash of host, port and user: short enough for a socket path.
        return os.path.join(self._control_dir, "%C")

    def close(self) -> None:
        """Close the shared connection, if one was opened."""
        if self._control_dir is None:
            return
        try:
            subprocess.run(self._options() + ["-O", "exit", self.target],
                           capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            pass
        shutil.rmtree(self._control_dir, ignore_errors=True)
        self._control_dir = None

    def _argv(self, command: str) -> list[str]:
        # The remote command is one argv element; ssh runs it via the remote shell.
        return self._options() + [self.target, command]

    def _options(self) -> list[str]:
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
        if self.multiplex:
            argv += [
                "-o", "ControlMaster=auto",
                "-o", f"ControlPath={self._control_path()}",
                "-o", f"ControlPersist={self.control_persist}",
            ]
        argv += list(self.extra_opts)
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


def installed_version(ecosystem: str | None, name: str, runner: CommandRunner) -> str | None:
    """Version of `name` installed on the runner's host, or None if unknown."""
    quoted = shlex.quote(name)
    if ecosystem == "pypi":
        r = runner.run(f"python3 -m pip show {quoted} | awk '/^Version:/ {{print $2}}'")
    elif ecosystem == "npm":
        r = runner.run(f"npm ls {quoted} --json --depth=0")
        try:
            deps = json.loads(r.stdout or "{}").get("dependencies", {}) or {}
        except json.JSONDecodeError:
            return None
        return (deps.get(name) or {}).get("version")
    elif is_apt_ecosystem(ecosystem):
        # `name` is a source package (see DpkgCollector). Every installed
        # binary built from it must be fixed, so report the lowest version.
        r = runner.run(
            r"dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${source:Package}"
            r"\t${source:Version}\n'"
        )
        if not r.ok:
            return None
        versions = []
        for line in r.stdout.splitlines():
            fields = [f.strip() for f in line.split("\t")]
            if len(fields) == 4 and fields[0].startswith("ii") and name in (fields[1], fields[2]):
                versions.append(fields[3])
        return min(versions, key=cmp_to_key(lambda a, b: _cmp(a, b, ecosystem)), default=None)
    else:
        return None
    if not r.ok:
        return None
    return r.stdout.strip() or None


class VersionValidator(Validator):
    """For patches: confirm the installed version is now at/above the fix."""

    def is_closed(self, match: Match, remediation: Remediation, runner: CommandRunner) -> bool:
        if remediation.kind != RemediationKind.PATCH or not remediation.target_version:
            return False
        # Under dry-run there is no live target to query; assume the planned
        # version was installed so the flow validates end to end.
        if isinstance(runner, DryRunner):
            return True
        eco = match.asset.ecosystem
        installed = installed_version(eco, match.asset.name, runner)
        if installed is None:
            return False
        return _cmp(installed, remediation.target_version, eco) >= 0


class MitigationValidator(Validator):
    """For mitigations: run the remediation's `verify` probe.

    A probe is a single command whose exit code is the verdict (0 == closed),
    built from the mitigation library's probe spec (see probes.py). Without a
    probe, a live host is never reported as fixed. Under a DryRunner there is
    nothing to probe, so an applied mitigation is assumed to hold.
    """

    def is_closed(self, match: Match, remediation: Remediation, runner: CommandRunner) -> bool:
        if remediation.kind != RemediationKind.MITIGATION:
            return False
        if isinstance(runner, DryRunner):
            return True
        if not remediation.verify:
            return False
        return runner.run(remediation.verify).ok


class DefaultValidator(Validator):
    """Version check for patches, verify probe for mitigations."""

    def __init__(self) -> None:
        self._by_kind = {
            RemediationKind.PATCH: VersionValidator(),
            RemediationKind.MITIGATION: MitigationValidator(),
        }

    def is_closed(self, match: Match, remediation: Remediation, runner: CommandRunner) -> bool:
        validator = self._by_kind.get(remediation.kind)
        return validator is not None and validator.is_closed(match, remediation, runner)


class Executor:
    def __init__(
        self,
        runner: CommandRunner,
        validator: Validator | None = None,
        production_runner: CommandRunner | None = None,
    ):
        # `runner` is the staging runner. Production assets are only acted on
        # directly when a separate production runner is supplied.
        self.runner = runner
        self.validator = validator or DefaultValidator()
        self.production_runner = production_runner

    def runner_for(self, environment: str) -> CommandRunner | None:
        if environment == "production":
            return self.production_runner
        return self.runner

    def apply_and_validate(
        self,
        match: Match,
        remediation: Remediation,
        runner: CommandRunner | None = None,
    ) -> tuple[bool, list[str]]:
        """Apply steps via `runner` (staging by default), then validate."""
        runner = runner or self.runner
        notes: list[str] = []
        if not remediation.steps:
            notes.append("no automated steps for this remediation")
            return False, notes
        for step in remediation.steps:
            result = runner.run(step)
            notes.append(f"$ {step} -> rc={result.returncode}")
            if not result.ok:
                notes.append(f"  step failed: {result.stderr.strip()[:200]}")
                self._rollback(remediation, notes, runner)
                return False, notes

        closed = self.validator.is_closed(match, remediation, runner)
        notes.append(f"validation: {'closed' if closed else 'STILL OPEN'}")
        if not closed:
            # Remediation did not hold; undo it so the host is left as found.
            self._rollback(remediation, notes, runner)
        return closed, notes

    def _rollback(self, remediation: Remediation, notes: list[str], runner: CommandRunner) -> None:
        if not remediation.rollback:
            notes.append("no rollback defined; host left as modified")
        for step in remediation.rollback:
            result = runner.run(step)
            notes.append(f"rollback $ {step} -> rc={result.returncode}")
