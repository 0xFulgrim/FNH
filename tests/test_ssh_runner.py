import subprocess

from fnh.executor import CommandResult, SSHRunner


def test_argv_defaults():
    argv = SSHRunner(host="stg.example")._argv("echo hi")
    assert argv[0] == "ssh"
    assert "BatchMode=yes" in argv
    assert "StrictHostKeyChecking=yes" in argv
    # Host-key checking is strict by default.
    assert "StrictHostKeyChecking=accept-new" not in argv
    # Target and the (single-arg) remote command come last.
    assert argv[-2:] == ["stg.example", "echo hi"]
    # Default port is not passed explicitly.
    assert "-p" not in argv


def test_argv_full_options():
    argv = SSHRunner(
        host="stg.example",
        user="deploy",
        port=2222,
        identity_file="/keys/id_ed25519",
        known_hosts="/etc/known_hosts",
        strict_host_key_checking="accept-new",
    )._argv("pip install --upgrade requests==2.32.0")
    assert "deploy@stg.example" in argv
    assert argv[argv.index("-p") + 1] == "2222"
    assert argv[argv.index("-i") + 1] == "/keys/id_ed25519"
    assert "IdentitiesOnly=yes" in argv
    assert "UserKnownHostsFile=/etc/known_hosts" in argv
    assert "StrictHostKeyChecking=accept-new" in argv
    # The command stays a single argv element (no local shell splitting).
    assert argv[-1] == "pip install --upgrade requests==2.32.0"


def test_command_not_locally_split():
    # A command with shell metacharacters must not be split on our side.
    argv = SSHRunner(host="h")._argv("echo $HOME && whoami")
    assert argv[-1] == "echo $HOME && whoami"


def test_run_captures_result(monkeypatch):
    captured = {}

    class FakeProc:
        returncode = 0
        stdout = "2.32.0\n"
        stderr = ""

    def fake_run(argv, capture_output, text, timeout):
        captured["argv"] = argv
        captured["timeout"] = timeout
        return FakeProc()

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = SSHRunner(host="h", user="u", timeout=42).run("pip show requests")
    assert isinstance(result, CommandResult)
    assert result.ok and result.stdout == "2.32.0\n"
    assert captured["argv"][-2:] == ["u@h", "pip show requests"]
    assert captured["timeout"] == 42


def test_run_timeout_is_surfaced(monkeypatch):
    def fake_run(*a, **k):
        raise subprocess.TimeoutExpired(cmd="ssh", timeout=1)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = SSHRunner(host="h").run("sleep 999")
    assert not result.ok
    assert result.returncode == 124
    assert "timed out" in result.stderr


def test_multiplexing_shares_one_private_control_socket():
    import os
    import stat
    runner = SSHRunner(host="h", user="u", port=2222)
    argv1, argv2 = runner._argv("a"), runner._argv("b")
    assert "ControlMaster=auto" in argv1 and "ControlPersist=60" in argv1
    path = next(a for a in argv1 if a.startswith("ControlPath="))
    assert path in argv2  # every command reuses the same master
    directory = os.path.dirname(path.split("=", 1)[1])
    assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700
    runner.close()
    assert not os.path.exists(directory)


def test_close_exits_master_with_matching_options(monkeypatch):
    calls = []
    runner = SSHRunner(host="h", user="u", port=2222)
    runner._argv("x")
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: calls.append(argv))
    runner.close()
    (argv,) = calls
    assert argv[-3:] == ["-O", "exit", "u@h"]
    assert "-p" in argv and any(a.startswith("ControlPath=") for a in argv)
    runner.close()  # idempotent
    assert len(calls) == 1


def test_multiplexing_can_be_disabled():
    argv = SSHRunner(host="h", multiplex=False)._argv("x")
    assert not any("Control" in a for a in argv)
