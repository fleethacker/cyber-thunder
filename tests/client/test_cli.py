import io
import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from cyberthunder.cli import main
from cyberthunder.client import cli
from cyberthunder.client.api import perform
from cyberthunder.client.errors import ClientError
from cyberthunder.client.http import Response


@pytest.fixture
def dispatch(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("remote command constructed local application state")
    monkeypatch.setattr("cyberthunder.cli.Settings.from_env", forbidden)
    monkeypatch.setattr("cyberthunder.cli._ctx", forbidden)
    monkeypatch.setattr(cli.ClientProfile, "load", lambda _: object())
    monkeypatch.setenv("CT_AUTH_MODE", "oidc")
    monkeypatch.setenv("CT_ACTOR", "typed-untrusted")


@pytest.mark.parametrize("actor", ["--actor", "--act", "--actor=typed", "--act=typed"])
def test_typed_actor_rejected_before_profile_or_local_context(dispatch, monkeypatch, capsys, actor):
    monkeypatch.setattr(cli.ClientProfile, "load", lambda _: pytest.fail("profile read before actor rejection"))
    argv = [actor] + ([] if "=" in actor else ["typed"])
    assert main(argv + ["auth", "--profile", "unused", "status"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "typed_actor_not_supported"


def test_explicit_remote_dispatch_ignores_legacy_actor_and_never_creates_context(dispatch, monkeypatch, capsys):
    monkeypatch.setattr(cli, "ClientAuth", lambda _: SimpleNamespace(status=lambda: ({"status": "logged_out", "verified": False}, 3)))
    assert main(["auth", "--profile", "unused", "status"]) == 3
    assert json.loads(capsys.readouterr().out) == {"status": "logged_out", "verified": False}


def test_login_requires_terminal_before_network_or_profile(dispatch, monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO())
    monkeypatch.setattr(cli.ClientProfile, "load", lambda _: pytest.fail("profile read before terminal check"))
    assert main(["auth", "--profile", "unused", "login"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "interactive_terminal_required"


@pytest.mark.parametrize("status,state", [(202, "applying"), (200, "proposed"), (200, "approved")])
def test_structured_operation_and_pending_quorum_exit(dispatch, monkeypatch, capsys, status, state):
    class Auth:
        def __init__(self, _):
            self.http = SimpleNamespace(request=lambda *a, **k: Response(status, {"id": "proposal-1", "state": state}))
        @contextmanager
        def access(self): yield "fixture-secret"
    monkeypatch.setattr(cli, "ClientAuth", Auth)
    monkeypatch.setattr(cli.sys, "stdin", io.TextIOWrapper(io.BytesIO(b'{"note":"Fixture review","assessment_note":"Reviewed"}')))
    code = main(["api", "--profile", "unused", "decisions", "approve", "proposal-1", "--stdin"])
    data = json.loads(capsys.readouterr().out)
    assert code == (0 if state == "approved" else 4)
    assert data["status"] == ("completed" if state == "approved" else "accepted_pending")
    assert data["operation_id"] == "proposal-1" and data["http_status"] == status


@pytest.mark.parametrize("status", [401, 403, 409, 423])
def test_server_denial_redacted_and_post_never_retried(dispatch, monkeypatch, capsys, status):
    calls = []
    class Auth:
        def __init__(self, _): self.http = self
        @contextmanager
        def access(self): yield "fixture-private-token"
        def request(self, *a, **kw):
            calls.append(kw)
            return Response(status, {"detail": "fixture-private-token", "error_description": "PRIVATE"})
    monkeypatch.setattr(cli, "ClientAuth", Auth)
    code = main(["api", "--profile", "unused", "decisions", "apply", "proposal-1"])
    output = capsys.readouterr().out
    assert code == 3 and len(calls) == 1 and calls[0]["method"] == "POST"
    assert json.loads(output)["http_status"] == status and "private" not in output and "PRIVATE" not in output


@pytest.mark.parametrize("failure,code", [(ClientError("request_timeout", outcome=4), 4),
    (RuntimeError("PRIVATE"), 2), (KeyboardInterrupt(), 130)])
def test_errors_and_interrupt_are_structured_without_local_fallback(dispatch, monkeypatch, capsys, failure, code):
    class Auth:
        def __init__(self, _): pass
        def status(self): raise failure
    monkeypatch.setattr(cli, "ClientAuth", Auth)
    assert main(["auth", "--profile", "unused", "status"]) == code
    output = capsys.readouterr().out
    assert json.loads(output)["source"] == "client" and "PRIVATE" not in output


@pytest.mark.parametrize("raw", [b'{"note":"a","note":"b"}', b'{"actor":"typed"}', b'{"note":"' + b'x'*8192 + b'"}'])
def test_sensitive_input_is_bounded_strict_json(dispatch, monkeypatch, capsys, raw):
    monkeypatch.setattr(cli, "ClientAuth", lambda _: object())
    monkeypatch.setattr(cli.sys, "stdin", io.TextIOWrapper(io.BytesIO(raw)))
    assert main(["api", "--profile", "unused", "decisions", "deny", "proposal-1", "--stdin"]) == 2
    assert json.loads(capsys.readouterr().out)["source"] == "client"


def test_no_url_or_bearer_override_on_remote_commands(dispatch, capsys):
    for flag in ("--token", "--password", "--url", "--force", "--actor", "--note"):
        assert main(["api", "--profile", "unused", "targets", "list", flag, "PRIVATE-PLACEHOLDER"]) == 2
        output = capsys.readouterr()
        assert json.loads(output.out)["error"] == "invalid_client_arguments"
        assert not output.err and "PRIVATE" not in output.out


def test_bad_remote_arguments_are_structured_and_redacted(dispatch, capsys):
    assert main(["auth", "--profile", "unused", "PRIVATE-NOT-AN-OPERATION"]) == 2
    output = capsys.readouterr()
    assert json.loads(output.out)["error"] == "invalid_client_arguments"
    assert not output.err and "PRIVATE" not in output.out


def test_hidden_note_input_never_falls_back_to_echo(dispatch, monkeypatch, capsys):
    import warnings
    class Terminal(io.StringIO):
        def isatty(self): return True
    monkeypatch.setattr(cli.sys, "stdin", Terminal())
    monkeypatch.setattr(cli.sys, "stderr", Terminal())
    monkeypatch.setattr(cli, "ClientAuth", lambda _: object())
    def fallback(_):
        warnings.warn("echo unavailable", cli.getpass.GetPassWarning)
        pytest.fail("echoing fallback reached")
    monkeypatch.setattr(cli.getpass, "getpass", fallback)
    assert main(["api", "--profile", "unused", "decisions", "deny", "proposal-1"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "client_operation_failed"


def test_api_output_redacts_escaped_bearer_values():
    token = 'opaque-"\\secret'
    class Auth:
        @contextmanager
        def access(self): yield token
        def request(self, *a, **kw): return Response(200, {"echo": token, token: ["prefix " + token]})
    auth = Auth()
    auth.http = auth
    result, code = perform(auth, SimpleNamespace(group="targets", operation="list"))
    assert code == 0 and token not in str(result) and result["result"] == {"echo": "[redacted]", "[redacted]": ["prefix [redacted]"]}
