"""Independent client regressions; all credentials and store paths are disposable."""
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from cyberthunder.cli import main
from cyberthunder.client import cli
from cyberthunder.client import store as store_module
from cyberthunder.client.api import perform
from cyberthunder.client.auth import ClientAuth
from cyberthunder.client.config import endpoint
from cyberthunder.client.errors import ClientError, decode
from cyberthunder.client.http import Response
from cyberthunder.client.store import TokenStore
from tests.client.test_auth import client


def challenge(token):
    return Response(401, {"error": "insufficient_user_authentication", "step_up": {
        "reason": "authentication_too_old", "max_age": 300, "acr_values": ["urn:fixture:" + token]}})


@pytest.mark.parametrize("operation", ["mutation", "login", "status", "access"])
def test_reflected_bearer_in_challenge_never_reaches_public_error(client, monkeypatch, operation):
    auth, provider, _ = client
    if operation in {"status", "access"}:
        auth.login(lambda *_: None)
    original = provider.request
    requests = []

    def reflected(kind, **kwargs):
        if kind == "api":
            requests.append(kwargs)
            return challenge(kwargs["credential"])
        return original(kind, **kwargs)

    monkeypatch.setattr(provider, "request", reflected)
    with pytest.raises(ClientError) as error:
        if operation == "login":
            auth.login(lambda *_: None)
        elif operation == "status":
            auth.status()
        elif operation == "access":
            with auth.access():
                pytest.fail("unverified credential reached operation")
        else:
            @contextmanager
            def access():
                yield "access-private"
            perform(SimpleNamespace(access=access, http=provider),
                    SimpleNamespace(group="decisions", operation="apply", id="proposal-1"))
    assert error.value.code == "insufficient_user_authentication" and error.value.status == 401
    assert "access-private" not in json.dumps(error.value.public())
    assert error.value.challenge["reason"] == "authentication_too_old"
    assert len(requests) == 1


@pytest.mark.parametrize("when", ["display", "wait"])
def test_completed_logout_stops_pending_device_redemption(client, when):
    auth, provider, clock = client
    if when == "wait":
        original = clock.sleep
        def sleep(seconds):
            original(seconds)
            auth.logout()
        clock.sleep = sleep
    with pytest.raises(ClientError, match="login_cancelled"):
        auth.login(lambda *_: auth.logout() if when == "display" else None)
    assert not any(kind in {"token_endpoint", "api"} for kind, _ in provider.requests)
    with auth.store.locked():
        assert auth.store.load()["phase"] == "empty"


def test_logout_generation_cancels_another_process_before_redemption(profile, store, tmp_path):
    ready, release = tmp_path / "pending-ready", tmp_path / "release-login"
    script = """
import json,sys,time
from pathlib import Path
from cyberthunder.client.auth import ClientAuth
from cyberthunder.client.config import ClientProfile
from cyberthunder.client.errors import ClientError
from cyberthunder.client.store import TokenStore
from tests.client.test_auth import Clock,Provider
profile_path,root,ready,release=map(Path,sys.argv[1:])
profile=ClientProfile.load(profile_path)
provider=Provider(profile,Clock())
auth=ClientAuth(profile,store=TokenStore(profile.digest,root=root),transport=provider)
def display(*args):
    ready.touch()
    deadline=time.monotonic()+15
    while not release.exists():
        if time.monotonic()>deadline: raise RuntimeError('fixture deadline')
        time.sleep(.01)
try:
    auth.login(display)
    result={'error':'unexpected_success'}
except ClientError as error:
    result={'error':error.code}
result['polls']=sum(kind=='token_endpoint' for kind,_ in provider.requests)
result['api_requests']=sum(kind=='api' for kind,_ in provider.requests)
print(json.dumps(result))
"""
    child = subprocess.Popen([sys.executable, "-c", script, str(tmp_path / "profile.json"), str(store.root),
                              str(ready), str(release)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        deadline = time.monotonic() + 15
        while not ready.exists():
            assert time.monotonic() < deadline and child.poll() is None
            time.sleep(.01)
        def no_network(*args, **kwargs):
            pytest.fail("empty pending login has no stored provider credential to revoke")
        auth = ClientAuth(profile, store=store, transport=SimpleNamespace(request=no_network))
        assert auth.logout()[0]["local_cleared"] is True
        release.touch()
        stdout, stderr = child.communicate(timeout=15)
        assert child.returncode == 0 and not stderr
        assert json.loads(stdout) == {"error": "login_cancelled", "polls": 0, "api_requests": 0}
    finally:
        release.touch()
        if child.poll() is None:
            child.kill()
            child.communicate()


@pytest.mark.parametrize("prefix", [["--token", "PRIVATE-ARG"], ["--password=PRIVATE-ARG"],
                                    ["--actor", "--PRIVATE-ARG"], ["--state-dir", "--PRIVATE-ARG"]])
@pytest.mark.parametrize("namespace", ["auth", "api"])
def test_root_argument_errors_for_client_commands_never_echo_values(monkeypatch, capsys, prefix, namespace):
    monkeypatch.setattr(cli.ClientProfile, "load", lambda *_: pytest.fail("invalid arguments reached profile"))
    tail = ["status"] if namespace == "auth" else ["targets", "list"]
    assert main([*prefix, namespace, "--profile", "unused", *tail]) == 2
    captured = capsys.readouterr()
    assert not captured.err and "PRIVATE-ARG" not in captured.out
    assert json.loads(captured.out)["source"] == "client"


@pytest.mark.parametrize("userinfo", ["@", ":@", "user:@"])
def test_even_empty_url_userinfo_is_refused(userinfo):
    with pytest.raises(ClientError, match="profile_endpoint_invalid"):
        endpoint("https://" + userinfo + "identity.example.test/token")


@pytest.mark.parametrize("number", [b"1e9999", b"-1e9999"])
def test_json_numeric_overflow_is_not_an_accepted_response(number):
    with pytest.raises(ClientError, match="response_invalid"):
        decode(b'{"value":' + number + b'}')


@pytest.mark.parametrize("failure", [ClientError("request_timeout", outcome=4), OSError("private fixture detail")])
def test_ambiguous_mutation_failure_never_replays(failure):
    calls = []
    @contextmanager
    def access():
        yield "fixture-access"
    def request(*args, **kwargs):
        calls.append(kwargs)
        raise failure
    with pytest.raises(type(failure)):
        perform(SimpleNamespace(access=access, http=SimpleNamespace(request=request)),
                SimpleNamespace(group="decisions", operation="apply", id="proposal-1"))
    assert len(calls) == 1 and calls[0]["method"] == "POST"


def test_busy_native_store_sends_no_mutation_or_refresh(client):
    auth, provider, _ = client
    auth.login(lambda *_: None)
    other = ClientAuth(auth.profile, store=TokenStore(auth.profile.digest, root=auth.store.root), transport=provider)
    before = len(provider.requests)
    with auth.store.locked(), ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(perform, other, SimpleNamespace(group="decisions", operation="apply", id="proposal-1"))
        with pytest.raises(ClientError, match="client_store_busy"):
            pending.result(timeout=10)
    assert len(provider.requests) == before


def test_os_owner_binding_cannot_be_replaced_with_typed_identity(store):
    with store.locked():
        record = store.empty()
        record["owner"] = "typed-fixture-administrator"
        store.save(record)
        with pytest.raises(ClientError, match="client_store_invalid"):
            store.load()


def test_native_os_identity_does_not_follow_actor_or_home_environment(monkeypatch):
    before = store_module.user_binding()
    for key in ("CT_ACTOR", "USERNAME", "USER", "HOME", "LOCALAPPDATA"):
        monkeypatch.setenv(key, "disposable-untrusted-user")
    assert store_module.user_binding() == before


def test_failed_refresh_publication_cannot_redeem_old_token_again(client, monkeypatch):
    auth, provider, clock = client
    auth.login(lambda *_: None)
    clock.elapsed += 280
    provider.refresh = "refresh-two"
    original = auth.store.save
    def fail_ready(record):
        if record["phase"] in {"ready", "empty"}:
            raise ClientError("client_store_unavailable")
        return original(record)
    with monkeypatch.context() as patch:
        patch.setattr(auth.store, "save", fail_ready)
        with pytest.raises(ClientError):
            with auth.access():
                pytest.fail("failed refresh publication must not reach caller")
    before = len(provider.requests)
    with pytest.raises(ClientError, match="login_required"):
        with auth.access():
            pytest.fail("interrupted refresh must require new login")
    assert len(provider.requests) == before
    with auth.store.locked():
        assert auth.store.load()["phase"] == "empty"
