"""Request lifetime and fixed error boundaries for the passive importer."""
import asyncio
import errno
import json
import threading
from unittest.mock import Mock

import httpx
import pytest

from cyberthunder.api.app import create_app
from cyberthunder.ingest import scap_results as scap
from tests.api.test_scap_results import HEADERS, URL, configured, envelope, scap_client


@pytest.mark.parametrize("auth_mode,security_mode", [("oidc", "range"), ("mesh", "fleet"), ("dev", "fleet")])
def test_local_cli_refusal_precedes_state_initialization(auth_mode, security_mode, tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace
    from cyberthunder import context
    from cyberthunder.config import Settings
    from cyberthunder.ingest import scap_cli

    settings = SimpleNamespace(auth_mode=auth_mode, security_mode=security_mode)
    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls, **kwargs: settings))
    initialize = Mock(side_effect=AssertionError("unauthenticated import initialized application state"))
    monkeypatch.setattr(context, "AppContext", initialize)
    state = tmp_path / "uninitialized"
    result = scap_cli.main(["--state-dir", str(state), "--actor", "range-operator",
                            "unused.xml", "--manifest", "unused.json"])
    assert result == 2
    assert "authenticated SCAP upload API" in capsys.readouterr().err
    initialize.assert_not_called()
    assert not state.exists()


def test_storage_permission_errors_do_not_expose_paths(scap_client, configured, monkeypatch):
    monkeypatch.setattr(configured.store, "save_scan_run",
        Mock(side_effect=PermissionError(errno.EACCES, "denied", "PRIVATE_STORAGE_PATH")))
    response = scap_client.post(URL, json=envelope(), headers=HEADERS)
    assert response.status_code == 503
    assert "PRIVATE_STORAGE_PATH" not in response.text


def test_cancelled_request_cannot_publish_late(configured, monkeypatch):
    from cyberthunder.api.routes import scap_results as route
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    parse, importer = scap.parse_results, route.import_results
    def block(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return parse(*args, **kwargs)
    def tracked(*args, **kwargs):
        try:
            return importer(*args, **kwargs)
        finally:
            finished.set()
    monkeypatch.setattr(scap, "parse_results", block)
    monkeypatch.setattr(route, "import_results", tracked)
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(configured)),
                                     base_url="http://testserver") as client:
            pending = asyncio.create_task(client.post(URL, json=envelope(), headers=HEADERS))
            try:
                assert await asyncio.to_thread(entered.wait, 5)
                pending.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await pending
            finally:
                release.set()
                assert await asyncio.to_thread(finished.wait, 10)
    asyncio.run(exercise())
    assert not configured.store.list_scan_runs()
    assert not configured.store.current_findings()


def test_disconnect_cannot_publish_late(configured, monkeypatch):
    from cyberthunder.api.routes import scap_results as route
    from starlette.requests import Request
    entered, disconnected = threading.Event(), threading.Event()
    parse = scap.parse_results
    def block(*args, **kwargs):
        entered.set()
        assert disconnected.wait(5)
        return parse(*args, **kwargs)
    monkeypatch.setattr(scap, "parse_results", block)
    async def exercise():
        sent = False
        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": json.dumps(envelope()).encode(), "more_body": False}
            assert await asyncio.to_thread(entered.wait, 5)
            # Yield once after the watcher sets cancellation, then release the parser.
            asyncio.get_running_loop().call_soon(disconnected.set)
            return {"type": "http.disconnect"}
        request = Request({"type": "http", "headers": [(b"content-type", b"application/json")]}, receive)
        with pytest.raises(PermissionError):
            await route.import_scap_results(request, ctx=configured, actor=HEADERS["X-Actor"])
    asyncio.run(exercise())
    assert not configured.store.list_scan_runs()


def test_kill_diagnostic_does_not_expose_state_path(scap_client, configured):
    (configured.store.root / "KILL").write_text("stop")
    response = scap_client.post(URL, json=envelope(), headers=HEADERS)
    assert response.status_code == 423
    assert str(configured.store.root) not in response.json()["detail"]
