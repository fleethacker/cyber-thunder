"""Owned TLS/ASGI requests must finish before their fixture dependencies close."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import http.client
import ssl
import threading
import time
from urllib.parse import urlsplit

import anyio
import pytest

from cyberthunder.client.errors import ClientError
from tests.client import test_api_integration as fixture_module


@pytest.mark.parametrize("ending", ["timeout", "disconnect", "failed_assertion", "concurrent_reads"])
def test_owned_requests_drain_before_api_exit(state_dir, tmp_path, certificates, signing_keys,
                                             profile_factory, monkeypatch, ending):
    entered, release = threading.Event(), threading.Event()
    lock = threading.Lock()
    active = 0
    wanted = 2 if ending == "concurrent_reads" else 1
    enabled = False
    exits, servers = [], []
    make_app, client_class, server_class = (fixture_module.create_app, fixture_module.TestClient,
                                            fixture_module.ThreadingHTTPServer)

    class ObservedApp:
        def __init__(self, inner): self.inner = inner
        async def __call__(self, scope, receive, send):
            nonlocal active
            gated = enabled and scope["type"] == "http" and scope["path"] == "/api/v1/targets"
            if not gated:
                return await self.inner(scope, receive, send)
            with lock:
                active += 1
                if active == wanted: entered.set()
            try:
                # Event driven, with a failure bound; no timing-dependent sleep.
                assert await anyio.to_thread.run_sync(release.wait, 5), "owned request was not released"
                await self.inner(scope, receive, send)
            finally:
                with lock: active -= 1

    class ObservedServer(server_class):
        def __init__(self, *args, **kwargs):
            self.handlers = []
            super().__init__(*args, **kwargs)
            servers.append(self)
        def process_request_thread(self, *args):
            self.handlers.append(threading.current_thread())
            return super().process_request_thread(*args)
        def shutdown(self):
            release.set()
            return super().shutdown()

    class ObservedClient(client_class):
        def __exit__(self, *args):
            with lock: exits.append((active, sum(t.is_alive() for t in servers[0].handlers)))
            # Bound the reproducer on the old fixture too. This observes order;
            # it is not a claim to reproduce or repair the reported portal hang.
            release.set()
            return super().__exit__(*args)

    monkeypatch.setattr(fixture_module, "create_app", lambda ctx: ObservedApp(make_app(ctx)))
    monkeypatch.setattr(fixture_module, "TestClient", ObservedClient)
    monkeypatch.setattr(fixture_module, "ThreadingHTTPServer", ObservedServer)
    pool = ThreadPoolExecutor(max_workers=wanted)
    pending = []
    try:
        failure = pytest.raises(AssertionError, match="intentional test-body failure") if ending == "failed_assertion" else nullcontext()
        with failure:
            with fixture_module.integrated_environment(state_dir, tmp_path, certificates, signing_keys,
                                                       profile_factory, monkeypatch) as (auth, _, _, _):
                auth.login(lambda *_: None)
                with auth.store.locked(): access = auth.store.load()["session"]["access_token"]
                # A real successful request first establishes TLS/API readiness.
                response = auth.http.request("api", method="GET", route="/targets", credential=access)
                assert response.status == 200 and [row["id"] for row in response.body["targets"]] == ["alpha"]
                enabled = True
                started = time.monotonic()
                if ending == "disconnect":
                    endpoint = urlsplit(auth.profile["api_base_url"])
                    connection = http.client.HTTPSConnection(endpoint.hostname, endpoint.port, timeout=3,
                        context=ssl.create_default_context(cafile=str(certificates[0])))
                    try:
                        connection.request("GET", "/api/v1/targets", headers={"Authorization": "Bearer " + access})
                        assert entered.wait(5), "request never entered the actual ASGI application"
                    finally:
                        connection.close()  # Explicit client cancellation before any response.
                else:
                    for _ in range(wanted):
                        pending.append(pool.submit(auth.http.request, "api", method="GET", route="/targets",
                                                   credential=access, timeout=3 if ending == "timeout" else 10))
                    assert entered.wait(5), "request never entered the actual ASGI application"
                if ending == "timeout":
                    with pytest.raises(ClientError, match="request_timeout"):
                        pending[0].result(timeout=5)
                    assert time.monotonic() - started < 5
                elif ending == "failed_assertion":
                    raise AssertionError("intentional test-body failure")
                # Concurrent reads remain active when the context is unwound.
        assert exits == [(0, 0)], "ASGI client closed before its owned TLS requests drained"
        assert active == 0 and all(not t.is_alive() for t in servers[0].handlers)
        if ending != "timeout":
            for future in pending:
                response = future.result(timeout=5)
                assert response.status == 200 and [row["id"] for row in response.body["targets"]] == ["alpha"]
    finally:
        release.set()
        pool.shutdown(wait=True, cancel_futures=True)
