"""Exception -> status mapping, both through MappedRoute and through register_error_handlers."""
from __future__ import annotations

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

from cyberthunder.api.errors import MappedRoute, feature, register_error_handlers, status_for
from cyberthunder.control.approvals import IllegalTransition
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.inventory.targets import ScopeViolation
from cyberthunder.transport.base import TransportError

TABLE = [
    (ScopeViolation("target x is marked out of scope"), 403),
    (PermissionError("agent may not approve"), 403),
    (IllegalTransition("proposed -> applying not allowed"), 409),
    (KillSwitchEngaged("kill switch engaged"), 423),
    (KeyError("unknown proposal 'p1'"), 404),
    (TransportError("ssh: connection refused"), 503),
    (NotImplementedError(), 501),
    (ValueError("bad input"), 400),
]


@pytest.mark.parametrize("exc,code", TABLE)
def test_status_table(exc, code):
    assert status_for(exc)[0] == code


def test_unmapped_is_left_alone():
    assert status_for(RuntimeError("boom")) is None


def _raiser(exc):
    def endpoint():
        raise exc
    return endpoint


def _app(with_route_class: bool) -> FastAPI:
    app = FastAPI()
    router = APIRouter(route_class=MappedRoute) if with_route_class else APIRouter()
    for i, (exc, _) in enumerate(TABLE):
        router.add_api_route(f"/e/{i}", _raiser(exc), methods=["GET"])

    def feat():
        with feature("widgets"):
            raise NotImplementedError("widgets not built yet")

    router.add_api_route("/feat", feat, methods=["GET"])

    def typed(n: int):
        return {"n": n}

    router.add_api_route("/typed", typed, methods=["GET"])
    app.include_router(router)
    if not with_route_class:
        register_error_handlers(app)
    return app


@pytest.mark.parametrize("with_route_class", [True, False])
def test_mapping_over_http(with_route_class):
    with TestClient(_app(with_route_class)) as c:
        for i, (exc, code) in enumerate(TABLE):
            r = c.get(f"/e/{i}")
            assert r.status_code == code, (exc, r.status_code)
            assert isinstance(r.json()["detail"], str)
        assert c.get("/e/4").json()["detail"] == "unknown proposal 'p1'"
        r = c.get("/feat")
        assert r.status_code == 501 and r.json()["detail"] == "widgets not available on this build"
        r = c.get("/typed", params={"n": "seven"})
        assert r.status_code == 400 and "n" in r.json()["detail"]


def test_serve_cli_registers():
    import argparse

    from cyberthunder.api.cli import cmd_serve, register_cli

    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd")
    register_cli(sp)
    a = ap.parse_args(["serve", "--host", "127.0.0.1", "--port", "8123", "--reload"])
    assert a.fn is cmd_serve and a.port == 8123 and a.reload is True
