"""One place that turns kernel exceptions into HTTP answers.

Every router in cyberthunder/api/routes uses MappedRoute, so the mapping holds even when the app factory
has not registered the app-wide handlers. The table matches docs/API.md:

  ScopeViolation, PermissionError  403   target out of scope, machine actor on a human-only edge
  IllegalTransition                409   proposal is not in a state that allows this
  KillSwitchEngaged                423   the kill switch blocks every apply and rollback
  KeyError                         404   unknown id
  TransportError                   503   could not reach the asset (detail carries the message)
  NotImplementedError              501   feature not built into this node
  ValueError                       400   bad input
  request validation               400   body or query did not match the schema
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute

from cyberthunder.control.approvals import IllegalTransition
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.inventory.targets import ScopeViolation
from cyberthunder.transport.base import TransportError
from cyberthunder.security.step_up import StepUpRequired, ERROR

log = logging.getLogger(__name__)

UNAVAILABLE = "not available on this build"


class FeatureUnavailable(NotImplementedError):
    """A service this request needs is not part of this build (module absent or still a skeleton)."""

    def __init__(self, feature: str):
        super().__init__(f"{feature} {UNAVAILABLE}")
        self.feature = feature


def unavailable(feature: str) -> FeatureUnavailable:
    return FeatureUnavailable(feature)


@contextmanager
def feature(name: str) -> Iterator[None]:
    """Turn a bare NotImplementedError from a service skeleton into a clear 501 for `name`."""
    try:
        yield
    except FeatureUnavailable:
        raise
    except NotImplementedError as e:
        raise FeatureUnavailable(name) from e


def requires(service: Any, name: str) -> Any:
    """Return the service or raise the 501 for it."""
    if service is None:
        raise FeatureUnavailable(name)
    return service


def _key_detail(e: KeyError) -> str:
    if e.args and isinstance(e.args[0], str):
        return e.args[0]
    return str(e) or "not found"


def _validation_detail(e: RequestValidationError) -> str:
    parts = []
    for err in e.errors():
        loc = ".".join(str(x) for x in err.get("loc", ()) if x not in ("body", "query", "path"))
        parts.append(f"{loc or 'request'}: {err.get('msg', 'invalid')}")
    return "; ".join(parts) or "invalid request"


def status_for(exc: BaseException) -> tuple[int, str] | None:
    """(status, detail) for a known exception, else None (left to the server as a 500)."""
    # order matters: ScopeViolation is a PermissionError; the RuntimeError family is checked by subtype
    if isinstance(exc, RequestValidationError):
        return 400, _validation_detail(exc)
    if isinstance(exc, StepUpRequired):
        return 401, str(exc)
    if isinstance(exc, (ScopeViolation, PermissionError)):
        return 403, str(exc) or "forbidden"
    if isinstance(exc, IllegalTransition):
        return 409, str(exc)
    if isinstance(exc, KillSwitchEngaged):
        return 423, str(exc)
    if isinstance(exc, KeyError):
        return 404, _key_detail(exc)
    if isinstance(exc, TransportError):
        return 503, str(exc) or "transport failure"
    if isinstance(exc, NotImplementedError):
        if isinstance(exc, FeatureUnavailable) or UNAVAILABLE in str(exc):
            return 501, str(exc)
        return 501, f"feature {UNAVAILABLE}" + (f" ({exc})" if str(exc) else "")
    for dotted, code in (("cyberthunder.ingest.outbox.LinkDisconnected", 409),
                         ("cyberthunder.vulnerabilities.service.VulnerabilityUnavailable", 409),
                         ("cyberthunder.vulnerabilities.service.VulnerabilityConflict", 409),
                         ("cyberthunder.vulnerabilities.service.VulnerabilityError", 400),
                         ("cyberthunder.findings.lifecycle.ReviewConflict", 409),
                         ("cyberthunder.remediation.engine.EngineError", 409),
                         ("cyberthunder.ingest.service.IngestError", 400),
                         ("cyberthunder.report.service.ReportError", 400)):
        mod, _, name = dotted.rpartition(".")
        try:
            cls = getattr(__import__(mod, fromlist=[name]), name)
        except Exception:  # noqa: BLE001  the module may not be installed on this node
            continue
        if isinstance(exc, cls):
            return code, str(exc)
    if isinstance(exc, ValueError):
        return 400, str(exc) or "invalid value"
    return None


def error_response(exc: BaseException) -> JSONResponse | None:
    if isinstance(exc, StepUpRequired):
        return JSONResponse({"detail": str(exc), "error": ERROR, "step_up": exc.challenge()}, status_code=401,
                            headers={"WWW-Authenticate": exc.authenticate_header(), "Cache-Control": "no-store",
                                     "Pragma": "no-cache"})
    mapped = status_for(exc)
    if mapped is None:
        return None
    code, detail = mapped
    if code >= 500:
        log.warning("request failed with %s: %s", code, detail)
    return JSONResponse({"detail": detail}, status_code=code)


class MappedRoute(APIRoute):
    """APIRoute that maps kernel exceptions to the documented status codes."""

    def get_route_handler(self) -> Callable:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            try:
                return await original(request)
            except HTTPException:
                raise
            except Exception as exc:  # noqa: BLE001  mapped or re-raised
                resp = error_response(exc)
                if resp is None:
                    raise
                return resp

        return handler


def register_error_handlers(app: FastAPI) -> None:
    """App-wide equivalent of MappedRoute, for routes added outside cyberthunder/api/routes."""

    def _handler(request: Request, exc: Exception) -> Response:
        resp = error_response(exc)
        if resp is None:  # pragma: no cover  only registered for mapped types
            return JSONResponse({"detail": "internal error"}, status_code=500)
        return resp

    for exc_type in (RequestValidationError, PermissionError, IllegalTransition, KillSwitchEngaged, KeyError,
                     TransportError, NotImplementedError, ValueError):
        app.add_exception_handler(exc_type, _handler)
