"""Reports: commander one-pager, POA&M CSV, CKLB write-back, path to fleet, friction log, answer-key score,
and queueing a report for the outbox. Rendering is done by ctx.reports.

Service methods used (first name found wins; arguments are positional):
  commander(scan_id, fmt)        -> str (html | md | json)
  poam_csv(scan_id)              -> str (CSV text)
  checklist(scan_id, host)       -> dict (CKLB JSON)
  fleet(fmt) / friction(fmt)     -> str
  score(scan_id)                 -> {seeded, found, share, items}
  queue(kind, scan_id, host, actor=) -> outbox entry
"""
from __future__ import annotations

from datetime import date
from typing import Literal

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from cyberthunder.api.errors import MappedRoute, feature, requires
from cyberthunder.api.schemas import QueueBody
from cyberthunder.api.util import ActorDep, CtxDep, call_first, safe_filename, to_plain

router = APIRouter(tags=["reports"], route_class=MappedRoute)

Fmt = Literal["html", "md"]


@router.get("/reports/history")
def report_history(ctx=CtxDep, q: str = Query("", max_length=200),
                   kind: Literal["commander", "poam", "checklist", "target"] | None = None,
                   target: str | None = None, from_date: date | None = None, to_date: date | None = None,
                   offset: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)) -> dict:
    from cyberthunder.report import history
    return history.search(ctx, q=q, kind=kind, target=target, from_date=from_date, to_date=to_date,
                          offset=offset, limit=limit)


@router.get("/reports/history/{report_id}")
def saved_report(report_id: str, ctx=CtxDep) -> dict:
    from cyberthunder.report import history
    return history.get(ctx, report_id)


@router.get("/reports/history/{report_id}/download")
def download_saved_report(report_id: str, ctx=CtxDep) -> Response:
    from cyberthunder.report import history
    doc = history.get(ctx, report_id)
    filename = safe_filename(doc["filename"], "report.txt")
    return Response(doc["content"], media_type=doc["media_type"],
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def _svc(ctx):
    return requires(getattr(ctx, "reports", None), "reports")


def _check_scan(ctx, scan_id: str | None) -> None:
    if scan_id and ctx.store.load_scan_run(scan_id) is None:
        raise KeyError(f"unknown scan {scan_id!r}")


def _doc(text, fmt: str, filename: str) -> Response:
    text = text if isinstance(text, str) else str(text)
    if fmt == "md":
        return PlainTextResponse(text, media_type="text/markdown; charset=utf-8",
                                 headers={"Content-Disposition": f'inline; filename="{filename}.md"'})
    return HTMLResponse(text)


@router.get("/reports/commander")
def commander(ctx=CtxDep, scan_id: str | None = None,
              format: Literal["html", "md", "json"] = Query("html")) -> Response:
    svc = _svc(ctx)
    _check_scan(ctx, scan_id)
    with feature("commander report"):
        text = call_first(svc, ("commander", "commander_report", "render_commander"), scan_id, format)
        if format == "json":
            return Response(text, media_type="application/json")
        return _doc(text, format, "commander")


@router.get("/reports/poam.csv")
def poam(ctx=CtxDep, scan_id: str | None = None) -> Response:
    svc = _svc(ctx)
    _check_scan(ctx, scan_id)
    with feature("POA&M export"):
        text = call_first(svc, ("poam_csv", "poam"), scan_id)
    return PlainTextResponse(text, media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": 'attachment; filename="poam.csv"'})


@router.get("/reports/checklist.cklb")
def checklist(ctx=CtxDep, scan_id: str | None = None, host: str | None = None) -> Response:
    svc = _svc(ctx)
    _check_scan(ctx, scan_id)
    with feature("checklist export"):
        doc = to_plain(call_first(svc, ("checklist", "cklb", "checklist_cklb"), scan_id, host))
    name = safe_filename(f"{host or 'checklist'}.cklb", "checklist.cklb")
    return JSONResponse(doc, headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/reports/fleet")
def fleet(ctx=CtxDep, format: Fmt = Query("html")) -> Response:
    svc = _svc(ctx)
    with feature("path-to-fleet report"):
        return _doc(call_first(svc, ("fleet", "path_to_fleet", "fleet_report"), format), format, "path-to-fleet")


@router.get("/reports/friction")
def friction(ctx=CtxDep, format: Fmt = Query("html")) -> Response:
    svc = _svc(ctx)
    with feature("friction log"):
        return _doc(call_first(svc, ("friction", "friction_log", "friction_report"), format), format, "friction")


@router.get("/reports/score")
def score(ctx=CtxDep, scan_id: str | None = None) -> dict:
    svc = _svc(ctx)
    _check_scan(ctx, scan_id)
    with feature("answer-key score"):
        return to_plain(call_first(svc, ("score", "answer_key_score"), scan_id))


@router.post("/reports/queue")
def queue(body: QueueBody, ctx=CtxDep, actor: str = ActorDep) -> dict:
    svc = _svc(ctx)
    _check_scan(ctx, body.scan_id)
    with feature("report queue"):
        return to_plain(call_first(svc, ("queue", "queue_report"), body.kind, body.scan_id, body.host, actor=actor))


@router.get("/reports/coverage")
def coverage(ctx=CtxDep, format: Literal["html", "md", "json"] = Query("html")) -> Response:
    svc = _svc(ctx)
    with feature("coverage report"):
        result = call_first(svc, ("coverage",), format)
        if format == "json":
            return JSONResponse(to_plain(result))
        return _doc(result, format, "coverage")
