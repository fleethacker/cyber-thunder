"""ReportService: the one entry point the CLI and the API use for every report.

Reads only what is on disk through the context (scan runs, findings, explanations, proposals, audit log).
Every render is recorded in the audit log as `report.render` with the kind and the audit head hash that
the report embedded, so a printed page can be matched to the chain later.
"""
from __future__ import annotations

import inspect
import json
from typing import TYPE_CHECKING

from cyberthunder.report import checklist, fleet, friction, onepager, poam, score
from cyberthunder.report.render import FORMATS, ReportError

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext

KINDS = ("commander", "poam", "checklist", "fleet", "friction", "score")
_CONTENT_PARAMS = ("content", "data", "payload", "body", "text")
_NAME_PARAMS = ("name", "filename", "file_name")


class ReportService:
    def __init__(self, ctx: "AppContext"):
        self.ctx = ctx

    # -- audit ----------------------------------------------------------------------
    def _audited(self, kind: str, head: str, **details) -> None:
        self.ctx.audit.append("report.render", "report", {"kind": kind, "audit_head": head, **details}, subject=kind)

    def _head(self) -> str:
        return self.ctx.audit.verify().head

    @staticmethod
    def _fmt(fmt: str) -> str:
        fmt = (fmt or "html").lower()
        if fmt not in FORMATS:
            raise ReportError(f"unknown format {fmt!r}; expected one of {FORMATS}")
        return fmt

    # -- reports --------------------------------------------------------------------
    def commander(self, scan_id: str | None = None, fmt: str = "html") -> str:
        fmt = self._fmt(fmt)
        text, data = onepager.render_commander(self.ctx, scan_id, fmt)
        self._audited("commander", data["audit"]["head"], scan_id=data["scan_id"], format=fmt)
        return text

    def poam_csv(self, scan_id: str | None = None) -> str:
        head = self._head()
        text = poam.poam_csv(self.ctx, scan_id)
        self._audited("poam", head, scan_id=scan_id, rows=max(text.count("\n") - 1, 0))
        return text

    def checklist_cklb(self, scan_id: str | None = None, host: str | None = None) -> dict:
        head = self._head()
        doc = checklist.build_checklist(self.ctx, scan_id, host)
        self._audited("checklist", head, scan_id=scan_id, host=doc["target_data"]["host_name"],
                      rules=sum(len(s["rules"]) for s in doc["stigs"]))
        return doc

    def fleet(self, fmt: str = "html") -> str:
        fmt = self._fmt(fmt)
        head = self._head()
        text = fleet.render_fleet(fleet.load_fleet(self.ctx), fmt, audit_head=head, node=self.ctx.settings.node)
        self._audited("fleet", head, format=fmt)
        return text

    def friction(self, fmt: str = "html") -> str:
        fmt = self._fmt(fmt)
        head = self._head()
        text = friction.render_friction(friction.load_friction(self.ctx), fmt, audit_head=head,
                                        node=self.ctx.settings.node)
        self._audited("friction", head, format=fmt)
        return text

    def score(self, scan_id: str | None = None, key_dir: str | None = None) -> dict:
        head = self._head()
        res = score.score(self.ctx, scan_id, key_dir)
        self._audited("score", head, scan_id=res["scan_id"], seeded=res["seeded"], found=res["found"])
        return res

    # -- sync on reconnect ------------------------------------------------------------
    def render_kind(self, kind: str, scan_id: str | None = None) -> tuple[str, str]:
        """(filename, text) for a report in its portable form: html for pages, csv for the POA&M, json for data."""
        if kind == "commander":
            return f"commander-{scan_id or 'latest'}.html", self.commander(scan_id, "html")
        if kind == "poam":
            return f"poam-{scan_id or 'latest'}.csv", self.poam_csv(scan_id)
        if kind == "checklist":
            return f"checklist-{scan_id or 'latest'}.cklb", json.dumps(self.checklist_cklb(scan_id), indent=2)
        if kind == "fleet":
            return "path-to-fleet.html", self.fleet("html")
        if kind == "friction":
            return "friction-log.html", self.friction("html")
        if kind == "score":
            return f"score-{scan_id or 'latest'}.json", json.dumps(self.score(scan_id), indent=2)
        raise ReportError(f"unknown report kind {kind!r}; expected one of {KINDS}")

    def queue(self, kind: str, scan_id: str | None = None, host: str | None = None, *, actor: str = "report") -> dict:
        """Render a report and put it in the sync outbox so it goes out when the link comes back."""
        ing = getattr(self.ctx, "ingest", None)
        outbox = getattr(ing, "outbox", None) if ing is not None else None
        if outbox is None:
            raise ReportError("cannot queue: the ingest outbox is not available on this node; "
                              "save the report with --out and carry it across instead")
        fn = next((getattr(outbox, n) for n in ("enqueue", "add", "put", "push") if callable(getattr(outbox, n, None))), None)
        if fn is None:
            raise ReportError("cannot queue: the ingest outbox has no enqueue method")
        filename, text = self.render_kind(kind, scan_id)
        kwargs, positional_free = {}, True
        for pname, param in inspect.signature(fn).parameters.items():
            if pname == "kind":
                kwargs[pname] = f"report.{kind}"
            elif pname in _NAME_PARAMS:
                kwargs[pname] = filename
            elif pname in _CONTENT_PARAMS:
                kwargs[pname] = text
            elif pname in ("meta", "metadata"):
                kwargs[pname] = {"report": kind, "scan_id": scan_id, "bytes": len(text.encode("utf-8"))}
            elif pname == "actor":
                kwargs[pname] = actor
            elif param.default is inspect.Parameter.empty and param.kind in (param.POSITIONAL_OR_KEYWORD, param.KEYWORD_ONLY):
                positional_free = False
        if not positional_free:
            raise ReportError("cannot queue: the ingest outbox enqueue signature is not understood")
        res = fn(**kwargs)
        out = {"queued": True, "kind": kind, "filename": filename, "bytes": len(text.encode("utf-8"))}
        if isinstance(res, (str, int, dict)):
            out["outbox"] = res
        self.ctx.audit.append("report.queue", "report", {"kind": kind, "filename": filename, "bytes": out["bytes"]}, subject=kind)
        return out
