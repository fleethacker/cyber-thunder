"""Saved report snapshots, including reports retained before history was available.

Snapshots stay as portable JSON files under reports/history on both state backends.
Opening or downloading one returns its saved content without rendering current state.
"""
from __future__ import annotations

from datetime import date
import hashlib
import json
import logging
import re

from cyberthunder.findings.schema import utcnow

log = logging.getLogger(__name__)
KINDS = {"commander": "Commander one-pager", "poam": "POA&M", "checklist": "Updated checklist", "target": "Target report"}
FORMATS = {"html": "text/html", "md": "text/markdown", "csv": "text/csv", "cklb": "application/json", "json": "application/json"}
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def _path(ctx, report_id: str):
    if not ID.fullmatch(report_id):
        raise ValueError("invalid report id")
    return ctx.store.root / "reports" / "history" / f"{report_id}.json"


def save(ctx, kind: str, content, fmt: str, *, scan_id: str | None = None, targets=(),
         actor: str = "report", generated_at: str | None = None, report_id: str | None = None) -> dict:
    if kind not in KINDS or fmt not in FORMATS:
        raise ValueError("unsupported saved report type or format")
    text = content if isinstance(content, str) else json.dumps(content, indent=2, ensure_ascii=False)
    targets = sorted(set(targets))
    names = []
    for target in targets:
        try:
            names.append(ctx.inventory.get(target).name)
        except KeyError:
            names.append(target)
    with ctx.store.files.lock("report-history"):
        rid = report_id or ctx.store.new_id("report-")
        existing = ctx.store.read_json(_path(ctx, rid))
        if report_id and existing:
            return existing
        while existing:
            rid = ctx.store.new_id("report-")
            existing = ctx.store.read_json(_path(ctx, rid))
        doc = {"id": rid, "kind": kind, "title": KINDS[kind], "format": fmt,
               "generated_at": generated_at or utcnow(), "generated_by": actor,
               "scan_id": scan_id, "targets": targets, "target_names": names,
               "filename": f"{kind}-{rid}.{fmt}", "media_type": FORMATS[fmt],
               "bytes": len(text.encode("utf-8")), "content": text}
        ctx.store.write_json(_path(ctx, rid), doc)
    return doc


def import_existing(ctx) -> None:
    """Copy legacy target reports and queued/sent exports once, before they can be replaced."""
    for path in ctx.store.list_json(ctx.store.root / "reports"):
        doc = ctx.store.read_json(path)
        if not isinstance(doc, dict) or doc.get("report_id") or not isinstance(doc.get("target"), dict):
            continue
        target = doc["target"].get("id")
        if not target:
            continue
        rid = "legacy-" + hashlib.sha256(f"target/{path.name}".encode()).hexdigest()[:24]
        save(ctx, "target", doc, "json", targets=[target], actor=doc.get("generated_by") or "report",
             generated_at=doc.get("generated_at"), report_id=rid)
    for directory in (ctx.store.outbox_dir, ctx.store.synced_dir):
        for path in ctx.store.list_json(directory, "*.meta.json"):
            entry = ctx.store.read_json(path)
            if not isinstance(entry, dict):
                continue
            meta = entry.get("meta") or {}
            if not isinstance(meta, dict):
                continue
            kind = str(entry.get("kind", "")).removeprefix("report.")
            if not str(entry.get("kind", "")).startswith("report.") or kind not in KINDS or meta.get("history_saved"):
                continue
            name = str(entry.get("id") or "")
            if not name or name != path.name.removesuffix(".meta.json"):
                continue
            rid = "legacy-" + hashlib.sha256(f"outbox/{name}".encode()).hexdigest()[:24]
            if ctx.store.read_json(_path(ctx, rid)):
                continue
            payload = directory / name
            try:
                text = payload.read_bytes().decode("utf-8")
            except (OSError, UnicodeError) as exc:
                log.warning("saved report payload unavailable: %s: %s", name, exc)
                continue
            fmt = {"commander": "html", "poam": "csv", "checklist": "cklb", "target": "json"}[kind]
            save(ctx, kind, text, fmt, scan_id=meta.get("scan_id"), targets=[meta["host"]] if meta.get("host") else [],
                 actor=entry.get("enqueued_by") or "report", generated_at=entry.get("enqueued_at"), report_id=rid)


def get(ctx, report_id: str) -> dict:
    doc = ctx.store.read_json(_path(ctx, report_id))
    if not doc:
        raise KeyError(f"saved report {report_id!r} not found")
    return doc


def search(ctx, *, q: str = "", kind: str | None = None, target: str | None = None,
           from_date: date | None = None, to_date: date | None = None, offset: int = 0, limit: int = 20) -> dict:
    if from_date and to_date and from_date > to_date:
        raise ValueError("from_date must be on or before to_date")
    import_existing(ctx)
    terms = q.casefold().split()
    rows = []
    for path in ctx.store.list_json(ctx.store.root / "reports" / "history"):
        doc = ctx.store.read_json(path)
        if not doc or doc.get("kind") not in KINDS:
            continue
        if kind and doc["kind"] != kind or target and target not in doc.get("targets", []):
            continue
        day = str(doc.get("generated_at", ""))[:10]
        if from_date and day < from_date.isoformat() or to_date and day > to_date.isoformat():
            continue
        if terms:
            text = json.dumps(doc, ensure_ascii=False).casefold()
            if not all(term in text for term in terms):
                continue
        rows.append({key: value for key, value in doc.items() if key != "content"})
    rows.sort(key=lambda row: (row["generated_at"], row["id"]), reverse=True)
    return {"reports": rows[offset:offset + limit], "total": len(rows), "offset": offset, "limit": limit}
