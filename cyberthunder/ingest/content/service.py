"""Content updates: check the DISA index, pull what the inventory needs, or hand a manifest to a connected
machine and import its bundle later. IngestService exposes these methods; this class does the work.

Pulls never touch an asset. They are read-only egress to the allow-listed hosts, and every check, fetch,
failure, quarantine, import and manifest is written to the audit log with the URL, size, time, digest
and actor, and nothing more.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import shutil
import threading
import time
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable

from cyberthunder.findings.schema import utcnow
from cyberthunder.ingest.content import fetch as fx
from cyberthunder.ingest.content import index as ix
from cyberthunder.ingest.content.http import ContentClient, ContentNetworkError
from cyberthunder.ingest.content.select import select
from cyberthunder.ingest.content.store import ContentStore
from cyberthunder.ingest.link import LinkState, transfer_seconds
from cyberthunder.ingest.outbox import LinkDisconnected

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.ingest.service import IngestService

log = logging.getLogger(__name__)

LOCK_NAME = "manifest.lock.json"
MANIFEST_NAME = "manifest.json"
MAX_HEADS = 40


def _ingest_error(msg: str) -> Exception:
    from cyberthunder.ingest.service import IngestError
    return IngestError(msg)


def _setting(settings: Any, name: str, default: Any) -> Any:
    v = getattr(settings, name, None)
    return default if v is None else v


class ContentService:
    def __init__(self, ingest: "IngestService"):
        self.ingest = ingest
        self.ctx = ingest.ctx
        self.store = ContentStore(ingest.store)
        self.audit = ingest.audit
        self._client: ContentClient | None = None
        self._job_lock = threading.Lock()
        self._running: str | None = None
        self.threads: list[threading.Thread] = []      # background jobs, kept so callers can join them

    # -- settings and client ----------------------------------------------------------------------
    @property
    def settings(self):
        return self.ctx.settings

    @property
    def timeout(self) -> float:
        return float(_setting(self.settings, "content_timeout_s", 30))

    @property
    def max_bytes(self) -> int:
        return int(_setting(self.settings, "content_max_bytes", fx.DEFAULT_MAX_BYTES))

    @property
    def client(self) -> ContentClient:
        if self._client is None:
            self._client = ContentClient(timeout=self.timeout)
        self._client.observer = self.ingest.link.observe
        self._client.before_request = self._network_guard
        self._client.test_mode = lambda: self._link().mode == "test"
        return self._client

    def _network_guard(self):
        self.ingest.ctx.killswitch.guard("content.network", "content")
        if not self._link().connected:
            raise LinkDisconnected("network attempt blocked by link state")

    @client.setter
    def client(self, value: ContentClient | None) -> None:
        self._client = value

    @property
    def default_manifest_path(self) -> Path:
        return self.store.root / MANIFEST_NAME

    @property
    def catalog_cache(self) -> Path:
        return self.store.root / "catalog.json"

    def _link(self) -> LinkState:
        return self.ingest.link.state()

    def _refuse_if_down(self, action: str, actor: str) -> None:
        if not self._link().connected:
            self.audit.append(action, actor, {"reason": "link disconnected"}, outcome="blocked")
            raise LinkDisconnected(
                "link is disconnected; write a manifest for a connected machine instead "
                f"(cyberthunder ingest manifest --out {self.default_manifest_path}, or POST /ingest/manifest), "
                "fetch it there with 'cyberthunder ingest fetch-manifest', and bring the folder back for "
                "'cyberthunder ingest import-dir'")

    # -- index ------------------------------------------------------------------------------------
    def _snapshot_path(self) -> Path:
        p = getattr(self.settings, "content_snapshot", None)
        return Path(p) if p else ix.BUNDLED_SNAPSHOT

    def _save_catalog(self, entries: list[ix.Entry], source: str, stats: dict | None = None) -> None:
        self.store.state.write_json(self.catalog_cache, {"saved_at": utcnow(), "source": source, "stats": stats or {},
                                                         "entries": [e.to_dict() for e in entries]})

    def catalog_entries(self) -> tuple[list[ix.Entry], str]:
        """The newest index this node has seen: the last live check, else the bundled snapshot."""
        doc = self.store.state.read_json(self.catalog_cache)
        if doc and isinstance(doc.get("entries"), list):
            return [ix.Entry.from_dict(e) for e in doc["entries"]], str(doc.get("source") or "cache")
        return ix.load_snapshot(self._snapshot_path()), "snapshot"

    def _fetch_live(self) -> ix.IndexResult:
        src = self.store.source()

        def remember(cls: str) -> None:
            self.store.save_source(classname=cls, discovered_at=utcnow())

        return ix.fetch_index_result(self.client, timeout=self.timeout, classname=src.get("classname"),
                                     on_discover=remember)

    # -- selection --------------------------------------------------------------------------------
    def _collected(self) -> dict[str, dict]:
        from cyberthunder.ingest.bulletin import latest_collected
        try:
            return latest_collected(self.store.state)
        except OSError:
            return {}

    def _select(self, entries: list[ix.Entry], *, include_automation: bool = False,
                include_compilation: bool = False, products: Iterable[str] = ()):
        prefs = self.preferences()
        inventory = self.ctx.inventory.all() if prefs["mode"] == "inventory" else []
        extra = list(products) + (prefs["products"] if prefs["mode"] == "selected" else [])
        selection = select(entries, inventory, self._collected(), self.store.records(),
                           include_automation=include_automation, include_compilation=include_compilation,
                           extra_products=extra, allowed_hosts=self.client.allowed_hosts,
                           allow_http=self.client.allow_http, content_kinds=prefs["kinds"])
        last = self.store.last_check() or {}
        heads = {(r["filename"], r.get("url")): r for r in last.get("updates", [])}
        for row in selection.updates:
            head = heads.get((row["filename"], row.get("url")), {})
            row.update({k: head[k] for k in ("expected_bytes", "expected_etag", "last_modified") if k in head})
        return selection

    def preferences(self) -> dict:
        from cyberthunder.ingest.content.library import ContentLibrary
        return ContentLibrary(self).preferences()

    def library(self) -> dict:
        from cyberthunder.ingest.content.library import ContentLibrary
        return ContentLibrary(self).view()

    def save_preferences(self, changes: dict, actor: str) -> dict:
        from cyberthunder.ingest.content.library import ContentLibrary
        return ContentLibrary(self).save_preferences(changes, actor)

    def _head_sizes(self, rows: list[dict], actor: str) -> None:
        for r in rows[:MAX_HEADS]:
            self.ctx.killswitch.guard("content.check", actor)
            if not self._link().connected:
                raise LinkDisconnected("link disconnected during the content check")
            try:
                status, h, _ = self.client.request("HEAD", r["url"], timeout=self.timeout, max_bytes=0)
            except ContentNetworkError:
                continue
            if status == 200:
                n = h.get("content-length")
                r["expected_bytes"] = int(n) if n and n.isdigit() else None
                r["expected_etag"] = h.get("etag")
                r["last_modified"] = h.get("last-modified")

    def check_updates(self, actor: str, *, source: str = "live", include_automation: bool = False,
                      include_compilation: bool = False, products: Iterable[str] = ()) -> dict:
        from cyberthunder.ingest.content.library import ContentLibrary
        library = ContentLibrary(self)
        live = (source or "live").lower() == "live"
        started = utcnow()
        if live:
            library.record_check(started, "running")
        try:
            result = self._check_updates(actor, source=source, include_automation=include_automation,
                                         include_compilation=include_compilation, products=products)
        except Exception as exc:
            if live:
                library.record_check(started, "failed", str(exc))
            raise
        if live:
            library.record_check(started, "success")
        return result

    def _check_updates(self, actor: str, *, source: str = "live", include_automation: bool = False,
                       include_compilation: bool = False, products: Iterable[str] = ()) -> dict:
        source = (source or "live").lower()
        if source not in ("live", "snapshot"):
            raise ValueError("source must be 'live' or 'snapshot'")
        link = self._link()
        stats: dict[str, Any] = {}
        url = ix.APEX_URL
        if source == "live":
            self._refuse_if_down("content.check", actor)
            if self.ctx.killswitch.is_engaged():
                self.audit.append("content.check", actor, {"reason": "kill switch engaged"}, outcome="blocked")
                raise _ingest_error("the kill switch is engaged; content checks are stopped")
            t0 = time.monotonic()
            try:
                res = self._fetch_live()
            except (ix.IndexFetchError, ContentNetworkError) as e:
                self.audit.append("content.check", actor, {"url": url, "seconds": round(time.monotonic() - t0, 3),
                                                           "error": str(e)[:300]}, outcome="failed")
                raise _ingest_error(f"index check failed: {e}") from None
            entries = res.entries
            stats = res.stats()
            self._save_catalog(entries, "live", stats)
        else:
            path = self._snapshot_path()
            entries = ix.load_snapshot(path)
            url = str(path)
            stats = {"bytes": path.stat().st_size, "wire_bytes": path.stat().st_size, "gzip": False, "seconds": 0.0}
        sel = self._select(entries, include_automation=include_automation, include_compilation=include_compilation,
                           products=products)
        if source == "live":
            self._head_sizes(sel.updates, actor)
        known = [r.get("expected_bytes") for r in sel.updates]
        est = round(sum(transfer_seconds(n, link) for n in known if n), 3) if any(known) and link.mode == "test" else None
        wire = int(stats.get("wire_bytes") or 0)
        report = {"checked_at": utcnow(), "checked_by": actor, "source": source, "url": url,
                  "index_entries": len(entries), "index_bytes": int(stats.get("bytes") or 0), "index_wire_bytes": wire,
                  "gzip": bool(stats.get("gzip")), "seconds": stats.get("seconds"),
                  "classname": stats.get("classname"), "rediscovered": bool(stats.get("rediscovered")),
                  "index_estimate_seconds": transfer_seconds(wire, link) if wire else None,
                  "estimate_seconds_at_link": est, "link": link.to_dict(),
                  "products": sel.to_dict()["products"], "wanted": sel.wanted, "updates": sel.updates,
                  "current": sel.current, "skipped": sel.skipped,
                  "wanted_count": len(sel.wanted), "new_count": len(sel.updates)}
        self.store.save_check(report)
        self.audit.append("content.check", actor, {"url": url, "bytes": wire, "seconds": stats.get("seconds"),
                                                   "source": source, "entries": len(entries),
                                                   "updates": len(sel.updates)})
        return report

    def last_check(self) -> dict | None:
        return self.store.last_check()

    def index_estimate(self) -> dict:
        """What a check would cost at the current link, from the last answer's size (or the snapshot's)."""
        lc = self.store.last_check() or {}
        n = int(lc.get("index_wire_bytes") or 0) or int(_setting(self.settings, "content_index_bytes", 190_000))
        link = self._link()
        return {"bytes": n, "seconds": transfer_seconds(n, link), "link": link.to_dict()}

    # -- pull -------------------------------------------------------------------------------------
    def _resolve(self, filenames: list[str] | None, all_matching: bool, actor: str) -> list[dict]:
        if all_matching:
            if self.store.last_check() is None:
                self.check_updates(actor)
            entries, _ = self.catalog_entries()
            return self._select(entries).updates
        if not filenames:
            raise ValueError("name the files to pull, or pull all matching updates")
        entries, _ = self.catalog_entries()
        by_name = {e.filename: e for e in entries}
        by_disk = {fx.disk_name(e.filename): e for e in entries}
        lc = self.store.last_check() or {}
        known = {r["filename"]: r for r in (lc.get("updates") or []) + (lc.get("current") or [])}
        out = []
        for n in filenames:
            e = by_name.get(n) or by_disk.get(n)
            if e is None:
                raise _ingest_error(f"{n} is not in the STIG index this node holds; run a check first")
            if not e.allowed_by(self.client.allowed_hosts, self.client.allow_http):
                raise _ingest_error(f"{n} is hosted on {e.host}, which is not on the content allow-list")
            row = dict(known.get(e.filename) or {})
            row.update({"filename": e.filename, "url": e.url, "product_key": e.product_key, "kind": e.kind,
                        "version": list(e.version) if e.version else None, "version_label": e.version_label,
                        "upload_date": e.upload_date, "title": e.title})
            out.append(row)
        return out

    def pull(self, actor: str, *, filenames: list[str] | None = None, all_matching: bool = False, pace: bool = False,
             background: bool = True) -> dict:
        if pace and self._link().mode != "test":
            raise ValueError("pacing requires explicit link test mode")
        self._refuse_if_down("content.fetch", actor)
        if self.ctx.killswitch.is_engaged():
            self.audit.append("content.fetch", actor, {"reason": "kill switch engaged"}, outcome="blocked")
            raise _ingest_error("the kill switch is engaged; content pulls are stopped")
        items = self._resolve(filenames, all_matching, actor)
        now = utcnow()
        job = {"id": self.store.state.new_id("pull-"), "created_at": now, "created_by": actor, "state": "queued",
               "pace": bool(pace), "all_matching": bool(all_matching), "started_at": None, "finished_at": None,
               "link": self._link().to_dict(),
               "files": [{"filename": r["filename"], "url": r["url"], "kind": r.get("kind"),
                          "product_key": r.get("product_key"), "version_label": r.get("version_label"),
                          "bytes": 0, "total": r.get("expected_bytes"), "state": "pending", "error": None,
                          "estimate_seconds": None, "sha256": None, "delta": None, "datastream_path": None}
                         for r in items],
               "deltas": [], "error": None}
        with self._job_lock:
            if self._running:
                raise _ingest_error(f"pull {self._running} is still running; wait for it to finish")
            self._running = job["id"]
        self.store.save_job(job)
        if not items:
            job.update(state="done", started_at=now, finished_at=now)
            self.store.save_job(job)
            with self._job_lock:
                self._running = None
            return job
        if background:
            snapshot = copy.deepcopy(job)          # the thread keeps mutating its own copy
            t = threading.Thread(target=self._run_job, args=(job, items, actor), name=f"content-{job['id']}",
                                 daemon=True)
            self.threads.append(t)
            t.start()
            return snapshot
        return self._run_job(job, items, actor)

    def wait(self, timeout: float | None = None) -> None:
        for t in list(self.threads):
            t.join(timeout)

    def get_job(self, job_id: str) -> dict:
        j = self.store.load_job(job_id)
        if j is None:
            raise KeyError(f"no pull job {job_id!r}")
        return j

    def _run_job(self, job: dict, items: list[dict], actor: str) -> dict:
        lock = threading.Lock()
        last = [0.0]

        def save(force: bool = False) -> None:
            with lock:
                now = time.monotonic()
                if force or now - last[0] >= 0.5:
                    last[0] = now
                    self.store.save_job(job)

        try:
            job.update(state="running", started_at=utcnow())
            save(True)
            staging = self.store.root / "incoming"
            for f, item in zip(job["files"], items):
                if self.ctx.killswitch.is_engaged():
                    f.update(state="stopped", error="kill switch engaged")
                    job["state"] = "stopped"
                    continue
                if not self._link().connected:
                    f.update(state="stopped", error="link went down; pull again when it is back")
                    job["state"] = "stopped"
                    continue
                f["state"] = "downloading"
                save(True)

                def progress(p: dict, f=f) -> None:
                    f["bytes"] = p.get("bytes", f["bytes"])
                    if p.get("total") is not None:
                        f["total"] = p["total"]
                    if p.get("estimate_seconds") is not None:
                        f["estimate_seconds"] = p["estimate_seconds"]
                    if p.get("state") in ("verifying", "retrying"):
                        f["state"] = p["state"]
                    save()

                polled = [0.0]

                def stop() -> str | None:
                    now = time.monotonic()
                    if now - polled[0] < 0.5:
                        return None
                    polled[0] = now
                    if self.ctx.killswitch.is_engaged():
                        return "kill switch engaged"
                    if job["pace"] and self._link().mode != "test":
                        return "test emulation disabled"
                    if not self._link().connected:
                        return "link went down; pull again when it is back"
                    return None

                entry = fx.entry_from_item(item)
                t0 = time.monotonic()
                try:
                    res = fx.download(self.client, entry, staging, link=self._link(), max_bytes=self.max_bytes,
                                      pace=job["pace"], progress=progress, quarantine_dir=self.store.quarantine_dir,
                                      timeout=self.timeout, stop=stop)
                except fx.Stopped as e:
                    f.update(state="stopped", error=str(e))
                    job["state"] = "stopped"
                    self.audit.append("content.fetch", actor, {"url": entry.url, "bytes": f["bytes"],
                                                               "seconds": round(time.monotonic() - t0, 3)},
                                      outcome="blocked", subject=entry.filename)
                    continue
                except fx.Quarantined as e:
                    f.update(state="quarantined", error=str(e))
                    self.audit.append("content.quarantine", actor, {"url": entry.url, "seconds":
                                                                    round(time.monotonic() - t0, 3),
                                                                    "reason": str(e)[:300]}, outcome="failed",
                                      subject=entry.filename)
                    continue
                except (fx.ContentError, ContentNetworkError, OSError) as e:
                    f.update(state="failed", error=str(e))
                    self.audit.append("content.fetch_failed", actor, {"url": entry.url, "bytes": f["bytes"],
                                                                      "seconds": round(time.monotonic() - t0, 3),
                                                                      "error": str(e)[:300]},
                                      outcome="failed", subject=entry.filename)
                    continue
                self.audit.append("content.fetch", actor, {"url": res.url, "bytes": res.bytes, "seconds": res.seconds,
                                                           "sha256": res.sha256}, subject=entry.filename)
                try:
                    rec = self._accept(Path(res.path), entry, source="pulled", actor=actor, sha256=res.sha256,
                                       etag=res.etag, size=res.bytes)
                except Exception as e:  # noqa: BLE001 - record and keep going with the next file
                    f.update(state="failed", error=f"accepted but not ingested: {e}")
                    continue
                f.update(state="done", bytes=res.bytes, total=res.bytes, sha256=res.sha256,
                         delta=rec["ingest"].get("delta"), datastream_path=rec["ingest"].get("datastream_path"))
                if rec["ingest"].get("delta"):
                    job["deltas"].append(rec["ingest"]["delta"])
                save(True)
            if job["state"] == "running":
                failed = [f for f in job["files"] if f["state"] != "done"]
                job["state"] = "done" if not failed else ("failed" if len(failed) == len(job["files"]) else "partial")
        except Exception as e:  # noqa: BLE001 - the job record must say what happened
            log.exception("content pull %s failed", job["id"])
            job.update(state="failed", error=str(e))
        finally:
            job["finished_at"] = utcnow()
            save(True)
            with self._job_lock:
                self._running = None
        return job

    # -- accepting a verified file ----------------------------------------------------------------
    def _accept(self, path: Path, entry: ix.Entry, *, source: str, actor: str, sha256: str, etag: str | None,
                size: int) -> dict:
        """Move a verified file into files/, run the same ingest as a hand import, and index it."""
        files = self.store.files_dir
        files.mkdir(parents=True, exist_ok=True)
        dest = files / fx.disk_name(entry.filename)
        if path.resolve() != dest.resolve():
            os.replace(path, dest)
        ingest: dict[str, Any] = {}
        if entry.kind in ("manual_stig", "srg"):
            rep = self.ingest.ingest_stig(dest, actor=actor, receipt_source=source)
            ingest.update(delta_id=rep["id"], catalog_path=rep.get("catalog_path"),
                          delta={"id": rep["id"], "benchmark_id": rep.get("benchmark_id"),
                                 "old_release": rep.get("old_release"), "new_release": rep.get("new_release"),
                                 "counts": rep.get("counts"), "rescan_rules": len(rep.get("rescan_rule_ids") or []),
                                 "full_import": rep.get("full_import"), "filename": entry.filename})
        elif entry.kind == "scap_benchmark":
            ingest["datastream_path"] = str(self._extract_datastream(dest, entry))
        rec = {"filename": entry.filename, "disk_name": dest.name, "product_key": entry.product_key, "kind": entry.kind,
               "version": list(entry.version) if entry.version else None, "version_label": entry.version_label,
               "upload_date": entry.upload_date, "sha256": sha256, "etag": etag, "bytes": size, "url": entry.url,
               "fetched_at": utcnow(), "fetched_by": actor, "source": source, "ingest": ingest}
        rec["title"] = entry.title
        saved = self.store.put(rec)
        from cyberthunder.ingest.content.library import ContentLibrary
        ContentLibrary(self).record_transfer(source, saved["fetched_at"])
        return saved

    def _extract_datastream(self, zpath: Path, entry: ix.Entry) -> Path:
        if not zipfile.is_zipfile(zpath):
            product = fx.disk_name(entry.product_key or "unknown")
            out = self.store.scap_dir / product / (fx.disk_name(Path(entry.filename).stem) + ".xml")
            out.parent.mkdir(parents=True, exist_ok=True)
            tmp = out.with_name(out.name + ".tmp")
            shutil.copyfile(zpath, tmp)
            os.replace(tmp, out)
            return out
        with zipfile.ZipFile(zpath) as zf:
            m = fx.find_datastream(zf)
            product = fx.disk_name(entry.product_key or "unknown")
            out = self.store.scap_dir / product / (fx.disk_name(Path(entry.filename).stem) + ".xml")
            out.parent.mkdir(parents=True, exist_ok=True)
            tmp = out.with_name(out.name + ".tmp")
            with zf.open(m) as src, open(tmp, "wb") as dst:       # member name never used as a path
                shutil.copyfileobj(src, dst, 1024 * 1024)
            os.replace(tmp, out)
        return out

    # -- held content -----------------------------------------------------------------------------
    def content(self) -> dict:
        q = self.store.quarantine_dir
        quarantined = []
        if q.is_dir():
            for p in sorted(q.glob("*.why.json")):
                try:
                    quarantined.append(json.loads(p.read_text(encoding="utf-8")))
                except (OSError, ValueError):
                    continue
        return {"files": self.store.records(), "products": self.store.by_product(),
                "scap": [{"product_key": r.get("product_key"), "filename": r.get("filename"),
                          "datastream_path": r["ingest"].get("datastream_path")}
                         for r in self.store.records() if (r.get("ingest") or {}).get("datastream_path")],
                "quarantine": quarantined, "dir": str(self.store.root)}

    # -- disconnected path ------------------------------------------------------------------------
    def write_manifest(self, actor: str, path: str | Path | None = None) -> dict:
        entries, source = self.catalog_entries()
        sel = self._select(entries)
        lc = self.store.last_check() or {}
        heads = {r["filename"]: r for r in (lc.get("updates") or [])}
        items = []
        for r in sel.updates:
            h = heads.get(r["filename"], {})
            item = {k: r.get(k) for k in ("filename", "url", "product_key", "kind", "version", "version_label")}
            if h.get("expected_bytes"):
                item["expected_bytes"] = h["expected_bytes"]
            if h.get("expected_etag"):
                item["expected_etag"] = h["expected_etag"]
            items.append(item)
        doc = {"generated_at": utcnow(), "generated_by": actor, "node": getattr(self.settings, "node", None),
               "index_source": source, "items": items}
        out = Path(path) if path else self.default_manifest_path
        self.store.state.write_json(out, doc)
        digest = fx.sha256_file(out)
        self.audit.append("content.manifest", actor, {"url": str(out), "bytes": out.stat().st_size, "sha256": digest,
                                                      "items": len(items)})
        return dict(doc, path=str(out), sha256=digest)

    def import_dir(self, path: str | Path, actor: str) -> dict:
        from cyberthunder.control.identity import require_human
        actor = require_human(actor)
        self.ctx.killswitch.guard("content.import", actor)
        src = Path(path)
        if not src.is_dir():
            raise ValueError(f"no such folder on this node: {src}")
        lock = None
        lp = src / LOCK_NAME
        if lp.is_file():
            try:
                lock = json.loads(lp.read_text(encoding="utf-8"))
            except ValueError as e:
                raise _ingest_error(f"{LOCK_NAME} does not parse: {e}") from None
        locked = {f["disk_name"]: f for f in (lock or {}).get("files", []) if f.get("disk_name")}
        entries, _ = self.catalog_entries()
        by_disk = {fx.disk_name(e.filename): e for e in entries}
        staging = self.store.root / "incoming"
        staging.mkdir(parents=True, exist_ok=True)
        imported, refused, skipped = [], [], []
        for p in sorted(src.iterdir()):
            self.ctx.killswitch.guard("content.import", actor)
            if not p.is_file() or p.name == LOCK_NAME or p.name.endswith((".part", ".part.json", ".why.json")) \
                    or p.name == MANIFEST_NAME:
                continue
            info = locked.get(p.name)
            if info:
                entry = fx.entry_from_item(info)
            elif p.name in by_disk:
                entry = by_disk[p.name]
            else:
                parsed = ix.parse_filename(p.name)
                if not p.name.lower().endswith((".zip", ".xml")):
                    skipped.append({"filename": p.name, "reason": "not listed in the lock file or the index"})
                    continue
                entry = ix.Entry(filename=p.name, url="", host="", title=p.name, kind=parsed["kind"],
                                 product_key=parsed["product_key"], version=parsed["version"],
                                 version_label=parsed["version_label"])
            if info is None and entry.kind == "other" and p.suffix.lower() == ".xml":
                from cyberthunder.ingest.content.uploads import MAX_UPLOAD_BYTES, import_content
                try:
                    with p.open("rb") as source:
                        data = source.read(MAX_UPLOAD_BYTES + 1)
                    imported.append(import_content(self, data, p.name, actor)["record"])
                except ValueError as exc:
                    refused.append({"filename": p.name, "reason": str(exc)})
                continue
            work = staging / fx.disk_name(entry.filename)
            shutil.copyfile(p, work)
            digest = fx.sha256_file(work)
            reason = None
            if info and info.get("sha256") and info["sha256"].lower() != digest:
                reason = f"SHA-256 {digest} does not match {LOCK_NAME} ({info['sha256']})"
            else:
                try:
                    fx.check_file(work, entry.kind, filename=entry.filename)
                except ValueError as e:
                    reason = str(e)
            if reason:
                q = fx.quarantine(work, self.store.quarantine_dir, reason, filename=entry.filename, url=entry.url)
                self.audit.append("content.quarantine", actor, {"url": str(p), "bytes": q.stat().st_size,
                                                                "sha256": digest, "reason": reason[:300]},
                                  outcome="failed", subject=entry.filename)
                refused.append({"filename": entry.filename, "reason": reason})
                continue
            size = work.stat().st_size
            rec = self._accept(work, entry, source="imported", actor=actor, sha256=digest,
                               etag=(info or {}).get("etag"), size=size)
            self.audit.append("content.import", actor, {"url": str(p), "bytes": size, "sha256": digest},
                              subject=entry.filename)
            imported.append(rec)
        missing = [f["filename"] for f in (lock or {}).get("files", []) if f.get("disk_name")
                   and not (src / f["disk_name"]).is_file()]
        return {"imported": imported, "refused": refused, "skipped": skipped, "missing": missing,
                "verified_by": LOCK_NAME if lock else "integrity checks",
                "deltas": [r["ingest"]["delta"] for r in imported if (r.get("ingest") or {}).get("delta")]}

    # -- reconnect --------------------------------------------------------------------------------
    def on_reconnect(self, actor: str) -> dict:
        out: dict[str, Any] = {}
        prefs = self.preferences()
        check = prefs["check_on_reconnect"]
        auto = prefs["auto_pull"]
        if not check and not auto:
            return {"content_check": "off"}

        def run() -> None:
            try:
                self.check_updates(actor)
                if auto:
                    job = self.pull(actor, all_matching=True, background=False)
                    out["job_id"] = job["id"]
            except Exception as e:  # noqa: BLE001 - a failed check must never undo the reconnect
                log.warning("content check on reconnect failed: %s", e)
                out["error"] = str(e)

        t = threading.Thread(target=run, name="content-reconnect", daemon=True)
        self.threads.append(t)
        t.start()
        out["content_check"] = "started"
        out["content_auto_pull"] = auto
        return out


# -- the connected machine ------------------------------------------------------------------------

def fetch_manifest(manifest_path: str | Path, out_dir: str | Path, opener: Any = None, *,
                   link: LinkState | None = None, pace: bool = False, max_bytes: int = fx.DEFAULT_MAX_BYTES,
                   progress: Callable[[dict], None] | None = None, timeout: float = 30.0) -> dict:
    """Download every item of a manifest into out_dir and write out_dir/manifest.lock.json.

    Runs on a connected machine with no Cyber Thunder state. The lock file carries the SHA-256 of each file;
    the node checks it on import. Items that fail are listed with the reason and left out of the lock."""
    mp = Path(manifest_path)
    try:
        doc = json.loads(mp.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise _ingest_error(f"cannot read manifest {mp}: {e}") from None
    items = doc.get("items")
    if not isinstance(items, list):
        raise _ingest_error("manifest has no items list")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    client = opener if isinstance(opener, ContentClient) else (ContentClient(opener=opener, timeout=timeout)
                                                                if opener is not None else ContentClient(timeout=timeout))
    files, failed = [], []
    for item in items:
        if not isinstance(item, dict) or not item.get("url"):
            failed.append({"filename": (item or {}).get("filename") if isinstance(item, dict) else None,
                           "reason": "item has no url"})
            continue
        entry = fx.entry_from_item(item)
        try:
            res = fx.download(client, entry, out, link=link, max_bytes=max_bytes, pace=pace, progress=progress,
                              quarantine_dir=out / "quarantine", timeout=timeout)
        except (fx.ContentError, ContentNetworkError, OSError) as e:
            failed.append({"filename": entry.filename, "url": entry.url, "reason": str(e)})
            continue
        note = None
        if item.get("expected_etag") and res.etag and item["expected_etag"] != res.etag:
            note = "newer than the manifest (ETag changed since the node checked)"
        files.append({"filename": entry.filename, "disk_name": Path(res.path).name, "url": entry.url,
                      "sha256": res.sha256, "bytes": res.bytes, "etag": res.etag, "kind": entry.kind,
                      "product_key": entry.product_key, "version": list(entry.version) if entry.version else None,
                      "version_label": entry.version_label, "fetched_at": res.fetched_at, "note": note})
    lock = {"generated_at": utcnow(), "manifest": {"node": doc.get("node"), "generated_at": doc.get("generated_at"),
                                                   "sha256": fx.sha256_file(mp)},
            "files": files, "failed": failed}
    tmp = out / (LOCK_NAME + ".tmp")
    tmp.write_text(json.dumps(lock, indent=2), encoding="utf-8")
    os.replace(tmp, out / LOCK_NAME)
    return dict(lock, path=str(out / LOCK_NAME))
