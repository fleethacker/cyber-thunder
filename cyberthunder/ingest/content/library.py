"""Offline library views and durable content subscriptions. Reading this module never fetches content."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import xml.etree.ElementTree as ET

from cyberthunder.control.identity import require_human
from cyberthunder.findings.schema import utcnow
from cyberthunder.ingest import delta
from cyberthunder.ingest.content.select import select
from cyberthunder.ingest.content.index import reconcile

CONTENT_KINDS = ("manual_stig", "srg", "scap_benchmark")


class PreferenceConflict(ValueError):
    """Another operator changed these subscriptions; reload before saving."""


@lru_cache(maxsize=128)
def _catalog_meta(path: str, mtime: int, size: int) -> dict:
    if size > 256 * 1024 * 1024:
        raise ValueError("catalog exceeds the metadata read limit")
    root = ET.parse(path).getroot()
    bench = next((el for el in root.iter() if el.tag.rsplit("}", 1)[-1] == "Benchmark"), None)
    if bench is None:
        raise ValueError("no XCCDF benchmark")
    def text(name):
        el = next((e for e in bench if e.tag.rsplit("}", 1)[-1] == name), None)
        return "".join(el.itertext()).strip() if el is not None else None
    release = next(("".join(e.itertext()).strip() for e in bench
                    if e.tag.rsplit("}", 1)[-1] == "plain-text" and e.get("id") == "release-info"), None)
    version = text("version")
    return {"benchmark_id": bench.get("id"), "title": text("title") or bench.get("id"),
            "release": f"Version {version}; {release}" if version and release else release or version,
            "rules": sum(e.tag.rsplit("}", 1)[-1] == "Rule" for e in bench.iter())}


class ContentLibrary:
    def __init__(self, service):
        self.service = service
        self.state = service.store.state
        self.root = service.store.root

    def preferences(self) -> dict:
        saved = self.state.read_json(self.root / "preferences.json", {}) or {}
        settings = self.service.settings
        return {"mode": "inventory", "products": [], "kinds": list(CONTENT_KINDS),
                "check_on_reconnect": bool(getattr(settings, "content_check_on_reconnect", False)),
                "auto_pull": bool(getattr(settings, "content_auto_pull", False)), "revision": 0,
                "updated_at": None, "updated_by": None, **saved}

    def save_preferences(self, changes: dict, actor: str) -> dict:
        actor = require_human(actor)
        self.service.ctx.killswitch.guard("content.preferences", actor)
        keys = {"mode", "products", "kinds", "check_on_reconnect", "auto_pull", "revision"}
        if set(changes) != keys:
            raise ValueError("send the complete subscription settings and revision")
        if changes["mode"] not in ("inventory", "selected"):
            raise ValueError("subscription mode must be inventory or selected")
        if any(type(changes[k]) is not bool for k in ("check_on_reconnect", "auto_pull")):
            raise ValueError("reconnect options must be boolean")
        if type(changes["revision"]) is not int or changes["revision"] < 0:
            raise ValueError("revision must be a nonnegative integer")
        products, kinds = changes["products"], changes["kinds"]
        if not isinstance(products, list) or len(products) > 1000 or any(
            not isinstance(p, str) or not p or len(p) > 180 for p in products
        ):
            raise ValueError("products must be a list of product keys from the catalog")
        if not isinstance(kinds, list) or any(k not in CONTENT_KINDS for k in kinds):
            raise ValueError("unsupported content kind")
        with self.state.files.lock("content-preferences"):
            old = self.preferences()
            if changes["revision"] != old["revision"]:
                raise PreferenceConflict("Update selections changed in another session; reload before saving")
            entries, _ = self.service.catalog_entries()
            known = {e.product_key for e in entries if e.kind in CONTENT_KINDS and e.format_supported} | set(old["products"])
            if any(p not in known for p in products):
                raise ValueError("an unknown product was selected; refresh the local catalog")
            new = {**changes, "products": sorted(set(products)), "kinds": sorted(set(kinds)),
                   "revision": old["revision"] + 1, "updated_at": utcnow(), "updated_by": actor}
            self.service.audit.append("content.preferences", actor,
                                      {"before": old, "after": new}, subject="content-subscriptions")
            self.state.write_json(self.root / "preferences.json", new)
        return new

    def record_check(self, started_at: str, status: str, error: str | None = None) -> None:
        with self.state.files.lock("content-sync"):
            path = self.root / "sync.json"
            doc = self.state.read_json(path, {}) or self.sync_status([])
            if started_at >= (doc.get("last_attempt_at") or ""):
                doc.update(last_attempt_at=started_at, last_attempt_status=status,
                           last_error=error[:300] if error else None)
            if status == "success":
                doc["last_successful_check_at"] = max(utcnow(), doc.get("last_successful_check_at") or "")
            self.state.write_json(path, doc)

    def record_transfer(self, source: str, at: str) -> None:
        key = "last_download_at" if source == "pulled" else "last_import_at"
        with self.state.files.lock("content-sync"):
            path = self.root / "sync.json"
            doc = self.state.read_json(path, {}) or self.sync_status([])
            doc[key] = max(at, doc.get(key) or "")
            self.state.write_json(path, doc)

    def record_index(self, status: str, error: str | None = None) -> None:
        with self.state.files.lock("content-sync"):
            path = self.root / "sync.json"
            doc = self.state.read_json(path, {}) or self.sync_status([])
            doc.update(live_index_status=status, last_index_attempt_at=utcnow(),
                       last_index_error=error[:300] if error else None)
            self.state.write_json(path, doc)

    def sync_status(self, records: list[dict]) -> dict:
        doc = self.state.read_json(self.root / "sync.json", {}) or {}
        cached = self.state.read_json(self.service.catalog_cache, {}) or {}
        last = self.service.store.last_check() or {}
        live = cached.get("saved_at") if not doc and cached.get("source") == "live" and cached.get("entries") else None
        if not doc and last.get("source") == "live":
            live = max(live or "", last.get("checked_at") or "") or None
        return {"last_attempt_at": doc.get("last_attempt_at") or live,
                "live_index_status": doc.get("live_index_status") or ("available" if live else "unconfirmed"),
                "last_index_attempt_at": doc.get("last_index_attempt_at"),
                "last_index_error": doc.get("last_index_error"),
                "last_attempt_status": doc.get("last_attempt_status") or ("success" if live else None),
                "last_error": doc.get("last_error"),
                "last_successful_check_at": doc.get("last_successful_check_at") or live,
                "last_download_at": max([doc.get("last_download_at") or ""] + [r.get("fetched_at") or "" for r in records
                                         if r.get("source") == "pulled"]) or None,
                "last_import_at": max([doc.get("last_import_at") or ""] + [r.get("fetched_at") or "" for r in records
                                       if r.get("source") in ("imported", "uploaded")]) or None}

    def catalogs(self) -> tuple[list[dict], list[dict]]:
        latest = {}
        for doc in delta.list_deltas(self.state):
            latest.setdefault(doc.get("benchmark_id"), doc)
        bundled = Path(__file__).resolve().parents[3] / "STIG"
        rows, errors = [], []
        for directory, origin in ((delta.catalog_dir(self.state), "imported_catalog"),
                                  (bundled, "bundled_reference")):
            for path in sorted(directory.glob("*.xml")):
                try:
                    stat = path.stat()
                    meta = dict(_catalog_meta(str(path), stat.st_mtime_ns, stat.st_size))
                    imp = latest.get(meta["benchmark_id"], {}) if origin == "imported_catalog" else {}
                    rows.append({**meta, "origin": origin, "filename": imp.get("filename") or path.name,
                                 "imported_at": imp.get("created_at"), "path": str(path)})
                except (OSError, ValueError, ET.ParseError) as exc:
                    errors.append({"filename": path.name, "reason": str(exc)[:200]})
        return rows, errors

    def view(self) -> dict:
        entries, source = self.service.catalog_entries()
        prefs = self.preferences()
        held = self.service.content()
        selected = self.service._select(entries)
        recommended = select(entries, self.service.ctx.inventory.all(), self.service._collected(),
                             allowed_hosts=self.service.client.allowed_hosts,
                             allow_http=self.service.client.allow_http)
        groups = {}
        for e in entries:
            if not e.product_key or e.kind not in CONTENT_KINDS or not e.format_supported:
                continue
            group = groups.setdefault(e.product_key, {"product_key": e.product_key, "title": e.product_key.replace("_", " "),
                                                       "available": [], "held": [], "kinds": set()})
            group["kinds"].add(e.kind)
            group["available"].append({**e.to_dict(), "allowed": e.allowed_by(self.service.client.allowed_hosts,
                                                                            self.service.client.allow_http)})
        for key in prefs["products"]:
            groups.setdefault(key, {"product_key": key, "title": key.replace("_", " "), "available": [],
                                    "held": [], "kinds": set()})
        for record in held["files"]:
            key = record.get("product_key")
            if key in groups:
                groups[key]["held"].append(record)
        all_products = select(entries, [], {}, extra_products=groups,
                              held=held["files"], content_kinds=CONTENT_KINDS,
                              allowed_hosts=self.service.client.allowed_hosts,
                              allow_http=self.service.client.allow_http)
        updating = {r["product_key"] for r in all_products.updates}
        current = {r["product_key"] for r in all_products.current}
        for key, group in groups.items():
            group["kinds"] = sorted(group["kinds"])
            group["available"].sort(key=lambda r: (tuple(r.get("version") or ()), r.get("upload_date") or ""), reverse=True)
            group["recommended"] = key in recommended.products
            group["targets"] = recommended.products[key].targets if group["recommended"] else []
            group["selected"] = key in selected.products
            available = any(not e["sunset"] and e["allowed"] for e in group["available"])
            group["status"] = ("unavailable" if not available else "not_downloaded" if not group["held"]
                               else "update_available" if key in updating
                               else "current" if key in current else "not_downloaded")
        cache = self.state.read_json(self.service.catalog_cache, {}) or {}
        catalogs, errors = self.catalogs()
        sync = self.sync_status(held["files"])
        downloaded_names = {r["filename"] for r in held["files"] if r.get("source") == "pulled"}
        imports = [r.get("created_at") for r in delta.list_deltas(self.state)
                   if r.get("receipt_source") != "pulled" and r.get("created_at") and
                   (r.get("receipt_source") or r.get("filename") not in downloaded_names)]
        if imports:
            sync["last_import_at"] = max(sync["last_import_at"] or "", *imports)
        publications = [{**e.to_dict(), **e.accounting(self.service.client.allowed_hosts, self.service.client.allow_http),
                         "publication_id": f"row-{i}"} for i, e in enumerate(entries, 1)]
        return {"catalog": {"source": source, "saved_at": cache.get("saved_at") if source == "live" else None,
                            "total_entries": len(entries),
                            "accounting": reconcile(entries, self.service.client.allowed_hosts, self.service.client.allow_http),
                            "live_status": sync["live_index_status"], "live_error": sync["last_index_error"]},
                "publications": publications, "sync": sync, "preferences": prefs,
                "products": [groups[key] for key in sorted(groups)], "selection": selected.to_dict(),
                "held": held, "catalogs": catalogs, "catalog_errors": errors,
                "jobs": self.service.store.jobs()[:20], "connected": self.service._link().connected,
                "check_interval_s": getattr(self.service.settings, "content_check_interval_s", 0)}
