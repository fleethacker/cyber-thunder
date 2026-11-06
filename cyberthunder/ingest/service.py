"""IngestService: the one entry point for STIG releases, bulletins, the link and the outbox.

Everything here is read-only with respect to assets. A STIG delta only updates the local catalog and,
on request, starts a targeted rescan through the Scanner (which enforces scope). A bulletin only matches
the package inventories the Scanner already collected. Fixes for what is found still go through the
fix library, the approval gate and the kill switch like any other finding.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

from cyberthunder.findings.schema import summarize, utcnow
from cyberthunder.control.principal import authorize, require_current
from cyberthunder.ingest import bulletin as bl
from cyberthunder.ingest import compress, delta as dl
from cyberthunder.ingest.link import Link, LinkState, transfer_seconds
from cyberthunder.ingest.outbox import Outbox
from cyberthunder.security.resources import check_record

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext
    from cyberthunder.scan import ScanRun


class IngestError(RuntimeError):
    pass


class IngestService:
    def __init__(self, ctx: "AppContext"):
        self.ctx = ctx
        self.store = ctx.store
        self.audit = ctx.audit
        self._link = Link(self.store, ctx.settings, self.audit)
        self._outbox = Outbox(self.store, self._link, self.audit)
        self._link.on_reconnect = self._flush_on_reconnect
        self._content = None

    def import_scanner(self, data: bytes, host_map: dict[str, str], *, actor: str,
                       include_info: bool = False) -> dict:
        """Import an offline Nessus/ACAS export without collecting or proposing changes."""
        from cyberthunder.ingest.scanner_results import import_results
        return import_results(self.ctx, data, host_map, actor=actor, include_info=include_info)

    # -- link / outbox -----------------------------------------------------------------------------
    @property
    def link(self) -> Link:
        return self._link

    @property
    def outbox(self) -> Outbox:
        return self._outbox

    def link_state(self) -> LinkState:
        return self._link.state()

    def set_link(self, *, actor: str, **changes) -> LinkState:
        self.ctx.killswitch.guard("link.change", actor)
        return self._link.set(actor=actor, **changes)

    def _flush_on_reconnect(self, actor: str) -> dict:
        self.ctx.killswitch.guard("link.reconnect", actor)
        result = self._outbox.sync(actor=actor)
        try:
            content = self.content.on_reconnect(actor)
        except Exception as e:  # noqa: BLE001 - the outbox flush already happened; report, do not undo
            content = {"error": str(e)}
        return dict(result, content=content)

    # -- DISA content updates (see cyberthunder/ingest/content/) ------------------------------------
    @property
    def content(self):
        if self._content is None:
            from cyberthunder.ingest.content.service import ContentService
            self._content = ContentService(self)
        return self._content

    def check_updates(self, actor: str = "operator", *, source: str = "live", include_automation: bool = False,
                      include_compilation: bool = False) -> dict:
        """Fetch the DISA STIG index (or read the bundled snapshot) and work out what this node needs."""
        return self.content.check_updates(actor, source=source, include_automation=include_automation,
                                          include_compilation=include_compilation)

    def last_update_check(self) -> dict | None:
        return self.content.last_check()

    def pull(self, actor: str = "operator", *, filenames: list[str] | None = None, all_matching: bool = False,
             pace: bool = False, background: bool = True) -> dict:
        """Download content (named files, or every update from the last check) as a job record."""
        return self.content.pull(actor, filenames=filenames, all_matching=all_matching, pace=pace,
                                 background=background)

    def pull_job(self, job_id: str) -> dict:
        return self.content.get_job(job_id)

    def held_content(self) -> dict:
        return self.content.content()

    def write_manifest(self, actor: str = "operator", path: str | Path | None = None) -> dict:
        """The wanted-but-missing list as a manifest a connected machine can fetch."""
        return self.content.write_manifest(actor, path)

    def fetch_manifest(self, manifest_path: str | Path, out_dir: str | Path, opener=None, **kw) -> dict:
        """Run the downloader for a manifest (normally on the connected machine; see content.service)."""
        from cyberthunder.ingest.content.service import fetch_manifest
        return fetch_manifest(manifest_path, out_dir, opener, link=self._link.state(), **kw)

    def import_dir(self, path: str | Path, actor: str = "operator") -> dict:
        """Import every DISA file in a folder (removable media), verified against manifest.lock.json if present."""
        return self.content.import_dir(path, actor)

    # -- STIG releases -----------------------------------------------------------------------------
    def ingest_stig(self, path_or_bytes: str | Path | bytes, filename: str | None = None, *,
                    old: str | Path | None = None, actor: str = "operator", method: str | None = None,
                    receipt_source: str = "local") -> dict:
        """Diff a new STIG release against the catalog copy (or `old`), store the delta, make the new release
        the catalog copy, and report sizes and transfer time at the current link."""
        from cyberthunder.ingest.content import fetch as fx, signatures as sig
        self.ctx.killswitch.guard("ingest.stig", actor)
        maximum = min(self.content.max_bytes, sig.MAX_FILE_BYTES)
        if isinstance(path_or_bytes, (bytes, bytearray)) and not 0 < len(path_or_bytes) <= maximum:
            raise sig.AuthenticityError("Invalid content import size")
        staging = self.content.store.root / "incoming"
        staging.mkdir(parents=True, exist_ok=True)
        report = None
        try:
            with tempfile.TemporaryDirectory(prefix="stig-", dir=staging) as temporary:
                name = filename or ("benchmark.xml" if isinstance(path_or_bytes, (bytes, bytearray)) else Path(path_or_bytes).name)
                path = Path(temporary) / fx.disk_name(name)
                if isinstance(path_or_bytes, (bytes, bytearray)):
                    path.write_bytes(path_or_bytes)
                    digest, size = hashlib.sha256(path_or_bytes).hexdigest(), len(path_or_bytes)
                else:
                    digest, size = sig.copy_checked(path_or_bytes, path, maximum=maximum)
                sig.acceptance(self.ctx, actor, digest, size)
                entry = fx.entry_from_item({"filename": name, "url": "", "kind": "manual_stig"})
                record = self.content._accept(path, entry, source=receipt_source, actor=actor, sha256=digest,
                                              etag=None, size=size, old=old, method=method, catalog_import=True)
                report = dict(record["ingest"]["report"])
                report.update(generation=record["generation"], active=record["active"], commit_status=record["commit_status"])
                return report
        except OSError:
            if report is None:
                raise
            report["commit_status"] = "committed_with_bookkeeping_pending"
            return report

    def _prepare_stig(self, path, filename, *, previous=None, actor, method=None, receipt_source="local"):
        """Build complete delta artifacts without changing any catalog or index."""
        new = dl.load_benchmark(path)
        prev = dl.load_benchmark(previous) if previous and Path(previous).exists() else None
        if prev and prev[0] != new[0]:
            raise IngestError("Previous benchmark identity does not match the candidate")
        report = dl.diff(prev, new)
        full = path.read_bytes()
        payload = compress.delta_payload(report, new[2])
        sizes = compress.compare(full, payload, method or self._default_method())
        state = self._link.state()
        from cyberthunder.ingest.content import signatures as sig
        authenticity = sig.acceptance(self.ctx, actor, hashlib.sha256(full).hexdigest(), len(full))
        return dict(report.to_dict(), filename=filename, sizes=sizes,
                    transfer={"full_seconds": transfer_seconds(sizes["full_bytes"], state),
                              "delta_seconds": transfer_seconds(sizes["compressed_bytes"], state), "link": state.to_dict()},
                    full_import=prev is None, receipt_source=receipt_source,
                    authenticity=dict(authenticity, sha256=hashlib.sha256(full).hexdigest(), bytes=len(full))), dl.read_benchmark_xml(path)

    @staticmethod
    def _default_method() -> str:
        import os
        return "external" if os.environ.get("CT_COMPRESSOR") else "lzma"

    def get_delta(self, delta_id: str) -> dict:
        d = next((row for row in dl.list_deltas(self.store) if row["id"] == delta_id), None)
        if d is None:
            raise KeyError(f"no delta {delta_id!r}")
        return d

    def rescan_for_delta(self, delta_id: str, requested_by: str = "operator",
                         target_ids: list[str] | None = None) -> "ScanRun":
        """Targeted rescan of only the rules the delta added or changed."""
        report = dl.load_delta(self.store, delta_id)
        if not report.rescan_rule_ids:
            raise IngestError(f"delta {delta_id} adds or changes no rules; nothing to rescan")
        try:
            return self.ctx.scanner.start(target_ids, rule_filter=list(report.rescan_rule_ids), trigger="stig_delta",
                                          requested_by=requested_by)
        except NotImplementedError:
            raise IngestError("the scanner is not available on this node yet; run a full scan when it is") from None

    # -- bulletins ---------------------------------------------------------------------------------
    def ingest_bulletin(self, data: bytes | str | Mapping, *, actor: str = "operator") -> dict:
        self._guard_bulletin([], actor, action="import")
        b = bl.parse_bulletin(data)
        ownership = {}
        guard = self._collected_guard(actor, "read", ownership)
        collected, stale = self._in_scope(bl.latest_collected(self.store, guard=guard))
        targets = {t.id: t for t in self.ctx.inventory.all()}
        findings = bl.match(b, collected, targets)
        for finding in findings:
            finding.authorization_scope = ownership.get(finding.host)
        hosts = bl.affected_hosts(findings)
        scan_id = self._save_bulletin_run(findings, actor, {"trigger": "bulletin", "bulletin_id": b.id}, action="import")
        self._guard_bulletin(hosts, actor, action="import")
        for host in collected:
            check_record(self.ctx, {"host": host, "authorization_scope": ownership.get(host)})
        bl.save_bulletin(self.store, b, {"ingested_at": utcnow(), "ingested_by": actor, "hosts_affected": hosts,
                                         "hosts_checked": sorted(collected), "findings": len(findings),
                                         "scan_id": scan_id})
        self.audit.append("ingest.bulletin", actor, {"bulletin_id": b.id, "cves": b.cves, "hosts_checked": len(collected),
                                                     "hosts_affected": hosts, "findings": len(findings),
                                                     "scan_id": scan_id, "skipped_out_of_scope": stale},
                          subject=b.id)
        return {"bulletin_id": b.id, "hosts_affected": hosts, "hosts_checked": sorted(collected),
                "findings": [f.to_dict() for f in findings], "scan_id": scan_id}

    def rematch_all(self, scan_id: str, *, actor: str | None = None) -> dict:
        """Re-run every stored bulletin against the inventories collected by scan_id.

        Bulletins stay in force until the packages are patched: the current picture is the newest full scan
        plus newer partial runs, so after each full scan the bulletins are matched again and saved as one
        partial run (trigger 'bulletin'). Hosts that are no longer in scope are left out."""
        if actor is None:
            actor = (require_current("scan").actor if getattr(self.ctx.settings, "auth_mode", "dev") != "dev"
                     else "scanner")
        collected: dict[str, dict] = {}
        ownership = {}
        guard = self._collected_guard(actor, "scan", ownership)
        raw = self.store.scans_dir / scan_id / "raw"
        if raw.is_dir():
            for p in sorted(raw.glob("*/collected.json")):
                if not guard(scan_id, p.parent.name):
                    continue
                try:
                    collected[p.parent.name] = json.loads(p.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
        collected, stale = self._in_scope(collected)
        # A full scan reevaluates previously accepted bulletin data with scan
        # authority. It must not obtain import privilege or create new bulletins.
        self._guard_bulletin(collected, actor, action="scan")
        stored = bl.list_bulletins(self.store)
        if not stored or not collected:
            return {"scan_id": None, "bulletins": [], "findings": 0, "hosts_affected": []}
        targets = {t.id: t for t in self.ctx.inventory.all()}
        findings = []
        ids: list[str] = []
        for doc in stored:
            try:
                b = bl.parse_bulletin(doc)
            except bl.BulletinError:
                continue
            ids.append(b.id)
            findings.extend(bl.match(b, collected, targets))
        for finding in findings:
            finding.authorization_scope = ownership.get(finding.host)
        hosts = bl.affected_hosts(findings)
        run_id = self._save_bulletin_run(findings, actor, {"trigger": "bulletin", "bulletin_ids": ids,
                                                           "rematch_of": scan_id}, action="scan")
        self.audit.append("ingest.bulletin_rematch", actor, {"scan_id": scan_id, "bulletins": ids,
                                                             "hosts_checked": len(collected), "hosts_affected": hosts,
                                                             "findings": len(findings), "run_id": run_id,
                                                             "skipped_out_of_scope": stale}, subject=scan_id)
        return {"scan_id": run_id, "bulletins": ids, "findings": len(findings), "hosts_affected": hosts}

    def _in_scope(self, collected: Mapping[str, dict]) -> tuple[dict[str, dict], list[str]]:
        """Split collected inventories into in-scope ones and the ids of stale, out-of-scope hosts."""
        keep = {tid: c for tid, c in collected.items() if self.ctx.inventory.in_scope(tid)}
        return keep, sorted(tid for tid in collected if tid not in keep)

    def _collected_guard(self, actor, action, ownership):
        def guard(scan_id, host):
            if getattr(self.ctx.settings, "auth_mode", "dev") == "dev":
                return True
            if not self.ctx.inventory.in_scope(host):
                return False
            run = self.store.load_scan_run(scan_id) or {}
            scopes = run.get("authorization_scopes")
            targets = run.get("targets")
            matches = [s for s in scopes if isinstance(s, dict) and s.get("target_id") == host] if (
                isinstance(scopes, list) and isinstance(targets, list) and host in targets) else []
            scope = matches[0] if len(matches) == 1 else None
            check_record(self.ctx, {"host": host, "authorization_scope": scope}, action)
            authorize(self.ctx, action, actor=actor, target=host)
            self.ctx.killswitch.guard("ingest.bulletin", actor)
            ownership[host] = scope
            return True
        return guard

    def _guard_bulletin(self, hosts, actor: str, *, action: str) -> None:
        if action == "import":
            authorize(self.ctx, "import", actor=actor)
        for host in sorted(set(hosts)):
            authorize(self.ctx, action, actor=actor, target=host)
        self.ctx.killswitch.guard("ingest.bulletin", actor)

    def _save_bulletin_run(self, findings: list, actor: str, meta: dict, *, action: str) -> str | None:
        """Persist bulletin findings as one partial scan run. No findings, no run."""
        from cyberthunder.scan import ScanRun, TargetScanResult
        if not findings:
            return None
        hosts = bl.affected_hosts(findings)
        now = utcnow()
        scan_id = self.store.new_id("scan-")
        for f in findings:
            f.scan_id = scan_id
        results = {}
        for h in hosts:
            n = sum(1 for f in findings if f.host == h)
            results[h] = TargetScanResult(target_id=h, status="done", started_at=now, finished_at=now,
                                          findings=n, open=n)
        run = ScanRun(id=scan_id, targets=hosts, modules=["cve"], trigger="bulletin", requested_by=actor,
                      status="done", started_at=now, finished_at=now, results=results,
                      findings_count=len(findings), summary=summarize(findings))
        self._guard_bulletin(hosts, actor, action=action)
        for finding in findings:
            check_record(self.ctx, finding, action)
        self.store.save_findings(scan_id, findings, meta=meta)
        self._guard_bulletin(hosts, actor, action=action)
        for finding in findings:
            check_record(self.ctx, finding, action)
        self.store.save_scan_run(run.to_dict())
        return scan_id

    # -- history -----------------------------------------------------------------------------------
    def history(self) -> dict[str, Any]:
        deltas = [{k: d.get(k) for k in ("id", "benchmark_id", "old_release", "new_release", "counts", "created_at",
                                          "filename", "sizes", "transfer", "full_import")}
                  for d in dl.list_deltas(self.store)]
        bulletins = [{k: d.get(k) for k in ("id", "title", "severity", "cves", "published", "ingested_at",
                                             "hosts_affected", "findings", "scan_id")}
                     for d in bl.list_bulletins(self.store)]
        return {"deltas": deltas, "bulletins": bulletins}

    def enqueue_json(self, kind: str, name: str, doc: Any, *, actor: str = "operator", meta: dict | None = None) -> dict:
        """Convenience for reports: queue a JSON document for shore."""
        data = json.dumps(doc, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
        return self._outbox.enqueue(kind, name, data, meta, actor=actor)
