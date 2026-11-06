"""Atomic database generations, persisted preferences/jobs, and offline transfer.

One nonblocking file lock serializes updates and transfers across API workers.
StateStore locks cover only short metadata transactions. A scan holds a separate
OS lease so generation retention works across both processes and threads.
"""
from __future__ import annotations

import copy
import hashlib
import os
import threading
import time
import uuid
import zipfile
from contextlib import ExitStack, contextmanager
from contextvars import copy_context
from cyberthunder.security.step_up import admit_transfer, authorize_transfer, transfer_continuation
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cyberthunder.control.identity import MAX_ACTOR_LEN, normalize_actor, require_human
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.control.principal import authorize
from cyberthunder.ingest.link import Link

from . import engine
from .errors import UpdateStopped, VulnerabilityConflict, VulnerabilityError, VulnerabilityUnavailable
from .storage import (CHUNK, FORMAT, GENERATION_RE, JSON_LIMIT, MANIFEST, Lease, encoded,
                      import_zip, inspect, is_link, missing_database, now, read_object, regular,
                      remove_tree, require_space, timestamp, tree_size, validate_manifest)

MAX_GENERATIONS = 4
MAX_JOBS = 50
MAX_EXPORTS = 2
MAX_LEASES = 128
DEFAULT_SETTINGS = {"revision": 0, "auto_update": False, "interval_hours": 24, "include_java": True}
ACTIVE = {"pending", "running"}


class ExportBundle:
    """An archive protected from retention until its consumer closes the lease."""

    def __init__(self, path: Path, lease: Lease):
        self.path = path
        self._lease = lease

    def close(self) -> None:
        # Leave the unlocked file for the next serialized retention pass. Unlinking
        # it here could race another process probing the same lock file.
        self._lease.close()

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, *args):
        self.close()


class VulnerabilityService:
    def __init__(self, ctx):
        self.ctx = ctx
        self.store = ctx.store
        self.root = (self.store.root / "vulnerabilities").absolute()
        self.generations = self.root / "generations"
        self.staging = self.root / "staging"
        self.exports = self.root / "exports"
        self.leases = self.root / "leases"
        self.home = self.root / "probe"
        for directory in (self.root, self.generations, self.staging, self.exports, self.leases, self.home):
            if is_link(directory):
                raise VulnerabilityUnavailable("Unsafe database storage directory")
            directory.mkdir(parents=True, exist_ok=True)
        self.state_path = self.root / "state.json"
        self.settings_path = self.root / "settings.json"
        self.jobs_dir = self.root / "jobs"
        self.threads: list[threading.Thread] = []
        self._engine_lock = threading.Lock()
        self._engine_cached: tuple[object, dict] | None = None
        self._integrity_cache: tuple[object, tuple] | None = None
        try:
            lease = Lease(self.root / "operation.lock")
        except VulnerabilityConflict:
            pass
        else:
            try:
                self._recover()
            finally:
                lease.close()

    def _setting(self, name, default):
        value = getattr(self.ctx.settings, name, None)
        return default if value is None else value

    @property
    def max_bundle_bytes(self) -> int:
        return max(1, int(self._setting("vulnerability_max_bundle_bytes", 4 * 1024 * 1024 * 1024)))

    @property
    def max_unpacked_bytes(self) -> int:
        return max(1, int(self._setting("vulnerability_max_unpacked_bytes", 8 * 1024 * 1024 * 1024)))

    @property
    def max_staging_bytes(self) -> int:
        return max(1, int(self._setting("vulnerability_max_staging_bytes", 12 * 1024 * 1024 * 1024)))

    @property
    def timeout(self) -> float:
        return max(0.01, float(self._setting("vulnerability_update_timeout_s", 1800)))

    def _state(self) -> dict:
        value = self.store.read_json(self.state_path, {})
        if not isinstance(value, dict):
            raise VulnerabilityUnavailable("Database management state is invalid")
        return value

    def _write_state(self, **changes):
        # Caller must hold the short StateStore lock.
        state = self._state()
        state.update(changes)
        self.store.write_json(self.state_path, state)

    def _guard(self, actor: str, *, online: bool = False, deadline: float | None = None,
               stage: Path | None = None, action: str | None = "admin", continuation=None):
        if continuation is not None:
            if action != "admin":
                raise PermissionError("invalid update continuation")
            authorize_transfer(self.ctx, actor=actor, continuation=continuation)
        elif action is not None:
            authorize(self.ctx, action, actor=actor)
        self.ctx.killswitch.guard("vulnerabilities.manage", actor)
        if online and not Link(self.store, self.ctx.settings).connected:
            raise UpdateStopped("Database update stopped: link disconnected")
        if deadline is not None and time.monotonic() >= deadline:
            raise UpdateStopped("Database operation timed out")
        if stage is not None:
            tree_size(stage, self.max_staging_bytes + JSON_LIMIT * 4, transient=True)

    def _audit(self, action: str, actor: str, details: dict, outcome: str = "ok"):
        self.ctx.audit.append(f"vulnerabilities.{action}", actor, details, outcome=outcome)

    def settings(self) -> dict:
        value = self.store.read_json(self.settings_path, DEFAULT_SETTINGS)
        if (not isinstance(value, dict) or set(value) != set(DEFAULT_SETTINGS)
                or type(value.get("revision")) is not int or value["revision"] < 0
                or type(value.get("auto_update")) is not bool
                or type(value.get("include_java")) is not bool
                or type(value.get("interval_hours")) is not int
                or not 1 <= value["interval_hours"] <= 168):
            raise VulnerabilityUnavailable("Database settings are invalid")
        return copy.deepcopy(value)

    def save_settings(self, changes: dict, *, actor: str) -> dict:
        actor = require_human(actor)
        self._guard(actor)
        if not isinstance(changes, dict) or set(changes) - {
                "expected_revision", "auto_update", "interval_hours", "include_java"}:
            raise VulnerabilityError("Unknown database settings")
        if type(changes.get("expected_revision")) is not int or changes["expected_revision"] < 0:
            raise VulnerabilityError("expected_revision is required")
        for key in ("auto_update", "include_java"):
            if key in changes and type(changes[key]) is not bool:
                raise VulnerabilityError(f"{key} must be a boolean")
        if "interval_hours" in changes and (type(changes["interval_hours"]) is not int
                                            or not 1 <= changes["interval_hours"] <= 168):
            raise VulnerabilityError("interval_hours must be between 1 and 168")
        with self.store.lock("vulnerabilities"):
            prefs = self.settings()
            if changes["expected_revision"] != prefs["revision"]:
                raise VulnerabilityConflict("Database settings changed; reload and retry")
            self._guard(actor)
            prefs.update({k: v for k, v in changes.items() if k != "expected_revision"})
            prefs["revision"] += 1
            self._audit("settings", actor, prefs)
            self._guard(actor)
            self.store.write_json(self.settings_path, prefs)
        return prefs

    def _engine(self, *, refresh: bool = False, guard=None) -> dict:
        binary = str(self._setting("trivy_binary", "trivy"))
        try:
            path = engine.executable(binary)
            info = Path(path).stat()
            key = (path, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        except (VulnerabilityUnavailable, OSError):
            return {"available": False, "version": None, "supported": False,
                    "error": "Trivy executable is unavailable"}
        with self._engine_lock:
            if refresh or self._engine_cached is None or self._engine_cached[0] != key:
                self._engine_cached = (key, engine.probe(binary, self.home, guard=guard))
            return copy.deepcopy(self._engine_cached[1])

    def _require_engine(self, *, refresh=False, guard=None) -> dict:
        result = self._engine(refresh=refresh, guard=guard)
        if not result["available"] or not result["supported"]:
            raise VulnerabilityUnavailable(result["error"] or "Trivy is unavailable")
        return result

    def _job_path(self, job_id: str) -> Path:
        if not isinstance(job_id, str) or not GENERATION_RE.fullmatch(job_id):
            raise KeyError(job_id)
        return self.jobs_dir / f"{job_id}.json"

    def job(self, job_id: str) -> dict:
        value = self.store.read_json(self._job_path(job_id))
        if value is None:
            raise KeyError(job_id)
        return copy.deepcopy(value)

    def jobs(self) -> list[dict]:
        values = [self.store.read_json(p) for p in self.store.list_json(self.jobs_dir)]
        return sorted((v for v in values if isinstance(v, dict)),
                      key=lambda v: (v.get("started_at") or "", v.get("id") or ""), reverse=True)[:MAX_JOBS]

    def _trim_jobs(self):
        jobs = sorted((self.store.read_json(p) for p in self.store.list_json(self.jobs_dir)),
                      key=lambda v: v.get("started_at") or "", reverse=True)
        for job in jobs[MAX_JOBS:]:
            if job["state"] not in ACTIVE:
                self.store.delete_json(self._job_path(job["id"]))

    def _recover(self):
        # The operation lock proves there is no live updater in another process.
        with self.store.lock("vulnerabilities"):
            state = self._state()
            selected = state.get("selected") or {}
            for job in self.jobs():
                if job["state"] in ACTIVE:
                    published = selected.get("job_id") == job["id"]
                    job.update(state="completed" if published else "stopped", finished_at=now(),
                               generation=selected.get("generation") if published else None,
                               error=None if published else "Database update interrupted before completion")
                    self.store.write_json(self._job_path(job["id"]), job)
                    self._write_state(last_error=job["error"])
                    self._audit("recover", job["actor"], {"job": job["id"], "state": job["state"]})
            self._trim_jobs()
        for stage in self.staging.iterdir():
            if GENERATION_RE.fullmatch(stage.name):
                remove_tree(stage, self.staging)

    def _pinned(self, generation: str) -> bool:
        pinned = False
        for path in self.leases.glob(f"{generation}.*.lock"):
            try:
                lease = Lease(path)
            except VulnerabilityConflict:
                pinned = True
            else:
                lease.close()
                path.unlink(missing_ok=True)
        return pinned

    def _make_room(self):
        # Serialize with snapshot acquisition, which creates its lease under this lock.
        with self.store.lock("vulnerabilities"):
            selected = (self._state().get("selected") or {}).get("generation")
            generations = sorted((p for p in self.generations.iterdir()
                                  if GENERATION_RE.fullmatch(p.name)), key=lambda p: p.stat().st_mtime_ns)
            for path in list(generations):
                if len(generations) < MAX_GENERATIONS:
                    break
                if path.name != selected and not self._pinned(path.name):
                    remove_tree(path, self.generations)
                    generations.remove(path)
            if len(generations) >= MAX_GENERATIONS:
                raise VulnerabilityConflict("Database retention limit reached while older scans are active")

    @contextmanager
    def _selected(self):
        lease = None
        try:
            with self.store.lock("vulnerabilities"):
                selected = copy.deepcopy(self._state().get("selected"))
                if not selected:
                    raise VulnerabilityUnavailable("No managed vulnerability database is available")
                generation = selected.get("generation")
                if not isinstance(generation, str) or not GENERATION_RE.fullmatch(generation):
                    raise VulnerabilityUnavailable("Selected database generation is invalid")
                paths = list(self.leases.glob("*.lock"))
                if len(paths) >= MAX_LEASES:
                    for old in {p.name.split(".")[0] for p in paths}:
                        self._pinned(old)
                    if len(list(self.leases.glob("*.lock"))) >= MAX_LEASES:
                        raise VulnerabilityConflict("Too many active database readers")
                lease = Lease(self.leases / f"{generation}.{uuid.uuid4().hex}.lock")
            yield selected
        finally:
            if lease is not None:
                # Release the OS resource even if the metadata lock/transaction
                # fails. A leftover unlocked lease file is safe to reclaim.
                lease.close()
                with self.store.lock("vulnerabilities"):
                    lease.path.unlink(missing_ok=True)

    def _inspect_selected(self, selected: dict, guard=lambda: None) -> tuple[Path, dict, list[dict]]:
        cache = self.generations / selected["generation"]
        try:
            if is_link(cache):
                raise VulnerabilityError("Unsafe database generation")
            manifest_path = cache / MANIFEST
            if regular(manifest_path).st_size > JSON_LIMIT:
                raise VulnerabilityError("Invalid generation manifest")
            manifest_raw = manifest_path.read_bytes()
            if hashlib.sha256(manifest_raw).hexdigest() != selected.get("manifest_sha256"):
                raise VulnerabilityError("Database manifest integrity verification failed")
            manifest = validate_manifest(read_object(manifest_raw))
            # Cache only unchanged, previously hashed payloads. ctime detects rewriting
            # followed by restoring mtime. Always re-evaluate the directory allowlist.
            tree_size(cache, self.max_unpacked_bytes + JSON_LIMIT)
            signature = (selected["generation"], manifest_raw, tuple(sorted(
                (p.relative_to(cache).as_posix(), p.stat().st_size, p.stat().st_mtime_ns,
                 p.stat().st_ctime_ns, p.stat().st_ino)
                for p in cache.rglob("*"))))
            cached = self._integrity_cache
            if cached and cached[0] == signature:
                files, databases = copy.deepcopy(cached[1])
            else:
                files, databases = inspect(cache, self.max_unpacked_bytes, guard, expected=manifest["files"])
                self._integrity_cache = (signature, copy.deepcopy((files, databases)))
            current = datetime.now(timezone.utc)
            age = timedelta(hours=max(1, int(self._setting("vulnerability_db_max_age_hours", 72))))
            for database in databases:
                if database["present"]:
                    database["stale"] = (current >= timestamp(database["next_update"])
                                         or current - timestamp(database["updated_at"]) > age)
            return cache, manifest, databases
        except (OSError, ValueError, TypeError, KeyError) as exc:
            if isinstance(exc, VulnerabilityError):
                raise VulnerabilityUnavailable(str(exc)) from None
            raise VulnerabilityUnavailable("Managed database is missing, invalid, or unreadable") from None

    def _data_status(self, selected: dict, databases: list[dict]) -> dict:
        stale = any(d["stale"] for d in databases if d["present"])
        warnings = []
        if stale:
            warnings.append("Vulnerability data is stale; scan assurance is reduced")
        if not databases[1]["present"]:
            warnings.append("Java database is absent; Java package coverage may be incomplete")
        provenance = selected.get("provenance", "unknown")
        if provenance != "official_download":
            warnings.append("Bundle hashes verify integrity, not publisher authenticity")
        return {"state": "stale" if stale else "ready", "generation": selected["generation"],
                "updated_at": databases[0]["updated_at"], "imported_at": selected.get("imported_at"),
                "source": selected.get("source"), "provenance": provenance, "integrity_verified": True,
                "databases": databases, "warnings": warnings}

    def status(self) -> dict:
        result = {"version": 1, "engine": self._engine(), "state": "missing", "generation": None,
                  "updated_at": None, "imported_at": None, "last_attempt": None, "last_success": None,
                  "last_error": None, "source": None, "provenance": "unknown", "integrity_verified": False,
                  "databases": [missing_database("main"), missing_database("java")],
                  "settings": self.settings(), "active_job": next((j for j in self.jobs()
                                                                      if j["state"] in ACTIVE), None),
                  "warnings": []}
        state = self._state()
        for key in ("last_attempt", "last_success", "last_error"):
            result[key] = state.get(key)
        if state.get("selected"):
            try:
                with self._selected() as selected:
                    _, _, databases = self._inspect_selected(selected)
                    result.update(self._data_status(selected, databases))
            except VulnerabilityError as exc:
                result["state"] = "invalid"
                result["warnings"].append(str(exc))
        if not result["engine"]["supported"]:
            if result["state"] in {"ready", "stale"}:
                result["state"] = "unavailable"
            result["warnings"].append(result["engine"]["error"] or "Trivy is unavailable")
        return result

    @contextmanager
    def scan_context(self):
        # Reading an existing generation belongs to the caller's target scan;
        # it does not confer or require node database-management permission.
        guard = lambda: self._guard("scanner", action=None)
        guard()
        engine_status = self._require_engine(guard=guard)
        with self._selected() as selected:
            cache, _, databases = self._inspect_selected(selected, guard)
            snapshot = self._data_status(selected, databases)
            snapshot.update(version=1, cache_dir=cache, engine=engine_status)
            guard()
            yield copy.deepcopy(snapshot)

    def _publish(self, cache: Path, *, actor: str, provenance: str, job_id: str | None = None,
                 guard=lambda: None) -> str:
        files, _ = inspect(cache, self.max_unpacked_bytes, guard)
        created = now()
        source = "official_trivy" if provenance == "official_download" else "offline_bundle"
        manifest = {"format": FORMAT, "version": 1, "created_at": created,
                    "provenance": provenance, "source": source, "files": files}
        raw = encoded(manifest)
        guard()
        with (cache / MANIFEST).open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        generation = uuid.uuid4().hex
        selected = {"generation": generation, "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                    "provenance": provenance, "source": source, "job_id": job_id,
                    "imported_at": created if provenance == "offline_import" else None}
        guard()
        self._audit("publish", actor, {"generation": generation, "provenance": provenance,
                                       "job": job_id, "files": files}, outcome="prepared")
        with self.store.lock("vulnerabilities"):
            guard()
            os.replace(cache, self.generations / generation)
            # This single document is the commit point on both storage backends.
            # A failed write leaves an unselected orphan for retention to reclaim.
            guard()
            self._write_state(selected=selected, last_success=created, last_error=None)
        return generation

    def update(self, *, actor: str, include_java: bool = True, background: bool = True) -> dict:
        return self._start_update(actor=require_human(actor), include_java=include_java, background=background)

    def _start_update(self, *, actor: str, include_java: bool, background: bool, scheduled=False) -> dict | None:
        if type(include_java) is not bool or type(background) is not bool:
            raise VulnerabilityError("include_java and background must be booleans")
        self._guard(actor, online=True)
        lease = Lease(self.root / "operation.lock")
        admission = None
        try:
            self._recover()
            if scheduled and not self.due_update():
                lease.close()
                return None
            self._make_room()
            job = {"id": uuid.uuid4().hex, "kind": "update", "state": "pending", "started_at": now(),
                   "finished_at": None, "actor": actor, "error": None, "generation": None}
            with self.store.lock("vulnerabilities"):
                if scheduled:
                    if not self.due_update():
                        lease.close()
                        return None
                    include_java = self.settings()["include_java"]
                self._guard(actor, online=True)
                admission = admit_transfer(self.ctx, operation="vulnerabilities.update", job_id=job["id"],
                    intent=self._update_intent(include_java), actor=actor)
                self._audit("update", actor, {"job": job["id"], "include_java": include_java,
                                              "scheduled": scheduled})
                self.store.write_json(self._job_path(job["id"]), job)
                self._write_state(last_attempt=job["started_at"], last_error=None)
                self._trim_jobs()
            if background:
                self.threads = [t for t in self.threads if t.is_alive()]
                try:
                    thread = threading.Thread(target=copy_context().run, args=(self._run_update, job, include_java, lease, admission),
                                              name="vulnerability-update", daemon=True)
                    thread.start()
                    self.threads.append(thread)
                except Exception:
                    self._finish(job, "failed", error="Database update worker could not start")
                    raise VulnerabilityUnavailable("Database update worker could not start") from None
                return copy.deepcopy(job)
            self._run_update(job, include_java, lease, admission)
            return self.job(job["id"])
        except BaseException:
            if admission is not None:
                admission.close()
            lease.close()
            raise

    def _update_intent(self, include_java):
        return {"include_java": include_java, "settings": self.settings(), "timeout": self.timeout,
                "binary": str(self._setting("trivy_binary", "trivy")),
                "max_staging_bytes": self.max_staging_bytes, "max_unpacked_bytes": self.max_unpacked_bytes}

    def _finish(self, job: dict, state: str, error: str | None = None, generation: str | None = None):
        job = {**job, "state": state, "finished_at": now(), "error": error, "generation": generation}
        with self.store.lock("vulnerabilities"):
            self.store.write_json(self._job_path(job["id"]), job)
            self._write_state(last_error=error)
            self._trim_jobs()
        self._audit("update_finished", job["actor"], {"job": job["id"], "state": state,
                                                     "generation": generation, "error": error},
                    outcome="ok" if state == "completed" else state)

    def _run_update(self, job: dict, include_java: bool, lease: Lease, admission=None):
        stage = self.staging / job["id"]
        generation = None
        def continuation():
            return transfer_continuation(admission, operation="vulnerabilities.update", job_id=job["id"],
                                         intent=self._update_intent(include_java))
        try:
            self._guard(job["actor"], online=True, continuation=continuation())
            stage.mkdir()
            cache, home = stage / "cache", stage / "home"
            cache.mkdir()
            home.mkdir()
            config = home / "trivy.yaml"
            config.write_text("{}\n", encoding="utf-8", newline="\n")
            deadline = time.monotonic() + self.timeout
            guard = lambda: self._guard(job["actor"], online=True, deadline=deadline, stage=stage, continuation=continuation())
            guard()
            require_space(stage, self.max_staging_bytes)
            job = {**job, "state": "running"}
            with self.store.lock("vulnerabilities"):
                self.store.write_json(self._job_path(job["id"]), job)
            self._require_engine(refresh=True, guard=guard)
            binary = engine.executable(str(self._setting("trivy_binary", "trivy")))
            for java in ([False, True] if include_java else [False]):
                guard()
                args = engine.download_args(binary, cache, config, deadline - time.monotonic(), java=java)
                engine.run(args, home=home, timeout=max(0.01, deadline - time.monotonic()), guard=guard)
            _, databases = inspect(cache, self.max_unpacked_bytes, guard)
            if include_java and not databases[1]["present"]:
                raise VulnerabilityError("Requested Java database was not downloaded")
            generation = self._publish(cache, actor=job["actor"], provenance="official_download",
                                       job_id=job["id"], guard=guard)
            self._finish(job, "completed", generation=generation)
        except (KillSwitchEngaged, UpdateStopped, PermissionError) as exc:
            error = ("Database update stopped: account authorization expired or was revoked"
                     if isinstance(exc, PermissionError) else
                     "Database update stopped by kill switch" if isinstance(exc, KillSwitchEngaged) else str(exc))
            self._finish(job, "stopped", error=error[:256])
        except Exception as exc:
            # Never return subprocess output, filesystem paths, credentials, or
            # unexpected exception text through status, jobs, or the audit log.
            if generation is not None:
                # Publication is already committed; recovery can repair a job write.
                return
            error = str(exc)[:256] if isinstance(exc, VulnerabilityError) else "Database update failed"
            self._finish(job, "failed", error=error)
        finally:
            if admission is not None:
                admission.close()
            try:
                remove_tree(stage, self.staging)
            finally:
                lease.close()

    def wait(self, timeout: float | None = None):
        deadline = None if timeout is None else time.monotonic() + timeout
        for thread in list(self.threads):
            thread.join(None if deadline is None else max(0, deadline - time.monotonic()))

    def import_bundle(self, path: Path, *, actor: str) -> dict:
        actor = require_human(actor)
        self._guard(actor, action="import")
        with Lease(self.root / "operation.lock"):
            self._recover()
            self._make_room()
            stage = self.staging / uuid.uuid4().hex
            stage.mkdir()
            cache = stage / "cache"
            cache.mkdir()
            deadline = time.monotonic() + self.timeout
            guard = lambda: self._guard(actor, deadline=deadline, stage=stage, action="import")
            with self.store.lock("vulnerabilities"):
                self._write_state(last_attempt=now())
            try:
                guard()
                if regular(Path(path)).st_size > self.max_bundle_bytes:
                    raise VulnerabilityError("Compressed bundle size limit exceeded")
                import_zip(Path(path), cache, self.max_unpacked_bytes, guard)
                self._publish(cache, actor=actor, provenance="offline_import", guard=guard)
            except (KillSwitchEngaged, VulnerabilityError, OSError) as exc:
                error = str(exc)[:256] if isinstance(exc, VulnerabilityError) else "Database import stopped or failed"
                with self.store.lock("vulnerabilities"):
                    self._write_state(last_error=error)
                self._audit("import_failed", actor, {"error": error}, outcome="failed")
                if isinstance(exc, OSError) and not isinstance(exc, PermissionError):
                    raise VulnerabilityError("Database bundle could not be read") from None
                raise
            finally:
                remove_tree(stage, self.staging)
        return self.status()

    def export_bundle(self, *, actor: str) -> Path:
        """Return a retained cache path; use export_lease while consuming its bytes."""
        with self.export_lease(actor=actor) as path:
            return path

    def _make_export_room(self):
        # Caller holds operation.lock. All export leases are acquired under it;
        # release only unlocks, so crash leftovers can be removed without races.
        for path in self.exports.glob("*.lock"):
            try:
                lease = Lease(path)
            except VulnerabilityConflict:
                continue
            lease.close()
            path.unlink(missing_ok=True)
        exports = sorted(self.exports.glob("*.zip"), key=lambda p: p.stat().st_mtime_ns)
        for path in exports:
            if len(exports) < MAX_EXPORTS:
                break
            lock_path = path.with_suffix(".lock")
            try:
                lease = Lease(lock_path)
            except VulnerabilityConflict:
                continue
            try:
                path.unlink()
            except OSError:
                continue
            else:
                exports = [p for p in exports if p != path]
            finally:
                lease.close()
                lock_path.unlink(missing_ok=True)
        if len(exports) >= MAX_EXPORTS:
            raise VulnerabilityConflict("Database exports are still in use")

    def export_lease(self, *, actor: str) -> ExportBundle:
        actor = require_human(actor)
        self._guard(actor, action="export")
        with ExitStack() as cleanup:
            with Lease(self.root / "operation.lock"), self._selected() as selected:
                deadline = time.monotonic() + self.timeout
                guard = lambda: self._guard(actor, deadline=deadline, action="export")
                cache, manifest, _ = self._inspect_selected(selected, guard)
                for partial in self.exports.glob("*.partial"):
                    partial.unlink(missing_ok=True)
                self._make_export_room()
                output = self.exports / f"{uuid.uuid4().hex}.zip"
                partial = output.with_suffix(".partial")
                try:
                    guard()
                    require_space(self.exports, self.max_bundle_bytes)
                    with zipfile.ZipFile(partial, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                        archive.writestr(MANIFEST, encoded(manifest))
                        for name, expected in manifest["files"].items():
                            hasher = hashlib.sha256()
                            count = 0
                            with (cache / name).open("rb") as src, archive.open(name, "w", force_zip64=True) as dest:
                                while block := src.read(CHUNK):
                                    guard()
                                    count += len(block)
                                    if count > expected["bytes"]:
                                        raise VulnerabilityUnavailable("Database changed during export")
                                    dest.write(block)
                                    hasher.update(block)
                                    if archive.fp.tell() > self.max_bundle_bytes:
                                        raise VulnerabilityError("Compressed bundle size limit exceeded")
                            if count != expected["bytes"] or hasher.hexdigest() != expected["sha256"]:
                                raise VulnerabilityUnavailable("Database integrity verification failed during export")
                    if partial.stat().st_size > self.max_bundle_bytes:
                        raise VulnerabilityError("Compressed bundle size limit exceeded")
                    guard()
                    self._audit("export", actor, {"generation": selected["generation"],
                                                  "provenance": selected["provenance"]})
                    guard()
                    os.replace(partial, output)
                    lease = Lease(output.with_suffix(".lock"))
                    cleanup.callback(lease.close)
                    result = ExportBundle(output, lease)
                finally:
                    partial.unlink(missing_ok=True)
            cleanup.pop_all()
            return result

    def due_update(self) -> bool:
        prefs = self.settings()
        if (not prefs["auto_update"] or self.ctx.killswitch.is_engaged()
                or not Link(self.store, self.ctx.settings).connected):
            return False
        if any(job["state"] in ACTIVE for job in self.jobs()):
            try:
                lease = Lease(self.root / "operation.lock")
            except VulnerabilityConflict:
                return False
            else:
                # A dead worker must not block an already-running scheduler forever.
                # Let update_scheduled recover it, then recheck the retry interval.
                lease.close()
                return True
        last = self._state().get("last_attempt")
        if last is None:
            return True
        try:
            return datetime.now(timezone.utc) >= timestamp(last) + timedelta(hours=prefs["interval_hours"])
        except VulnerabilityError:
            return False

    def update_scheduled(self) -> dict | None:
        if not self.due_update():
            return None
        actor = normalize_actor(self._setting("scheduler_actor", "scheduler"))
        if not actor or len(actor) > MAX_ACTOR_LEN or any(ord(c) < 32 or ord(c) == 127 for c in actor):
            raise PermissionError("Database scheduler requires a named scheduler actor")
        try:
            return self._start_update(actor=actor, include_java=self.settings()["include_java"],
                                      background=True, scheduled=True)
        except (VulnerabilityConflict, KillSwitchEngaged, UpdateStopped):
            return None


__all__ = ["VulnerabilityService", "VulnerabilityError", "VulnerabilityUnavailable", "VulnerabilityConflict"]
