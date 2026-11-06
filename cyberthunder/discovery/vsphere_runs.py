"""Target-owned, read-only source snapshots; independent of global discovery reconciliation."""
from __future__ import annotations

from copy import deepcopy
import re
from uuid import uuid4

from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.control.principal import authorize, current_principal, operation
from cyberthunder.findings.schema import utcnow
from cyberthunder.inventory.host import persisted_target
from cyberthunder.security.resources import authorize_artifact, target_scope

from .models import DiscoveryScope
from .recipes import ScopeRecipeStore, fingerprint
from .sources import vsphere
from .sources.vsphere_access import _configuration
from .sources.vsphere_client import VsphereError

RUN_ID = re.compile(r"vsphere-[0-9a-f]{32}\Z")
# Only fixed, locally defined diagnostics may cross this boundary. Never serialize
# exception text from a transport, audit sink, credential provider or remote body.
ERRORS = frozenset("vsphere:" + code for code in (
    "invalid_data", "invalid_reference", "invalid_xml_structure", "invalid_property",
    "invalid_endpoint_or_trust", "invalid_tls_trust", "deadline", "api_fault",
    "invalid_xml_response", "http_failure", "encoded_response", "invalid_content_type",
    "invalid_framing", "body_limit", "invalid_session", "transport_failure",
    "unsupported_method", "sensitive_response", "missing_service_content", "unsupported_server",
    "missing_page", "page_limit", "inconsistent_inventory", "object_limit", "invalid_page_token",
    "repeated_page_token", "incomplete_object", "verified_binding_unavailable",
    "invalid_source_options", "conflicting_endpoint_port", "explicit_credential_required",
    "credential_unavailable",
))
PUBLIC_FIELDS = (
    "version", "id", "source", "target_id", "authorization_scope", "requested_by",
    "requested_principal", "started_at", "finished_at", "status", "collection_started",
    "complete", "observation_count", "error",
)


class VsphereRuns:
    def __init__(self, ctx):
        self.ctx = ctx
        self.directory = ctx.store.root / "discovery" / "vsphere"

    def _directory(self, ownership):
        # No caller-controlled string becomes a filesystem path, and listing one
        # source does not enumerate another source's documents or old generations.
        return self.directory / fingerprint(ownership)

    def _path(self, run):
        return self._directory(run["authorization_scope"]) / (run["id"] + ".json")

    def _scopes(self):
        try:
            scopes = [DiscoveryScope.from_dict(s) for s in ScopeRecipeStore(self.ctx).snapshot()["scopes"]]
            for scope in scopes:
                scope.validate()
            return scopes
        except Exception:
            # Global recipe text is not part of a limited account's source view.
            raise PermissionError("vsphere:saved_scope_unavailable") from None

    def _scope_guard(self, scope):
        if not any(s.to_dict() == scope.to_dict() for s in self._scopes()):
            raise PermissionError("vsphere:scope_revoked")

    def _target(self, target_id, action, actor=None):
        target = persisted_target(self.ctx.inventory, target_id, require_scope=True)
        authorize(self.ctx, action, actor=actor, target=target)
        return target

    def _check(self, run, action, actor=None):
        target = self._target(run["target_id"], action, actor)
        # Check generations even in development, where authorize_artifact is a no-op.
        if target_scope(target) != run["authorization_scope"]:
            raise PermissionError("vsphere:source_ownership_changed")
        authorize_artifact(self.ctx, run["authorization_scope"], action)
        if fingerprint(_configuration(target)) != run["source_configuration_sha256"]:
            raise PermissionError("vsphere:source_configuration_changed")
        current = {fingerprint(s.to_dict()) for s in self._scopes()}
        if not run["scope_grants"] or not set(run["scope_grants"]) <= current:
            raise PermissionError("vsphere:scope_revoked")

    @staticmethod
    def _public(run, *, observations=True):
        result = {key: deepcopy(run[key]) for key in PUBLIC_FIELDS}
        if observations:
            result["observations"] = deepcopy(run["observations"])
        return result

    def _save(self, run, guard, actor):
        def check():
            self._check(run, "discover", actor)
            self.ctx.killswitch.guard("discovery.vsphere.collect", actor)
            if guard is not None:
                guard()
        check()
        self.ctx.store.write_json(self._path(run), run)
        check()

    @operation("discover")
    def collect(self, target_id: str, actor: str) -> dict:
        """Synchronous, bounded inventory collection. No probes, reconciliation or acceptance."""
        target = self._target(target_id, "discover", actor)
        self.ctx.killswitch.guard("discovery.vsphere.collect", actor)
        scopes = self._scopes()
        if not scopes:
            raise PermissionError("vsphere:no_saved_scope")
        principal = current_principal()
        run = {"version": 1, "id": "vsphere-" + uuid4().hex, "source": "vsphere", "target_id": target.id,
               "authorization_scope": target_scope(target),
               "source_configuration_sha256": fingerprint(_configuration(target)),
               "scope_grants": [fingerprint(s.to_dict()) for s in scopes],
               "requested_by": actor, "requested_principal": None,
               "started_at": utcnow(), "finished_at": None, "status": "running",
               "collection_started": False, "complete": False, "observation_count": 0,
               "observations": [], "error": None}
        if principal is not None:
            run["requested_principal"] = {key: value for key, value in principal.evidence().items()
                                          if key in {"kind", "iss", "sub", "name", "roles", "via", "verified"}}
        guard = None
        saved = False
        try:
            try:
                guard = vsphere.source_guard(self.ctx, target, scopes, actor, self._scope_guard)
                saved = True
                self._save(run, guard, actor)
                # Missing credentials are a local failure, before client creation.
                # The client resolves the same pinned reference again at login.
                guard.credentials()
                run["collection_started"] = True
                self._save(run, guard, actor)
                assets = vsphere.collect(self.ctx, target, scopes, actor, self._scope_guard, access=guard)
                run.update(status="finished", complete=True, observations=[a.to_dict() for a in assets],
                           observation_count=len(assets))
            except (PermissionError, KillSwitchEngaged):
                raise
            except Exception as exc:
                code = str(exc) if isinstance(exc, VsphereError) and str(exc) in ERRORS else "vsphere:collection_failed"
                run.update(status="failed", error=code, complete=False, observations=[], observation_count=0)
            run["finished_at"] = utcnow()
            saved = True
            self._save(run, guard, actor)
            self._audit(run)
            self._check(run, "discover", actor)
            self.ctx.killswitch.guard("discovery.vsphere.collect", actor)
            if guard is not None:
                guard()
            return self._public(run)
        except (PermissionError, KillSwitchEngaged) as exc:
            if saved:
                # A stop updates only this run's original ownership and fixed
                # diagnostics. Never publish collected metadata under a revoked grant.
                self._stop(run)
            if isinstance(exc, KillSwitchEngaged):
                raise KillSwitchEngaged("vsphere:collection_stopped") from None
            raise PermissionError("vsphere:collection_not_authorized") from None
        except Exception:
            if saved:
                self._stop(run)
            raise VsphereError("vsphere:publication_failed") from None

    def _stop(self, run):
        run.update(status="stopped", error="vsphere:collection_stopped", complete=False,
                   finished_at=utcnow(), observations=[], observation_count=0)
        try:
            self.ctx.store.write_json(self._path(run), run)
        except Exception:
            # Storage failure still denies the response; never log raw sink errors.
            pass
        try:
            self._audit(run)
        except Exception:
            pass

    def _audit(self, run):
        self.ctx.audit.append("discovery.vsphere.run", run["requested_by"],
                              {"run_id": run["id"], "authorization_scope": run["authorization_scope"],
                               "status": run["status"], "complete": run["complete"],
                               "collection_started": run["collection_started"],
                               "observation_count": run["observation_count"], "error": run["error"],
                               "auto_accepted": 0}, subject=run["target_id"])

    def runs(self, target_id: str, *, limit: int = 20) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        target = self._target(target_id, "read")
        ownership = target_scope(target)
        visible = []
        for path in self.ctx.store.list_json(self._directory(ownership)):
            run = self.ctx.store.read_json(path)
            if not self._belongs(run, target_id, ownership):
                continue
            try:
                self._check(run, "read")
            except PermissionError:
                continue
            # Keep only bounded summaries in memory, never every historical
            # observation set. Filter ownership before selecting the latest rows.
            visible.append({k: v for k, v in run.items() if k != "observations"})
            visible.sort(key=lambda r: (r["started_at"], r["id"]), reverse=True)
            del visible[limit:]
        # A revocation while loading cannot leave already-selected rows visible.
        for run in visible:
            self._check(run, "read")
        self._same_reader(target)
        return [self._public(run, observations=False) for run in visible]

    def get(self, target_id: str, run_id: str) -> dict:
        target = self._target(target_id, "read")
        if not RUN_ID.fullmatch(run_id):
            raise KeyError("unknown vSphere run")
        ownership = target_scope(target)
        run = self.ctx.store.read_json(self._directory(ownership) / (run_id + ".json"))
        if not self._belongs(run, target_id, ownership):
            raise KeyError("unknown vSphere run")
        self._check(run, "read")
        result = self._public(run)
        self._check(run, "read")
        self._same_reader(target)
        return result

    @staticmethod
    def _belongs(run, target_id, ownership):
        return (isinstance(run, dict) and run.get("version") == 1 and run.get("source") == "vsphere"
                and run.get("target_id") == target_id and run.get("authorization_scope") == ownership)

    def _same_reader(self, target):
        current = self._target(target.id, "read")
        if target_scope(current) != target_scope(target):
            raise PermissionError("vsphere:source_ownership_changed")
