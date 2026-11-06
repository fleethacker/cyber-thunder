"""AppContext wires the kernel together once; CLI and API both use it.

Everything that touches an asset goes through: inventory (scope) -> transport -> adapter, orchestrated by
Scanner (read-only) or RemediationEngine (state-changing, approval-gated, kill-switch-guarded, audited).
"""
from __future__ import annotations

import logging

from cyberthunder.audit.chain import AuditLog
from cyberthunder.config import Settings
from cyberthunder.control.approvals import ApprovalGate
from cyberthunder.control.killswitch import KillSwitch
from cyberthunder.control.identity import normalize_actor, require_human
from cyberthunder.control.policy import AutomationPolicy, load_policy, save_policy, signer_problem
from cyberthunder.inventory.targets import Inventory, Target
from cyberthunder.remediation.library import FixLibrary
from cyberthunder.store import StateStore
from cyberthunder.transport.base import Transport, make_transport

log = logging.getLogger(__name__)


class AppContext:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings.from_env()
        # Validate explicit credential configuration before creating any state.
        self._credential_resolver()
        from cyberthunder.security.step_up import FreshnessClock
        self.step_up_clock = FreshnessClock()
        # Trust configuration is mandatory when explicitly configured. Validate it
        # before constructing services or creating state; optional wiring cannot
        # swallow a bad key/policy file and silently disable authenticity checks.
        self.content_signature_config = None
        if self.settings.content_trust_config:
            from cyberthunder.ingest.content.signatures import load_config
            self.content_signature_config = load_config(self.settings.content_trust_config)
        self.store = StateStore(self.settings.state_dir, backend=self.settings.state_backend)
        self.audit = AuditLog(self.store.audit_log, node=self.settings.node)
        self.killswitch = KillSwitch(self.store.root, self.audit)
        self.gate = ApprovalGate(self.store.proposals, self.audit, self.killswitch, policy_path=self.store.policy)
        self.inventory = Inventory.load(self.store.targets)
        from cyberthunder.security.resources import capture
        def resource_scope(target_id):
            try:
                return capture(self, [target_id])[0]
            except (KeyError, PermissionError, OSError, ValueError):
                if self.settings.auth_mode != "dev":
                    raise
                return None
        self.gate.resource_scope = resource_scope
        from cyberthunder.security.resources import check_record
        self.gate.artifact_authorizer = lambda record, action: check_record(self, record, action)
        if self.settings.auth_mode != "dev":
            from cyberthunder.control.access import AccessPolicy
            self.access = AccessPolicy(self.store.root / "auth" / "access.json")
            self.gate.authorizer = self.authorize
            self.killswitch.authorizer = self.authorize
        from cyberthunder.adapters import load_all
        self.adapters = load_all()
        self.library = FixLibrary.from_adapters(self.adapters)
        self.policy: AutomationPolicy = load_policy(self.store.policy)
        # services; each module may still be under construction, so wire lazily and tolerate absence
        from cyberthunder.scan import Scanner
        from cyberthunder.remediation.engine import RemediationEngine
        from cyberthunder.explain.service import ExplainService
        self.scanner = Scanner(self)
        self.engine = RemediationEngine(self)
        self.explain = ExplainService(self)
        self.impact = self._optional("cyberthunder.impact.service", "ImpactService")
        from cyberthunder.control.assessment import bind_assessment
        self.gate.assessment_validator = lambda pid, aid, note: bind_assessment(self, pid, aid, note)
        self.ingest = self._optional("cyberthunder.ingest.service", "IngestService")
        if self.ingest is not None:
            self.ingest.outbox.ctx = self
        self.reports = self._optional("cyberthunder.report.service", "ReportService")
        self.discovery = self._optional("cyberthunder.discovery.service", "DiscoveryService")
        self.vulnerabilities = self._optional("cyberthunder.vulnerabilities.service", "VulnerabilityService")
        self.cluster = self._optional("cyberthunder.cluster.service", "ClusterBaselineService")

    def _optional(self, module: str, cls: str):
        try:
            import importlib
            return getattr(importlib.import_module(module), cls)(self)
        except ModuleNotFoundError:
            return None
        except Exception as e:  # noqa: BLE001
            log.warning("%s.%s unavailable: %s", module, cls, e)
            return None

    # -- helpers ---------------------------------------------------------------------
    def authorize(self, action: str, *, actor: str | None = None, target=None, step_up_continuation=None):
        if self.settings.auth_mode == "dev":
            if step_up_continuation is not None:
                raise PermissionError("transfer authentication mode changed")
            return None
        from cyberthunder.control.principal import current_principal, require_current
        from cyberthunder.inventory.host import persisted_target
        from cyberthunder.security.resources import target_scope
        from cyberthunder.security.step_up import StepUpRequired, require_step_up, freshness_clock
        principal = current_principal()
        try:
            principal = require_current(action, actor)
            if isinstance(target, str):
                resource = persisted_target(self.inventory, target,
                    require_scope=action in {"scan", "discover", "plan", "apply", "rollback", "verify"})
            elif target is not None and action != "admin":
                resource = persisted_target(self.inventory, target.id,
                    require_scope=action in {"scan", "discover", "plan", "apply", "rollback", "verify"})
                # Authorize the ownership snapshot the caller will actually use.
                # An identifier may now name a different account's target.
                if target_scope(target) != target_scope(resource):
                    raise PermissionError("target ownership changed")
            else:
                resource = target
            self.access.require(principal, action, resource)
            require_step_up(self.settings, principal, action, clock=freshness_clock(self), ctx=self,
                            target=resource, continuation=step_up_continuation)
            return principal
        except StepUpRequired as exc:
            self.audit.append("authorization.denied", principal.actor,
                {"action": action, "target": getattr(target, "id", target), "step_up": exc.challenge()},
                outcome="rejected")
            raise
        except (PermissionError, KeyError):
            self.audit.append("authorization.denied", principal.actor if principal else "unverified",
                {"action": action, "target": getattr(target, "id", target), "reason": "permission denied"},
                outcome="rejected")
            raise PermissionError("this account is not authorized for the requested operation and resource") from None

    def may_access(self, target, action: str = "read") -> bool:
        if self.settings.auth_mode == "dev":
            return True
        from cyberthunder.control.principal import require_current
        from cyberthunder.inventory.host import persisted_target
        from cyberthunder.security.resources import target_scope
        try:
            principal = require_current(action)
            resource = persisted_target(self.inventory, target if isinstance(target, str) else target.id)
            if not isinstance(target, str) and target_scope(target) != target_scope(resource):
                return False
            return self.access.allows(principal, action, resource)
        except (PermissionError, KeyError):
            return False

    def _credential_resolver(self):
        from cyberthunder.security.secret_resolver import load_registry
        return load_registry(self.settings.credential_sources,
                             security_mode=self.settings.security_mode, auth_mode=self.settings.auth_mode)

    def transport_for(self, target: Target) -> Transport:
        resolver = self._credential_resolver()
        registry_state = (self.settings.credential_sources, self.settings.security_mode, self.settings.auth_mode,
                          resolver.fingerprint if resolver else None)

        def registry_guard():
            current = self._credential_resolver()
            if (self.settings.credential_sources, self.settings.security_mode, self.settings.auth_mode,
                    current.fingerprint if current else None) != registry_state:
                raise PermissionError("credential source configuration changed; reconnect using current permissions")

        if self.settings.security_mode == "fleet" and "cpe_alias" in (target.options or {}):
            raise PermissionError("CPE aliases are limited to explicitly configured range validation")
        if self.settings.auth_mode != "dev":
            from cyberthunder.control.principal import current_operation, current_principal
            from cyberthunder.inventory.host import persisted_target
            from cyberthunder.security.credentials import bind_target
            from cyberthunder.security.transport_guard import protect_transport
            action = current_operation()
            if action not in {"scan", "discover", "plan", "apply", "rollback", "verify"}:
                raise PermissionError("target access requires an explicit authorized operation")
            requested = target
            target = persisted_target(self.inventory, requested.id, require_scope=True)
            from cyberthunder.security.resources import target_scope
            if target_scope(requested) != target_scope(target):
                raise PermissionError("target ownership changed; retry using the current inventory")
            principal = self.authorize(action, target=target)
            binding = self.access.credential(principal, action, target)
            selected = bind_target(target, binding)
            kube_binding = None
            if selected.transport == "kubeconfig":
                from cyberthunder.security.kube_credentials import validate_kubeconfig
                kube_binding = validate_kubeconfig(binding)
            evidence = binding.evidence()
            configuration = {k: v for k, v in target.to_dict().items() if k not in {"last_scan", "notes", "added_at"}}

            def guard():
                registry_guard()
                if current_principal() != principal:
                    raise PermissionError("target connection belongs to another authenticated session")
                current = persisted_target(self.inventory, target.id, require_scope=True)
                self.authorize(action, target=current)
                self.killswitch.guard("target.access", principal.actor)
                now = {k: v for k, v in current.to_dict().items() if k not in {"last_scan", "notes", "added_at"}}
                if now != configuration or self.access.credential(principal, action, current).evidence() != evidence:
                    raise PermissionError("target or account authorization changed; reconnect using current permissions")
                if kube_binding is not None:
                    from cyberthunder.security.kube_credentials import guard_kubeconfig
                    guard_kubeconfig(kube_binding)

            guard()
            credential_use = None
            if (resolver is not None and selected.transport in {"ssh", "winrm"}
                    and selected.options.get("credential_source") == "environment"):
                def credential_event(event):
                    # Failures may follow revocation: preserve their attribution
                    # without reauthorizing the failed operation or another user.
                    if current_principal() != principal or not principal.verified:
                        raise PermissionError("credential event belongs to another authenticated session")
                    details = credential_use.event_details(event)
                    self.audit.append(event.action, principal.actor, details, subject=target.id,
                                      outcome="blocked" if event.action == "credential.failed" else "ok")

                credential_use = resolver.bind(binding, principal=principal, target=target, purpose=action,
                                               guard=guard, on_event=credential_event)
            use_evidence = dict(evidence)
            if credential_use is not None:
                use_evidence["credential_source"] = credential_use.backend
                use_evidence["registry_fingerprint"] = resolver.fingerprint
            transport = make_transport(selected, self.settings, guard=guard,
                on_security_event=lambda event: self.record_transport_event(target, event),
                credential_use=credential_use)
            try:
                self.audit.append("credential.use", principal.actor, use_evidence, subject=target.id)
            except BaseException:
                transport.close()
                raise
            if kube_binding is not None:
                transport.account_binding = kube_binding
                transport.account_guard = guard
            def secondary_transport(target_id):
                guard()
                node = persisted_target(self.inventory, target_id, require_scope=True)
                return node, self.transport_for(node)
            transport.secondary_transport = secondary_transport
            return protect_transport(transport, guard, sudo_allowed=binding.sudo)
        return make_transport(target, self.settings,
                              guard=registry_guard,
                              on_security_event=lambda event: self.record_transport_event(target, event))

    def record_transport_event(self, target: Target, event) -> None:
        from cyberthunder.control.principal import current_principal
        from cyberthunder.findings.schema import Finding, Severity, Status, utcnow
        principal = current_principal()
        self.audit.append("transport.security", principal.actor if principal else "transport",
                          {"target": target.id, **event.to_dict()}, subject=target.id,
                          outcome="blocked" if event.severity == "high" else "warning")
        finding = Finding(host=target.id, asset_type=target.asset_type, source="transport", rule_id=event.code,
                          title=event.message, severity=Severity.parse(event.severity), status=Status.OPEN,
                          evidence="Transport identity or connection policy: " + event.message)
        sid = self.store.new_id("trust-")
        self.store.save_scan_run({"id": sid, "trigger": "transport_security", "targets": [target.id],
            "status": "done", "started_at": utcnow(), "coverage_incomplete": True})
        self.store.save_findings(sid, [finding])

    def adapter_for(self, target: Target):
        return self.adapters.get(target.asset_type)

    def save_policy(self, policy: AutomationPolicy, actor: str) -> AutomationPolicy:
        self.authorize("policy", actor=actor)
        if self.settings.auth_mode != "dev" and policy.enabled:
            raise PermissionError("standing approval requires a verifiable policy signature before it can be enabled")
        try:
            actor = require_human(actor)
            why = signer_problem(policy)
            if why:
                raise PermissionError(why)
        except PermissionError as e:
            self.audit.append("policy.rejected", normalize_actor(actor) or "?",
                              {"enabled": policy.enabled, "signed_by": policy.signed_by, "reason": str(e)},
                              outcome="rejected")
            raise
        self.policy = policy
        save_policy(self.store.policy, policy)
        self.audit.append("policy.update", actor, {"enabled": policy.enabled, "signed_by": policy.signed_by,
                                                   "rules": [r.name for r in policy.rules], "version": policy.version})
        return policy

    def save_inventory(self, actor: str, action: str = "inventory.update", details: dict | None = None) -> None:
        self.authorize("admin", actor=actor)
        self.inventory.save()
        self.audit.append(action, actor, details or {"targets": [t.id for t in self.inventory.all()]})

    def status(self) -> dict:
        from cyberthunder import PRODUCT, __version__
        v = self.audit.verify()
        st = {
            "product": PRODUCT, "version": __version__, "node": self.settings.node,
            "kill": self.killswitch.status(),
            "audit": {"count": v.count, "head": v.head, "verified": v.ok, "detail": str(v)},
            "policy": {"enabled": self.policy.enabled, "signed_by": self.policy.signed_by, "rules": len(self.policy.rules)},
            "adapters": self.adapters.types(),
            "targets": len(self.inventory.all()),
            "fixes": len(self.library.all()),
            "demo": self.settings.demo,
        }
        try:
            st["llm"] = self.explain.status()
        except NotImplementedError:
            st["llm"] = {"backend": self.settings.llm_backend, "model": self.settings.llm_model, "available": False, "detail": "not built"}
        return st
