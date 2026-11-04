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
        self.store = StateStore(self.settings.state_dir)
        self.audit = AuditLog(self.store.audit_log, node=self.settings.node)
        self.killswitch = KillSwitch(self.store.root, self.audit)
        self.gate = ApprovalGate(self.store.proposals, self.audit, self.killswitch, policy_path=self.store.policy)
        self.inventory = Inventory.load(self.store.targets)
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
        self.ingest = self._optional("cyberthunder.ingest.service", "IngestService")
        self.reports = self._optional("cyberthunder.report.service", "ReportService")
        self.discovery = self._optional("cyberthunder.discovery.service", "DiscoveryService")

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
    def transport_for(self, target: Target) -> Transport:
        return make_transport(target, self.settings)

    def adapter_for(self, target: Target):
        return self.adapters.get(target.asset_type)

    def save_policy(self, policy: AutomationPolicy, actor: str) -> AutomationPolicy:
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
