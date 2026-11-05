from __future__ import annotations

from copy import deepcopy
import json
import socket
from types import SimpleNamespace

import pytest

from cyberthunder.audit.chain import AuditLog
from cyberthunder.config import Settings
from cyberthunder.control.approvals import ApprovalGate
from cyberthunder.control.killswitch import KillSwitch
from cyberthunder.findings.schema import Finding, utcnow
from cyberthunder.impact import ImpactService
from cyberthunder.impact.packet import dependency_id, evidence_digest
from cyberthunder.inventory.targets import Inventory, Target
from cyberthunder.remediation.dependencies import target_binding_sha256
from cyberthunder.remediation.engine import RemediationEngine, fix_digest
from cyberthunder.remediation.library import FixEntry, FixLibrary
from cyberthunder.store import StateStore


class Backend:
    name = "test-model"
    model = "astra"

    def __init__(self):
        self.calls = []
        self._observations = {"probes": 0, "response": json.dumps(valid_response())}
        self.available_result = (True, "available")
        self.on_generate = None
        self.on_probe = None

    @property
    def probes(self):
        return self._observations["probes"]

    @property
    def response(self):
        return self._observations["response"]

    @response.setter
    def response(self, value):
        self._observations["response"] = value

    def available(self):
        self._observations["probes"] += 1
        if self.on_probe:
            self.on_probe()
        return self.available_result

    def generate(self, prompt, *, json_mode, timeout):
        self.calls.append((prompt, json_mode, timeout))
        if self.on_generate:
            self.on_generate()
        return self.response


def valid_response():
    edge = {"from": "web.service", "to": "sshd.service", "relation": "requires", "evidence_ids": ["e1"]}
    edge["id"] = dependency_id(edge)
    return {"risk_level": "high", "summary": "Observed service dependents may be interrupted.",
            "evidence_ids": ["e1"], "risks": [{"severity": "high", "summary": "The dependent service may lose access.",
            "evidence_ids": ["e1"], "dependency_refs": [edge]}],
            "unknowns": ["Failover capacity is unverified."], "required_checks": ["Confirm owner recovery access."],
            "rollback_limits": ["Interrupted sessions may not recover."]}


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("impact tests must never use the network")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


@pytest.fixture
def rig(state_dir, monkeypatch):
    # Exercise the planned parent allowlist through both actual StateStore backends.
    # This stays entirely inside the test; production routing is owned by the parent.
    import cyberthunder.state as state
    monkeypatch.setattr(state, "DOCUMENT_AREAS", (*state.DOCUMENT_AREAS, "change_assessments/"))
    settings = Settings.from_env(state_dir=state_dir, llm_backend="template", llm_timeout_s=2,
                                 explain_precompute=False)
    store = StateStore(state_dir)
    audit = AuditLog(store.audit_log, node="test-node")
    kill = KillSwitch(store.root, audit)
    gate = ApprovalGate(store.proposals, audit, kill)
    inventory = Inventory.load(store.targets)
    target = Target(id="host1", name="Host", asset_type="linux", transport="ssh")
    inventory.add(target)
    inventory.save()
    fix = FixEntry(fix_ref="test:fix", title="Declared SSH change", asset_type="linux", applies_to=["rule1"],
                   payload="bound payload", disruption="high", restarts_services=["sshd"],
                   before_state={"files": ["/etc/ssh/sshd_config"]})
    finding = Finding(host=target.id, source="test", rule_id="rule1", title="Finding", severity="high",
                      status="open", asset_type="linux", fix_ref=fix.fix_ref)
    current = [finding]
    monkeypatch.setattr(store, "current_findings", lambda: deepcopy(current))
    library = FixLibrary([fix])
    backend = Backend()
    ctx = SimpleNamespace(settings=settings, store=store, audit=audit, killswitch=kill,
                          gate=gate, inventory=inventory, library=library, explain=SimpleNamespace(backend=backend))
    ctx.engine = RemediationEngine(ctx)
    proposal = gate.propose(actor="Joshua", finding_id=finding.id, host=target.id, title="Fix",
                            fix_ref=fix.fix_ref, fix_preview=fix.preview_text(), rollback_plan="Restore",
                            risk="Declared disruption", meta={"fix_sha256": fix_digest(fix)})
    packet = {"version": 1, "generated_at": utcnow(), "proposal_id": proposal.id, "target_id": target.id,
              "target_binding_sha256": target_binding_sha256(target), "fix_sha256": fix_digest(fix),
              "mode": "live", "complete": False,
              "evidence": [{"id": "e1", "kind": "systemd", "source": "live:systemd", "observed_at": utcnow(),
                            "subject": "sshd.service", "facts": {"unit": "sshd.service", "active_state": "active",
                            "RequiredBy": ["web.service"]}}],
              "dependencies": valid_response()["risks"][0]["dependency_refs"],
              "risks": [{"id": "dependents-1", "severity": "high", "summary": "Dependent services may be disrupted.",
                         "evidence_ids": ["e1"], "deterministic": True}],
              "unknowns": ["Transitive dependencies remain unknown."], "required_checks": ["Confirm owner maintenance window."],
              "rollback_limits": ["Interrupted work cannot be restored."]}
    calls = []

    def collect(engine, pid, *, actor, live):
        calls.append((engine, pid, actor, live))
        result = deepcopy(packet)
        result["mode"] = "live" if live else "stored"
        result["evidence_sha256"] = evidence_digest(result)
        return result

    monkeypatch.setattr("cyberthunder.impact.service.collect_dependencies", collect)
    service = ImpactService(ctx)
    yield SimpleNamespace(ctx=ctx, service=service, packet=packet, backend=backend, collect=collect,
                          calls=calls, proposal=proposal, fix=fix, target=target, current=current)
    assert audit.verify().ok
    store.close()
