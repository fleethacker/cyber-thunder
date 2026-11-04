"""API test harness: a real AppContext in a temp state dir, with small fakes for the services that are
built elsewhere (scanner, engine, explain, ingest, reports, demo) and a fake adapter on a fixture
transport. Nothing here touches a network, a live host or the local model server."""
from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from cyberthunder.adapters.base import Adapter, AdapterRegistry, AssetFacts, Collected, make_finding
from cyberthunder.control.approvals import ProposalState
from cyberthunder.explain.service import Explanation, ExplainService
from cyberthunder.findings.schema import utcnow, summarize
from cyberthunder.remediation.engine import RemediationEngine
from cyberthunder.remediation.library import FixEntry, FixLibrary
from cyberthunder.remediation.models import ApplyResult, BeforeState, HealthResult, RollbackResult, VerifyResult
from cyberthunder.scan import ScanRun, Scanner, TargetScanResult

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "api"
ACTOR = {"X-Actor": "ITC Rivera"}

SSH_ROOT = "RHEL-09-255045"      # sshd must not permit root login
SSH_FIX = "test:sshd_disable_root_login"


class FakeLinux(Adapter):
    asset_type = "linux"
    display_name = "Fake Linux"
    transports = ("fixture",)

    def discover(self, target, transport):
        host = transport.check_output("hostname").strip()
        osr = transport.read_file("/etc/os-release").decode("utf-8")
        return AssetFacts(hostname=host, os_name="Rocky Linux" if "Rocky" in osr else None, os_version="9.4",
                          kernel=transport.check_output("uname -r").strip())

    def collect(self, target, transport, workdir, *, modules=("check", "hunt", "cve"), rule_filter=None):
        return Collected(target_id=target.id, asset_type=self.asset_type, workdir=str(workdir),
                         modules=list(modules), rule_filter=rule_filter)

    def check(self, target, collected):
        return [
            make_finding(target=target, source="openscap", rule_id="SV-257985r925717_rule", rule_version=SSH_ROOT,
                         title="RHEL 9 must not permit direct logons to the root account using SSH",
                         severity="medium", references=["CCI-000770"], evidence="PermitRootLogin yes"),
            make_finding(target=target, source="openscap", rule_id="xccdf_test_rule_banner",
                         title="Login banner configured", severity="low", status="not_a_finding",
                         references=["CCI-000048"]),
        ]

    def hunt(self, target, collected):
        return [make_finding(target=target, source="hunt", rule_id="hunt:linux:cron_persistence",
                             title="Unexpected root cron job pulls a script from an unknown address",
                             severity="high", references=["T1053.003"],
                             description="Scheduled task persistence (ATT&CK T1053.003).")]

    def fixes(self):
        return [FixEntry(fix_ref=SSH_FIX, title="Disable SSH root login", asset_type="linux",
                         applies_to=[SSH_ROOT], kind="script",
                         payload="sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                         restarts_services=["sshd"], before_state={"files": ["/etc/ssh/sshd_config"]},
                         verify={"rule_ids": [SSH_ROOT]}, citations=[SSH_ROOT, "CCI-000770"], source="ssg")]

    def capture_before_state(self, target, transport, fix, finding, dest):
        return BeforeState(target_id=target.id, fix_ref=fix.fix_ref, dir=str(dest))

    def apply(self, target, transport, fix, finding, before):
        return ApplyResult(ok=True, output="simulated")

    def verify(self, target, transport, fix, finding):
        return VerifyResult(ok=True, rule_passed=True, health=HealthResult(ok=True))

    def health_check(self, target, transport):
        return HealthResult(ok=True)

    def rollback(self, target, transport, fix, before):
        return RollbackResult(ok=True)


class FakeScanner(Scanner):
    """Collect + detect through the fake adapter; persists runs and findings exactly like the real one."""

    def start(self, target_ids=None, *, modules=None, rule_filter=None, trigger="manual", requested_by="operator",
              background=True):
        ids = list(target_ids) if target_ids else [t.id for t in self.ctx.inventory.all() if t.in_scope]
        run = ScanRun(id=self.ctx.store.new_id("scan-"), targets=ids, modules=list(modules or ["check", "hunt", "cve"]),
                      rule_filter=rule_filter, trigger=trigger, requested_by=requested_by, status="running",
                      results={i: TargetScanResult(target_id=i) for i in ids})
        self.ctx.store.save_scan_run(run.to_dict())
        self.ctx.audit.append("scan.start", requested_by, {"scan_id": run.id, "targets": ids}, subject=run.id)
        if background:
            threading.Thread(target=self.run, args=(run,), daemon=True).start()
        else:
            self.run(run)
        return run

    def run(self, run):
        time.sleep(0.05)
        found = []
        for tid in run.targets:
            t = self.ctx.inventory.assert_in_scope(tid)
            adapter = self.ctx.adapter_for(t)
            col = adapter.collect(t, None, self.ctx.store.scan_dir(run.id) / "raw", modules=run.modules)
            fs = adapter.run_detection(t, col)
            for f in fs:
                f.scan_id = run.id
            found.extend(fs)
            run.results[tid] = TargetScanResult(target_id=tid, status="done", findings=len(fs),
                                                open=sum(1 for f in fs if f.is_open))
        self.ctx.store.save_findings(run.id, found)
        run.status, run.finished_at = "done", utcnow()
        run.findings_count, run.summary = len(found), summarize(found)
        self.ctx.store.save_scan_run(run.to_dict())
        self.ctx.audit.append("scan.finish", "agent", {"scan_id": run.id, "findings": len(found)}, subject=run.id)
        return run


class FakeEngine(RemediationEngine):
    """Gate edges only; the fake adapter has nothing to change."""

    def propose(self, finding, *, actor="agent", fix=None):
        fix = fix or self.ctx.library.resolve(finding)
        if fix is None:
            return None
        return self.ctx.gate.propose(actor=actor, finding_id=finding.id, host=finding.host, title=fix.title,
                                     fix_ref=fix.fix_ref, fix_preview=fix.preview_text(),
                                     rollback_plan=fix.rollback_plan_text(), risk="test risk",
                                     citations=fix.citations)

    def execute(self, proposal_id, *, actor, simulate_verify_fail=False):
        g = self.ctx.gate
        g.start_apply(proposal_id, actor)
        time.sleep(0.05)
        g.applied(proposal_id)
        if simulate_verify_fail:
            g.failed(proposal_id, note="verification failed (simulated)")
            return g.rolled_back(proposal_id, note="automatic rollback")
        return g.verified(proposal_id)

    def rollback(self, proposal_id, *, actor):
        return self.ctx.gate.rolled_back(proposal_id, actor, note="manual rollback")

    def diff(self, proposal_id):
        return {"before": {"PermitRootLogin": "yes"}, "after": {"PermitRootLogin": "no"},
                "files": [{"path": "/etc/ssh/sshd_config", "before": "PermitRootLogin yes", "after": "PermitRootLogin no"}]}


class FakeExplain(ExplainService):
    def explain(self, finding, *, force=False):
        if not force and (e := self.get(finding.id)):
            return e
        e = Explanation(finding_id=finding.id, risk=f"{finding.title}.", impact="Remote root access.",
                        plan="Apply the library fix after approval.", citations=finding.citations[:2], fallback=True)
        self.ctx.store.save_explanation(finding.id, e.to_dict())
        self.ctx.audit.append("explain.generate", "agent", {"finding": finding.id}, subject=finding.id)
        return e

    def precompute(self, findings, *, background=True):
        fl = list(findings)
        for f in fl:
            self.explain(f)
        return len(fl)

    def status(self):
        return {"backend": "template", "model": None, "available": True, "detail": "test", "queue": 0}


class SkeletonScanner(Scanner):
    def start(self, *a, **k):
        raise NotImplementedError("scanner not built yet")


class SkeletonEngine(RemediationEngine):
    def propose(self, *a, **k):
        raise NotImplementedError

    def execute(self, *a, **k):
        raise NotImplementedError

    def rollback(self, *a, **k):
        raise NotImplementedError

    def diff(self, *a, **k):
        raise NotImplementedError


class SkeletonExplain(ExplainService):
    def explain(self, *a, **k):
        raise NotImplementedError

    def precompute(self, *a, **k):
        raise NotImplementedError

    def status(self):
        raise NotImplementedError


@pytest.fixture
def ctx(state_dir, monkeypatch):
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    monkeypatch.setenv("CT_LLM_BACKEND", "template")
    from cyberthunder.api import util
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext

    monkeypatch.setattr(util, "demo_module", lambda: None)
    c = AppContext(Settings.from_env(state_dir=state_dir))
    reg = AdapterRegistry()
    reg.register(FakeLinux)
    c.adapters = reg
    c.library = FixLibrary.from_adapters(reg)
    c.scanner = FakeScanner(c)
    c.engine = FakeEngine(c)
    c.explain = FakeExplain(c)
    c.ingest = None
    c.reports = None
    yield c
    util.wait_background()
    v = c.audit.verify()
    assert v.ok, str(v)


@pytest.fixture
def client(ctx):
    from fastapi.testclient import TestClient
    from cyberthunder.api.app import create_app

    with TestClient(create_app(ctx)) as tc:
        yield tc


def add_target(client, tid="web01", **extra):
    body = {"id": tid, "name": tid, "asset_type": "linux", "transport": "fixture",
            "options": {"fixture_dir": str(FIXTURES / "host1")}, **extra}
    r = client.post("/api/v1/targets", json=body, headers=ACTOR)
    assert r.status_code == 201, r.text
    return r.json()


def scan_and_wait(client, timeout=5.0, **body):
    r = client.post("/api/v1/scans", json=body, headers=ACTOR)
    assert r.status_code == 202, r.text
    sid = r.json()["id"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = client.get(f"/api/v1/scans/{sid}").json()
        if run["status"] == "done":
            return run
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def wait_state(client, pid, states, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        p = client.get(f"/api/v1/proposals/{pid}").json()
        if p["state"] in states:
            return p
        time.sleep(0.05)
    raise AssertionError(f"proposal {pid} never reached {states}")


@pytest.fixture
def scanned(client):
    """One target, scanned; returns the findings keyed by rule_version or rule_id."""
    add_target(client)
    scan_and_wait(client)
    fs = client.get("/api/v1/findings").json()["findings"]
    return {f["rule_version"] or f["rule_id"]: f for f in fs}


@pytest.fixture
def approved(client, scanned):
    fid = scanned[SSH_ROOT]["id"]
    p = client.post(f"/api/v1/findings/{fid}/propose", headers=ACTOR).json()
    r = client.post(f"/api/v1/proposals/{p['id']}/approve", json={"note": "change window 1400"}, headers=ACTOR)
    assert r.status_code == 200, r.text
    assert r.json()["state"] == ProposalState.APPROVED.value
    return r.json()
