import os

import pytest

from cyberthunder.explain.service import ExplainService

from .helpers import FakeBackend, canned, cron_finding, make_ctx, ssh_root_finding


@pytest.fixture
def ctx(state_dir):
    return make_ctx(state_dir)


def _events(ctx, action="explain.generate"):
    return [r for r in ctx.audit.records() if r["action"] == action]


def test_valid_model_answer(ctx):
    fb = FakeBackend([canned("valid")])
    ctx.explain.backend = fb
    exp = ctx.explain.explain(ssh_root_finding())
    assert exp.validated and not exp.fallback and exp.backend == "fake" and exp.model == "fake-model"
    assert exp.attempts == 1 and "ssg:sshd_disable_root_login" in exp.citations
    assert "Disable SSH root login" in fb.prompts[0]
    ev = _events(ctx)
    assert len(ev) == 1
    d = ev[0]["details"]
    assert d["backend"] == "fake" and d["validated"] is True and d["fallback"] is False and d["dropped"] == 0
    assert "latency_s" in d and d["model"] == "fake-model"
    assert ctx.audit.verify().ok


def test_invented_citation_dropped_and_recorded(ctx):
    ctx.explain.backend = FakeBackend([canned("invented")])
    exp = ctx.explain.explain(ssh_root_finding())
    assert exp.validated and exp.citations == ["RHEL-09-255045"]
    assert set(exp.dropped_citations) == {"CVE-2099-0001", "RHEL-09-999999"}
    assert _events(ctx)[0]["details"]["dropped"] == 2


def test_invalid_then_valid_on_retry(ctx):
    fb = FakeBackend([canned("invalid"), canned("valid")])
    ctx.explain.backend = fb
    exp = ctx.explain.explain(ssh_root_finding())
    assert exp.validated and not exp.fallback and exp.attempts == 2
    assert "previous answer was rejected" in fb.prompts[1]


def test_always_invalid_falls_back_to_template(ctx):
    ctx.explain.backend = FakeBackend([canned("invalid")])
    f = ssh_root_finding()
    exp = ctx.explain.explain(f)
    assert exp.fallback and not exp.validated and exp.attempts == 2 and exp.backend == "template"
    assert exp.citations == f.citations[:3]
    assert "CAT II" in exp.risk and "web01" in exp.risk
    assert "Disable SSH root login" in exp.plan and "approv" in exp.plan
    ev = _events(ctx)[0]
    assert ev["outcome"] == "fallback" and ev["details"]["reason"] == "model output failed validation"


def test_unavailable_backend_uses_template(ctx):
    fb = FakeBackend([canned("valid")], available=False)
    ctx.explain.backend = fb
    exp = ctx.explain.explain(cron_finding())
    assert exp.fallback and exp.validated and exp.attempts == 1 and fb.prompts == []
    assert exp.citations == ["hunt:linux:cron_persistence", "T1053.003"]
    assert "a vetted fix" in exp.plan and "CAT I" in exp.risk
    assert _events(ctx)[0]["details"]["reason"] == "fake down"


def test_backend_exception_is_contained(ctx):
    class Boom(FakeBackend):
        def generate(self, *a, **k):
            raise RuntimeError("socket closed")
    ctx.explain.backend = Boom([])
    exp = ctx.explain.explain(ssh_root_finding())
    assert exp.fallback and not exp.validated


def test_template_backend_configured(ctx):
    exp = ctx.explain.explain(ssh_root_finding())
    assert exp.backend == "template" and exp.fallback and exp.validated
    assert ctx.explain.status()["backend"] == "template"


def test_cache_hit_and_force(ctx):
    fb = FakeBackend([canned("valid")])
    ctx.explain.backend = fb
    f = ssh_root_finding()
    first = ctx.explain.explain(f)
    again = ctx.explain.explain(f)
    assert len(fb.prompts) == 1 and again.generated_at == first.generated_at
    assert ctx.explain.get(f.id).risk == first.risk
    # a fresh service reads the same on-disk cache
    assert ExplainService(ctx).explain(f).risk == first.risk
    ctx.explain.explain(f, force=True)
    assert len(fb.prompts) == 2
    assert len(_events(ctx)) == 2


def test_status_shape(ctx):
    ctx.explain.backend = FakeBackend([canned("valid")])
    s = ctx.explain.status()
    assert set(s) >= {"backend", "model", "available", "detail", "queue", "fallback_model"}
    assert s["backend"] == "fake" and s["available"] is True and s["queue"] == 0
    assert ctx.status()["llm"]["backend"] == "fake"


def test_precompute_order_and_dedupe(ctx):
    order = []
    fb = FakeBackend([canned("valid")])
    ctx.explain.backend = fb
    real = ctx.explain.explain

    def tracking(f, force=False):
        order.append(f.id)
        return real(f, force=force)
    ctx.explain.explain = tracking

    low = ssh_root_finding(rule_id="SV-1r1_rule", severity="low")
    closed_high = ssh_root_finding(rule_id="SV-2r1_rule", severity="high", status="not_a_finding")
    med = ssh_root_finding(rule_id="SV-3r1_rule", severity="medium")
    high = cron_finding()
    cached = ssh_root_finding(rule_id="SV-4r1_rule", severity="high")
    real(cached)
    todo = ctx.explain.plan_precompute([low, closed_high, med, high, med, cached, low])
    assert [f.id for f in todo] == [high.id, med.id, low.id, closed_high.id]

    n = ctx.explain.precompute([low, closed_high, med, high, med, cached, low], background=False)
    assert n == 4 and order == [high.id, med.id, low.id, closed_high.id]
    assert ctx.explain.precompute([low, med]) == 0      # everything cached now


def test_precompute_background_worker(ctx):
    ctx.explain.backend = FakeBackend([canned("valid")])
    fs = [ssh_root_finding(rule_id=f"SV-{i}r1_rule") for i in range(5)]
    try:
        n = ctx.explain.precompute(fs + fs, background=True)
        assert n == 5
        assert ctx.explain.wait(timeout=10)
        assert ctx.explain.worker.done == 5
        assert ctx.explain.status()["queue"] == 0
        assert all(ctx.explain.get(f.id) for f in fs)
    finally:
        ctx.explain.shutdown(timeout=5)
    assert not ctx.explain.worker.alive
    assert len(_events(ctx)) == 5 and ctx.audit.verify().ok


@pytest.mark.skipif(os.environ.get("CT_TEST_LLM") != "1", reason="set CT_TEST_LLM=1 to test against a local model server")
def test_real_local_model(state_dir):
    ctx = make_ctx(state_dir, llm_backend=os.environ.get("CT_LLM_BACKEND", "ollama"))
    ok, detail = ctx.explain.status()["available"], ctx.explain.status()["detail"]
    if not ok:
        pytest.skip(detail)
    exp = ctx.explain.explain(ssh_root_finding())
    assert exp.citations and exp.risk
    assert ctx.audit.verify().ok
