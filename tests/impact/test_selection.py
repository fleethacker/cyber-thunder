import json

import pytest

from cyberthunder.explain import backends
from cyberthunder.impact.selection import generate_selected, isolated_backend, selected_identity

from .conftest import Backend, valid_response


@pytest.mark.parametrize("selected", ["primary", "fallback"])
def test_builtin_private_factory_records_actual_request_model_despite_shared_probe(rig, monkeypatch, selected):
    rig.ctx.settings.llm_backend = "ollama"
    rig.ctx.settings.llm_url = "http://127.0.0.1:11434"
    rig.ctx.settings.llm_model = "primary"
    rig.ctx.settings.llm_fallback_model = "fallback"
    shared = backends.make_backend(rig.ctx.settings)
    rig.ctx.explain.backend = shared
    actual = []

    def http(method, url, body, timeout, **kwargs):
        if method == "GET":
            return {"models": [{"name": selected}]}
        # This is the actual built-in request body, after request construction.
        # Simulate a concurrent explain probe mutating the shared backend.
        shared.model = "concurrent-other-selection"
        actual.append(body["model"])
        return {"response": json.dumps(valid_response())}

    monkeypatch.setattr(backends, "_http_json", http)
    receipt = rig.service.assess(rig.proposal.id, actor="Joshua")
    assert actual == [selected]
    assert receipt["model"]["name"] == selected
    assert receipt["model"]["used"] and receipt["model"]["validated"]
    assert rig.service.readiness(rig.proposal.id, receipt["id"])["ready"]


def test_private_selection_change_inside_generation_is_not_mislabeled(rig):
    class ChangingBackend(Backend):
        configured_model = "primary"
        fallback_model = "fallback"
        model = "primary"

        def generate(self, prompt, *, json_mode, timeout):
            self.model = "fallback"
            return super().generate(prompt, json_mode=json_mode, timeout=timeout)

    source = ChangingBackend()
    rig.ctx.explain.backend = source
    receipt = rig.service.assess(rig.proposal.id, actor="Joshua")
    assert source.model == "primary"
    assert not receipt["model"]["used"] and not receipt["model"]["validated"]
    assert receipt["model"]["name"] is None
    assert receipt["model"]["fallback_reason"] == "model_selection_changed"


def test_request_boundary_refuses_changed_selection_before_backend_call():
    backend = Backend()
    private = isolated_backend(backend)
    identity = selected_identity(private)
    private.model = "changed"
    assert generate_selected(private, identity, "prompt", 1) == (None, False)
    assert not backend.calls


def test_review_repro_shared_generate_closure_cannot_claim_primary_provenance(rig, monkeypatch):
    rig.backend.configured_model = "primary"
    rig.backend.fallback_model = "fallback"
    rig.backend.model = "primary"
    actual = []

    def generate(prompt, *, json_mode, timeout):
        rig.backend.model = "fallback"
        actual.append(rig.backend.model)
        return json.dumps(valid_response())

    monkeypatch.setattr(rig.backend, "generate", generate)
    receipt = rig.service.assess(rig.proposal.id, actor="Joshua")
    assert not actual
    assert receipt["model"]["name"] is None and not receipt["model"]["used"]
    assert receipt["model"]["fallback_reason"] == "backend_not_isolatable"
