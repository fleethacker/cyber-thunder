from copy import deepcopy
import json

from cyberthunder.impact.input import COVERAGE_UNKNOWN, MAX_PROMPT_BYTES, prepare_model_input
from cyberthunder.impact.packet import dependency_id, fix_allowlist
from cyberthunder.impact.validator import build_prompt, validate_response

from .conftest import valid_response


def large_packet(rig):
    packet = deepcopy(rig.packet)
    packet["evidence"] = []
    packet["dependencies"] = []
    for i in range(1, 61):
        packet["evidence"].append({"id": f"e{i}", "kind": "systemd", "source": "live:systemd",
                                   "observed_at": packet["generated_at"], "subject": f"unit-{i}.service",
                                   "facts": {"unit": f"unit-{i}.service", "RequiredBy": [f"client-{i}.service"]}})
        edge = {"from": f"client-{i}.service", "to": f"unit-{i}.service", "relation": "requires",
                "evidence_ids": [f"e{i}"]}
        edge["id"] = dependency_id(edge)
        packet["dependencies"].append(edge)
    packet["risks"] = [{"id": "critical-60", "severity": "critical", "summary": "A critical dependency needs owner review.",
                        "evidence_ids": ["e60"], "deterministic": True}]
    packet["unknowns"] = [f"Dependency group {i} is unverified." for i in range(40)]
    return packet


def test_large_input_is_bounded_prioritized_and_reference_closed(rig):
    packet = large_packet(rig)
    before = deepcopy(packet)
    fix = fix_allowlist(rig.fix, packet["fix_sha256"])
    view, coverage = prepare_model_input(packet, fix)
    assert coverage["limited"] and coverage["counts"]["evidence"]["total"] == 60
    assert len(build_prompt(view, fix).encode("utf-8")) <= MAX_PROMPT_BYTES
    assert coverage["prompt_bytes"] <= MAX_PROMPT_BYTES
    assert view["evidence"][0]["id"] == "e60" and view["risk_floor"] == "critical"
    assert view["dependencies"]
    ids = {e["id"] for e in view["evidence"]}
    assert all(set(edge["evidence_ids"]) <= ids for edge in view["dependencies"])
    assert packet == before
    assert all("id" not in risk for risk in view["risks"])
    response = valid_response()
    response.update(risk_level="critical", evidence_ids=["e60"], risks=[])
    assert validate_response(json.dumps(response), view)
    response["risk_level"] = "high"
    assert validate_response(json.dumps(response), view) is None
    response.update(risk_level="critical", evidence_ids=[next(e["id"] for e in packet["evidence"] if e["id"] not in ids)])
    assert validate_response(json.dumps(response), view) is None


def test_full_receipt_retains_omitted_facts_and_explicit_coverage_unknown(rig):
    rig.packet.update(large_packet(rig))
    response = valid_response()
    response.update(risk_level="critical", evidence_ids=["e60"], risks=[])
    rig.backend.response = json.dumps(response)
    receipt = rig.service.assess(rig.proposal.id, actor="Joshua")
    assert receipt["model"]["used"] and receipt["model"]["input_coverage"]["limited"]
    assert len(receipt["evidence_packet"]["evidence"]) == 60
    assert len(receipt["evidence_packet"]["dependencies"]) == 60
    assert receipt["assessment"]["risk_level"] == "critical"
    assert COVERAGE_UNKNOWN in receipt["assessment"]["unknowns"]
    assert COVERAGE_UNKNOWN in receipt["evidence_packet"]["unknowns"]
    assert len(rig.backend.calls[0][0].encode("utf-8")) <= MAX_PROMPT_BYTES


def test_oversized_exact_fix_metadata_does_not_reach_model(rig):
    from cyberthunder.remediation.engine import fix_digest
    rig.fix.restarts_services = ["service-" + str(i) + "x" * 230 for i in range(32)]
    with rig.ctx.gate._locked():
        rig.proposal.history[0]["meta"]["fix_sha256"] = fix_digest(rig.fix)
        rig.ctx.gate._save()
    rig.packet["fix_sha256"] = fix_digest(rig.fix)
    receipt = rig.service.assess(rig.proposal.id, actor="Joshua")
    assert not receipt["model"]["used"] and receipt["model"]["fallback_reason"] == "model_input_unavailable"
    assert not rig.backend.calls and not rig.backend.probes
