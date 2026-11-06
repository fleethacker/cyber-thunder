"""Session correlation in stored evidence never exposes a current raw session identifier."""
from dataclasses import replace
import json
import time

import pytest

from cyberthunder.audit.chain import AuditLog
from cyberthunder.control.principal import Principal, principal_scope
from cyberthunder.findings.review import principal_from_evidence


def account():
    return Principal("https://identity.example.test", "operator", "Operator", kind="human",
                     roles=("auditor",), session_id="raw-fixture-session-identifier",
                     expires_at=time.time() + 600)


def test_current_session_reference_is_stable_scoped_and_not_an_identity_grant():
    person = account()
    evidence = person.evidence()
    assert evidence["session_id"] is None
    assert person.session_id not in json.dumps(evidence)
    assert evidence["session_fingerprint"].startswith("sha256:")
    assert person.evidence() == evidence
    for change in ({"issuer": person.issuer + "/second"}, {"subject": "other"}, {"session_id": "different"}):
        assert replace(person, **change).evidence()["session_fingerprint"] != evidence["session_fingerprint"]
    assert replace(person, session_id=None).evidence()["session_fingerprint"] is None
    recorded = principal_from_evidence(person.actor, evidence, human=True)
    assert recorded.actor == person.actor and recorded.session_id is None


def test_audit_correlation_is_hash_covered_without_raw_session_material(state_dir):
    person = account()
    log = AuditLog(state_dir / "session-audit.jsonl", node="fixture")
    with principal_scope(person):
        first = log.append("fixture.first", person.actor)
        second = log.append("fixture.second", person.actor)
    assert log.verify().ok
    assert first["principal"]["session_fingerprint"] == second["principal"]["session_fingerprint"]
    assert person.session_id not in log.path.read_text(encoding="utf-8")
    rows = list(log.records())
    rows[0]["principal"]["session_fingerprint"] = "sha256:" + "0" * 64
    log.path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    assert not log.verify().ok


def test_legacy_recorded_attribution_is_accepted_without_rewriting_it():
    person = account()
    legacy = person.evidence()
    legacy.pop("session_fingerprint")
    legacy["session_id"] = "legacy-session-metadata"
    before = json.dumps(legacy, sort_keys=True)
    assert principal_from_evidence(person.actor, legacy).actor == person.actor
    assert json.dumps(legacy, sort_keys=True) == before


@pytest.mark.parametrize("reference", ["raw", "sha256:" + "g" * 64, "sha256:" + "0" * 63, 3, {}, []])
def test_malformed_recorded_session_reference_is_not_accepted(reference):
    person = account()
    evidence = {**person.evidence(), "session_fingerprint": reference}
    with pytest.raises(ValueError, match="session reference"):
        principal_from_evidence(person.actor, evidence)
