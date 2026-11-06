"""Strict opt-in schema and the existing protected loader for person associations."""
from copy import deepcopy
import json

import pytest

from cyberthunder.control import access
from tests.security.test_access import Principal, entry, target


def document():
    return {"version": 2, "approval_identity": {"mode": "person", "version": 1,
            "namespace": "operators", "revision": 1}, "entries": [entry(person_id="p-1")]}


@pytest.mark.parametrize("change", [
    lambda d: d.update(version=True), lambda d: d.update(version=2.0),
    lambda d: d.update(version=3), lambda d: d.update(version=1),
    lambda d: d.pop("approval_identity"), lambda d: d.update(extra=True),
    lambda d: d["approval_identity"].update(mode="account"),
    lambda d: d["approval_identity"].update(mode="group"),
    lambda d: d["approval_identity"].update(version=True),
    lambda d: d["approval_identity"].update(version=2),
    lambda d: d["approval_identity"].update(revision=True),
    lambda d: d["approval_identity"].update(revision=0),
    lambda d: d["approval_identity"].update(revision=1.0),
    lambda d: d["approval_identity"].update(revision=2**53),
    lambda d: d["approval_identity"].update(namespace=""),
    lambda d: d["approval_identity"].update(namespace="a/b"),
    lambda d: d["approval_identity"].update(extra=True),
    lambda d: d["entries"][0].update(person_id=""),
    lambda d: d["entries"][0].update(person_id="email@example.test"),
    lambda d: d["entries"][0].update(person_id="Full Name"),
    lambda d: d["entries"][0].update(person_id="*"),
    lambda d: d["entries"][0].update(person_id="x" * 129),
    lambda d: d["entries"][0].update(person_id=["one", "two"]),
    lambda d: d["entries"][0].update(person_id=None),
    lambda d: d["entries"][0].update(group=d["entries"][0].pop("subject")),
    lambda d: d["entries"].append(deepcopy(d["entries"][0])),
    lambda d: d["entries"].append({**d["entries"][0], "person_id": "conflicting"}),
])
def test_invalid_person_policy_denies_all_consumers(tmp_path, change):
    d = document()
    change(d)
    path = tmp_path / "access.json"
    path.write_text(json.dumps(d), encoding="utf-8")
    policy = access.AccessPolicy(path)
    assert not policy.allows(Principal(), "scan", target())
    with pytest.raises(access.AccessDenied, match="unavailable or invalid"):
        policy.approval_identity_source()


def test_groups_grant_access_but_only_exact_subject_entries_associate_people(tmp_path):
    d = document()
    group = entry(group="operators")
    group.pop("subject")
    d["entries"] = [group, entry(person_id="p-1", grants=[])]
    path = tmp_path / "access.json"
    path.write_text(json.dumps(d), encoding="utf-8")
    policy = access.AccessPolicy(path)
    assert policy.allows(Principal(groups=("operators",)), "scan", target())
    assert not policy.allows(Principal(), "scan", target())
    snapshot = policy.approval_identity_source()
    assert snapshot.association(Principal().issuer, "alice")["person_id"] == "p-1"
    for issuer, subject in [(Principal().issuer, "operators"), (Principal().issuer + "/", "alice"),
                            (Principal().issuer, "Alice"), (Principal().issuer, "missing")]:
        with pytest.raises(access.AccessDenied):
            snapshot.association(issuer, subject)


def test_legacy_schema_cannot_smuggle_person_field(tmp_path):
    d = {"version": 1, "entries": [entry(person_id="p-1")]}
    path = tmp_path / "access.json"
    path.write_text(json.dumps(d))
    with pytest.raises(access.AccessDenied):
        access.AccessPolicy(path).approval_identity_source()
    d["entries"][0].pop("person_id")
    path.write_text(json.dumps(d))
    assert access.AccessPolicy(path).approval_identity_source().basis == {"mode": "account", "policy_version": 1}


def test_association_load_uses_same_race_checks_and_no_last_good_cache(tmp_path, monkeypatch):
    path = tmp_path / "access.json"
    path.write_text(json.dumps(document()))
    policy = access.AccessPolicy(path)
    policy.approval_identity_source()
    parse = access._parse

    def changed(raw):
        result = parse(raw)
        path.write_bytes(raw + b"\n")
        return result

    monkeypatch.setattr(access, "_parse", changed)
    with pytest.raises(access.AccessDenied):
        policy.approval_identity_source()


def test_duplicate_json_mapping_key_is_not_last_write_wins(tmp_path):
    path = tmp_path / "access.json"
    path.write_text(json.dumps(document()).replace('"person_id": "p-1"', '"person_id":"p-1","person_id":"p-2"'))
    with pytest.raises(access.AccessDenied):
        access.AccessPolicy(path).approval_identity_source()
