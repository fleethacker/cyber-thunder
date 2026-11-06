"""Authorization reads must use a stable current file across atomic inventory saves."""
from copy import deepcopy
import json
import os

import pytest
import yaml

from cyberthunder.inventory.host import persisted_target
from cyberthunder.inventory.targets import Inventory, ScopeViolation, Target


@pytest.fixture(params=['yaml', 'json'])
def inventory_file(tmp_path, request):
    path = tmp_path / ('targets.' + request.param)
    row = Target('target', 'Target', 'linux', address='192.0.2.4', in_scope=True).to_dict()

    def publish(document):
        pending = path.with_name(path.name + '.next')
        text = yaml.safe_dump(document) if request.param == 'yaml' else json.dumps(document)
        pending.write_text(text, encoding='utf-8')
        os.replace(pending, path)

    publish({'targets': [row]})
    return path, row, publish, request.param


def during_decode(monkeypatch, format, action):
    module, name = (yaml, 'safe_load') if format == 'yaml' else (json, 'loads')
    original = getattr(module, name)
    calls = []

    def decode(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append(None)
        action(len(calls))
        return result

    monkeypatch.setattr(module, name, decode)
    return calls


def test_atomic_unrelated_registration_reads_new_complete_inventory(inventory_file, monkeypatch):
    path, row, publish, format = inventory_file
    added = Target('other', 'Other', 'windows', in_scope=False).to_dict()
    calls = during_decode(monkeypatch, format,
                          lambda count: publish({'targets': [row, added]}) if count == 1 else None)
    rows = Inventory.read_persisted(path)
    assert rows == {'target': row, 'other': added}
    assert len(calls) == 2


def test_scope_revocation_during_decode_cannot_reuse_cached_authority(inventory_file, monkeypatch):
    path, row, publish, format = inventory_file
    inventory = Inventory.load(path)
    assert inventory.get('target').in_scope is True
    revoked = {**row, 'in_scope': False}
    calls = during_decode(monkeypatch, format,
                          lambda count: publish({'targets': [revoked]}) if count == 1 else None)
    with pytest.raises(ScopeViolation, match='out of scope'):
        persisted_target(inventory, 'target', require_scope=True)
    assert len(calls) == 2


def test_changed_target_binding_is_returned_from_latest_file(inventory_file, monkeypatch):
    path, row, publish, format = inventory_file
    moved = {**row, 'address': '192.0.2.8', 'credential_ref': 'rotated-reference',
             'authorization_id': 'f' * 32}
    during_decode(monkeypatch, format,
                  lambda count: publish({'targets': [moved]}) if count == 1 else None)
    assert Inventory.read_persisted(path)['target'] == moved


@pytest.mark.parametrize('damage', ['malformed', 'missing', 'implicit_scope'])
def test_replacement_does_not_fall_back_after_invalid_or_missing_file(inventory_file, monkeypatch, damage):
    path, row, publish, format = inventory_file

    def replace(count):
        if count != 1:
            return
        if damage == 'missing':
            path.unlink()
        elif damage == 'malformed':
            publish({'targets': 'private-invalid-scope'})
        else:
            changed = deepcopy(row)
            changed.pop('in_scope')
            publish({'targets': [changed]})

    calls = during_decode(monkeypatch, format, replace)
    with pytest.raises(ScopeViolation, match='persisted inventory') as failure:
        Inventory.read_persisted(path)
    assert 'private-invalid-scope' not in str(failure.value)
    assert len(calls) <= 2


def test_continuously_replaced_inventory_fails_after_bounded_fresh_reads(inventory_file, monkeypatch):
    path, row, publish, format = inventory_file
    calls = during_decode(monkeypatch, format,
                          lambda count: publish({'targets': [{**row, 'notes': str(count)}]}))
    with pytest.raises(ScopeViolation, match='persisted inventory'):
        Inventory.read_persisted(path)
    assert len(calls) == 8


def test_unchanged_invalid_scope_is_not_retried(inventory_file, monkeypatch):
    path, row, publish, format = inventory_file
    publish({'targets': [{**row, 'in_scope': 'true'}]})
    calls = during_decode(monkeypatch, format, lambda count: None)
    with pytest.raises(ScopeViolation, match='persisted inventory'):
        Inventory.read_persisted(path)
    assert len(calls) == 1
