"""Authorization reads must use a stable current file across atomic inventory saves."""
from copy import deepcopy
from contextlib import contextmanager
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from cyberthunder.inventory.host import persisted_target
from cyberthunder.inventory.targets import Inventory, ScopeViolation, Target
from cyberthunder.inventory import targets
from tests.security.test_account_transports import bound_context


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


def test_review_last_attempt_returns_fresh_rows_after_closing_each_handle(inventory_file, monkeypatch):
    path, row, publish, format = inventory_file
    opened, sleeps = [], []
    original_open = os.open

    def track_open(value, *args, **kwargs):
        fd = original_open(value, *args, **kwargs)
        if Path(value) == path:
            opened.append(fd)
        return fd

    def wait(delay):
        sleeps.append(delay)
        with pytest.raises(OSError):
            os.fstat(opened[-1])

    monkeypatch.setattr(os, 'open', track_open)
    monkeypatch.setattr(targets, 'time', SimpleNamespace(sleep=wait))
    calls = during_decode(monkeypatch, format, lambda count:
                          publish({'targets': [{**row, 'notes': str(count)}]}) if count < 8 else None)
    assert Inventory.read_persisted(path) == {'target': {**row, 'notes': '7'}}
    assert len(calls) == len(opened) == 8
    assert sleeps == [0.01] * 7
    with pytest.raises(OSError):
        os.fstat(opened[-1])


def test_review_exhaustion_has_seven_waits_and_no_cached_fallback(inventory_file, monkeypatch):
    path, row, publish, format = inventory_file
    inventory = Inventory.load(path)
    sleeps = []
    monkeypatch.setattr(targets, 'time', SimpleNamespace(sleep=sleeps.append))
    calls = during_decode(monkeypatch, format,
                          lambda count: publish({'targets': [{**row, 'notes': str(count)}]}))
    with pytest.raises(ScopeViolation, match='^persisted inventory is missing, unreadable or invalid$'):
        persisted_target(inventory, 'target', require_scope=True)
    assert len(calls) == 8 and sleeps == [0.01] * 7
    assert inventory._targets['target'].in_scope is True


@pytest.mark.parametrize('phase', ['initial', 'after_change'])
@pytest.mark.parametrize('failure', ['open_permission', 'stat_permission', 'read_io'])
def test_review_io_errors_are_sanitized_without_further_retries(
        inventory_file, monkeypatch, phase, failure):
    path, row, publish, format = inventory_file
    sleeps, attempts = [], []
    original_open, original_stat, original_fdopen = os.open, Path.stat, os.fdopen
    failing = phase == 'initial'

    def denied():
        raise PermissionError('private inventory permission detail')

    def open_file(value, *args, **kwargs):
        if Path(value) == path:
            attempts.append(None)
            if failing and failure == 'open_permission':
                denied()
        return original_open(value, *args, **kwargs)

    def stat_file(value, *args, **kwargs):
        if value == path and failing and failure == 'stat_permission':
            denied()
        return original_stat(value, *args, **kwargs)

    @contextmanager
    def read_file(fd, *args, **kwargs):
        with original_fdopen(fd, *args, **kwargs) as stream:
            if failing and failure == 'read_io':
                def failed_read(*args):
                    raise OSError('private inventory read detail')
                yield SimpleNamespace(fileno=stream.fileno, read=failed_read)
            else:
                yield stream

    def wait(delay):
        nonlocal failing
        sleeps.append(delay)
        failing = True

    monkeypatch.setattr(os, 'open', open_file)
    monkeypatch.setattr(Path, 'stat', stat_file)
    monkeypatch.setattr(os, 'fdopen', read_file)
    monkeypatch.setattr(targets, 'time', SimpleNamespace(sleep=wait))
    during_decode(monkeypatch, format, lambda count:
                  publish({'targets': [{**row, 'notes': 'changed'}]})
                  if count == 1 and phase == 'after_change' else None)
    with pytest.raises(ScopeViolation) as error:
        Inventory.read_persisted(path)
    assert str(error.value) == 'persisted inventory is missing, unreadable or invalid'
    assert error.value.__suppress_context__
    assert len(attempts) == (2 if phase == 'after_change' else 1)
    assert sleeps == ([0.01] if phase == 'after_change' else [])


def test_review_registration_retry_preserves_revocation_without_relocking(inventory_file, monkeypatch):
    path, row, publish, format = inventory_file
    inventory = Inventory.load(path)
    original_lock = targets.file_lock
    held, entries, sleeps = [], [], []

    @contextmanager
    def lock(value):
        assert not held, 'inventory read reacquired the registration lock'
        with original_lock(value):
            held.append(value)
            entries.append(value)
            try:
                yield
            finally:
                held.pop()

    def wait(delay):
        assert len(held) == 1
        sleeps.append(delay)

    monkeypatch.setattr(targets, 'file_lock', lock)
    monkeypatch.setattr(targets, 'time', SimpleNamespace(sleep=wait))
    calls = during_decode(monkeypatch, format, lambda count:
                          publish({'targets': [{**row, 'in_scope': False}]}) if count == 1 else None)
    inventory.add_new(Target('new', 'New target', 'linux', in_scope=False))
    assert len(entries) == 1 and not held
    assert len(calls) == 2 and sleeps == [0.01]
    fresh = Inventory.read_persisted(path)
    assert set(fresh) == {'target', 'new'}
    assert fresh['target']['in_scope'] is False and fresh['new']['in_scope'] is False


@pytest.mark.parametrize('change', ['scope', 'address', 'identity', 'credential', 'missing'])
def test_review_revocation_during_backoff_blocks_an_open_connection(bound_context, monkeypatch, change):
    from cyberthunder.control.principal import operation_scope, principal_scope

    ctx, target, person, _, _, opened = bound_context
    path = ctx.inventory.path
    document = yaml.safe_load(path.read_text(encoding='utf-8'))
    sleeps = []

    def publish(value):
        pending = path.with_name(path.name + '.review-next')
        pending.write_text(yaml.safe_dump(value), encoding='utf-8')
        os.replace(pending, path)

    def interrupt(count):
        if count == 1:
            publish({'targets': [*document['targets'], Target('other', 'Other', 'linux').to_dict()]})

    def revoke(delay):
        sleeps.append(delay)
        if change == 'missing':
            path.unlink()
            return
        field, value = {'scope': ('in_scope', False), 'address': ('address', '192.0.2.99'),
                        'identity': ('authorization_id', 'f' * 32),
                        'credential': ('credential_ref', 'ROTATED')}[change]
        document['targets'][0][field] = value
        publish(document)

    try:
        with principal_scope(person), operation_scope('scan'):
            transport = ctx.transport_for(target)
            try:
                transport.run('before')
                calls = during_decode(monkeypatch, 'yaml', interrupt)
                monkeypatch.setattr(targets, 'time', SimpleNamespace(sleep=revoke))
                with pytest.raises(PermissionError):
                    transport.run('after')
                assert sleeps == [0.01]
                if change == 'missing':
                    assert len(calls) == 1
                else:
                    assert len(calls) >= 2
                assert opened[0][1].calls == [('before', False)]
                assert ctx.inventory._targets[target.id].in_scope is True
            finally:
                transport.close()
    finally:
        assert ctx.close(5)
