"""Finite schedule and exact-account exception boundaries, with both document backends."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import time

import pytest

from cyberthunder.control.access import AccessPolicy
from cyberthunder.control.principal import principal_scope
from cyberthunder.remediation.maintenance import MaintenanceBlocked, MaintenanceService, iso, parse
from tests.security.test_identity_boundary import identity
from . import fakes
from .conftest import HOST
from .test_engine import root_login_proposal, scan, SAILOR, sshd

NOW = datetime(2030, 1, 2, 12, tzinfo=timezone.utc)


def schedule(ctx, *, windows=None, rules=None):
    path = ctx.store.root / 'maintenance.json'
    doc = {'version': 1, 'rules': rules if rules is not None else [dict(id='target-window', target_ids=[HOST],
        environments=['default'], windows=windows if windows is not None else [
            dict(start=iso(NOW), end=iso(NOW + timedelta(hours=1)))])]}
    path.write_text(json.dumps(doc), encoding='utf-8')
    path.chmod(0o600)
    ctx.settings.maintenance_policy = str(path)
    return doc


@pytest.fixture
def clock(monkeypatch):
    value = [NOW]
    monkeypatch.setattr(MaintenanceService, '_now', lambda _: value[0])
    return value


@pytest.fixture
def secure(make_ctx, clock, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    # The in-memory fixture needs no OS privilege; retain the real protected transport.
    from cyberthunder.remediation.models import ApplyResult
    adapter = ctx.engine._adapter(ctx.inventory.get(HOST))
    def simulated_apply(target, transport, fix, finding, before):
        result = transport.run(fix.payload)
        return ApplyResult(ok=result.ok, output=result.stdout or result.stderr)
    monkeypatch.setattr(adapter, 'apply', simulated_apply)
    finding = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    ctx.settings.auth_mode = 'oidc'
    ctx.settings.step_up_acr_values = ('urn:ct:test:strong',)
    path = ctx.store.root / 'auth' / 'access.json'
    path.parent.mkdir(exist_ok=True)
    grant = dict(actions=['read', 'propose', 'approve', 'apply', 'rollback', 'verify', 'plan', 'cancel'],
                 target_ids=[HOST], environments=['default'])
    doc = dict(version=1, entries=[dict(issuer=identity().issuer, subject=subject, node_actions=[],
                                     grants=[deepcopy(grant)]) for subject in ('proposer', 'first-user', 'other-login')])
    doc['entries'][1]['grants'].append(dict(actions=['maintenance.override'], target_ids=[HOST], environments=['default']))
    path.write_text(json.dumps(doc), encoding='utf-8')
    path.chmod(0o600)
    ctx.access = AccessPolicy(path)
    ctx.gate.authorizer = ctx.authorize
    ctx.gate.separation_policy = ctx.access.approval_identity_source
    with principal_scope(identity('proposer')):
        p = ctx.engine.propose(finding, actor=identity('proposer').actor)
    with principal_scope(identity()):
        ctx.gate.approve(p.id, identity().actor)
    schedule(ctx, windows=[])
    return ctx, p, doc


def override(ctx, p):
    review = MaintenanceService(ctx).summary(p)['override']
    assert review is not None
    return {**review, 'reason': 'Owner requested immediate restoration of service'}


def write_access(ctx, doc):
    ctx.access.path.write_text(json.dumps(doc), encoding='utf-8')


@pytest.mark.parametrize('offset,allowed,next_time', [(-1, False, True), (0, True, False), (3599, True, False), (3600, False, False)])
def test_exact_start_end_and_future(ctx, clock, offset, allowed, next_time):
    p = root_login_proposal(ctx)
    schedule(ctx)
    clock[0] = NOW + timedelta(seconds=offset)
    summary = MaintenanceService(ctx).summary(p)
    assert summary['allowed'] is allowed
    assert summary['next_eligible_at'] == (iso(NOW) if next_time else None)
    assert bool(summary['current_window']) is allowed
    assert summary['override'] is None  # Development labels cannot request exceptions.


def test_timezone_normalization_and_intersection(ctx, clock):
    p = root_login_proposal(ctx)
    schedule(ctx, rules=[dict(id='enclave', environments=['default'], windows=[
        dict(start='2030-01-02T06:00:00-05:00', end='2030-01-02T08:00:00-05:00')]),
        dict(id='target', target_ids=[HOST], windows=[dict(start='2030-01-02T12:30:00Z', end='2030-01-02T14:00:00Z')])])
    service = MaintenanceService(ctx)
    assert service.summary(p)['next_eligible_at'] == '2030-01-02T12:30:00Z'
    clock[0] = NOW + timedelta(minutes=30)
    assert service.summary(p)['current_window'] == dict(start='2030-01-02T12:30:00Z', end='2030-01-02T13:00:00Z')


@pytest.mark.parametrize('case', ['none', 'other_target', 'other_environment'])
def test_explicit_unconfigured_or_inapplicable_behavior(ctx, clock, case):
    p = root_login_proposal(ctx)
    if case != 'none':
        schedule(ctx, rules=[dict(id='other', target_ids=[HOST if case == 'other_environment' else 'other'],
                                 environments=['other' if case == 'other_environment' else 'default'], windows=[])])
    summary = MaintenanceService(ctx).summary(p)
    assert summary['status'] == ('unconfigured' if case == 'none' else 'not_applicable')
    assert summary['allowed']
    assert ctx.engine.execute(p.id, actor=SAILOR).state.value == 'verified'


@pytest.mark.parametrize('case', ['missing', 'empty', 'relative', 'directory', 'malformed', 'untrusted'])
def test_bad_config_is_held_without_state_or_target_change(ctx, clock, monkeypatch, case):
    p = root_login_proposal(ctx)
    schedule(ctx)
    path = ctx.store.root / 'maintenance.json'
    if case == 'missing': path.unlink()
    if case == 'empty': ctx.settings.maintenance_policy = ''
    if case == 'relative': ctx.settings.maintenance_policy = 'maintenance.json'
    if case == 'directory': ctx.settings.maintenance_policy = str(ctx.store.root)
    if case == 'malformed': path.write_text('{broken', encoding='utf-8')
    if case == 'untrusted':
        import cyberthunder.control.access as access
        def reject(*args, **kwargs): raise ValueError('untrusted owner')
        monkeypatch.setattr(access, '_check_node', reject)
    before, host = p.to_dict(), deepcopy(fakes.HOSTS[HOST])
    assert MaintenanceService(ctx).summary(p)['status'] == 'invalid'
    with pytest.raises(MaintenanceBlocked, match='unavailable or invalid'):
        ctx.engine.execute(p.id, actor=SAILOR)
    assert ctx.gate.get(p.id).to_dict() == before
    assert fakes.HOSTS[HOST] == host


@pytest.mark.parametrize('raw', [
    b'{"version":true,"rules":[]}', b'{"version":1,"version":1,"rules":[]}',
    b'{"version":1,"rules":[],"extra":0}', b'{"version":1,"rules":NaN}',
])
def test_strict_json(raw):
    with pytest.raises(ValueError): parse(raw)


@pytest.mark.parametrize('change', ['no_timezone', 'unknown_offset', 'offset_minutes', 'inverted', 'duplicate',
                                  'wildcard', 'empty_selector', 'no_selector', 'unknown_field', 'duplicate_id'])
def test_strict_rules(change):
    rule = dict(id='window', target_ids=[HOST], windows=[dict(start=iso(NOW), end=iso(NOW + timedelta(hours=1)))])
    doc = dict(version=1, rules=[rule])
    if change == 'no_timezone': rule['windows'][0]['start'] = '2030-01-02T12:00:00'
    if change == 'unknown_offset': rule['windows'][0]['start'] = '2030-01-02T12:00:00-00:00'
    if change == 'offset_minutes': rule['windows'][0]['start'] = '2030-01-02T12:00:00+01:99'
    if change == 'inverted': rule['windows'][0]['end'] = iso(NOW)
    if change == 'duplicate': rule['windows'] *= 2
    if change == 'wildcard': rule['target_ids'] = ['*']
    if change == 'empty_selector': rule['target_ids'] = []
    if change == 'no_selector': rule.pop('target_ids')
    if change == 'unknown_field': rule['timezone'] = 'America/New_York'
    if change == 'duplicate_id': doc['rules'] *= 2
    with pytest.raises(ValueError): parse(json.dumps(doc).encode())


def test_outside_window_has_no_capture_no_mutation(ctx, clock, monkeypatch):
    p = root_login_proposal(ctx)
    schedule(ctx, windows=[])
    before, host = p.to_dict(), deepcopy(fakes.HOSTS[HOST])
    monkeypatch.setattr(ctx, 'transport_for', lambda *_: pytest.fail('outside window connected'))
    with pytest.raises(MaintenanceBlocked, match='Outside maintenance window'):
        ctx.engine.execute(p.id, actor=SAILOR)
    assert ctx.gate.get(p.id).to_dict() == before and fakes.HOSTS[HOST] == host
    plan = ctx.engine.plan(p.id, actor=SAILOR)
    assert plan['maintenance']['status'] == 'held'
    assert next(c for c in plan['checks'] if c['code'] == 'maintenance')['status'] == 'blocked'


@pytest.mark.parametrize('change', ['clock', 'policy', 'removed', 'ownership', 'audit', 'kill'])
def test_final_boundary_stops_changes_during_capture(ctx, clock, monkeypatch, change):
    p = root_login_proposal(ctx)
    schedule(ctx)
    host = deepcopy(fakes.HOSTS[HOST])
    append = ctx.audit.append
    def audit(action, *args, **kwargs):
        result = append(action, *args, **kwargs)
        if action == 'remediation.before_state':
            if change == 'clock': clock[0] = NOW + timedelta(hours=1)
            if change == 'policy': schedule(ctx, windows=[])
            if change == 'removed': ctx.settings.maintenance_policy = None
            if change == 'ownership':
                ctx.inventory.get(HOST).environment = 'new-owner'; ctx.inventory.save()
            if change == 'kill': ctx.killswitch.engage(SAILOR, 'fixture stop')
        if change == 'audit' and action == 'maintenance.checked' and args[1]['boundary'] == 'execution':
            raise OSError('audit unavailable')
        return result
    monkeypatch.setattr(ctx.audit, 'append', audit)
    with pytest.raises(Exception): ctx.engine.execute(p.id, actor=SAILOR)
    assert fakes.HOSTS[HOST] == host
    assert not (ctx.store.snapshots_dir / p.id / 'apply.json').exists()
    assert not any(r['action'] == 'remediation.rollback_mutation' for r in ctx.audit.records())


@pytest.mark.parametrize('operation', ['rollback', 'verify', 'automatic_rollback'])
def test_window_end_never_strands_already_executed_work(ctx, clock, monkeypatch, operation):
    p = root_login_proposal(ctx)
    original = sshd(ctx)
    schedule(ctx)
    adapter = ctx.engine._adapter(ctx.inventory.get(HOST))
    apply = adapter.apply
    def perform(*args):
        result = apply(*args)
        clock[0] = NOW + timedelta(hours=1)
        return result
    monkeypatch.setattr(adapter, 'apply', perform)
    result = ctx.engine.execute(p.id, actor=SAILOR, simulate_verify_fail=operation == 'automatic_rollback')
    if operation == 'automatic_rollback':
        assert result.state.value == 'rolled_back' and sshd(ctx) == original
    elif operation == 'rollback':
        assert ctx.engine.rollback(p.id, actor=SAILOR).state.value == 'rolled_back'
        assert sshd(ctx) == original
    else:
        assert result.state.value == 'verified'  # Automatic verification occurred after expiry.


def test_override_apply_requires_approval_and_records_account_reason(secure):
    ctx, p, _ = secure
    with principal_scope(identity()):
        request = override(ctx, p)
        assert ctx.engine.execute(p.id, actor=identity().actor, maintenance_override=request).state.value == 'verified'
    records = [r for r in ctx.audit.records() if r['action'] == 'maintenance.override']
    assert {r['details']['boundary'] for r in records} == {'admission', 'execution'}
    assert all(r['actor'] == identity().actor and r['details']['override']['reason'] == request['reason'] for r in records)
    assert all(r['principal']['sub'] == 'first-user' for r in records)
    with principal_scope(identity()), pytest.raises(Exception):
        ctx.engine.execute(p.id, actor=identity().actor, maintenance_override=request)


@pytest.mark.parametrize('case', ['ordinary_apply', 'admin', 'group', 'wildcard_target', 'wildcard_environment',
                                'missing_target', 'missing_environment', 'node', 'other_account', 'same_person'])
def test_unequal_override_grants_never_inherit(secure, case):
    ctx, p, doc = secure
    row = doc['entries'][1]
    grant = row['grants'].pop()
    person = identity()
    if case == 'group':
        doc['entries'].append(dict(issuer=person.issuer, group='operators', node_actions=[], grants=[grant]))
        person = replace(person, groups=('operators',))
    elif case == 'node': row['node_actions'].append('maintenance.override')
    elif case != 'ordinary_apply':
        row['grants'].append(grant)
        if case == 'admin': person = identity(roles=('admin',))
        if case == 'wildcard_target': grant['target_ids'] = ['*']
        if case == 'wildcard_environment': grant['environments'] = ['*']
        if case == 'missing_target': grant.pop('target_ids')
        if case == 'missing_environment': grant.pop('environments')
        if case == 'other_account': person = identity('other-login')
        if case == 'same_person':
            doc.update(version=2, approval_identity=dict(mode='person', version=1, namespace='crew', revision=1))
            for entry in doc['entries']: entry['person_id'] = 'shared-person'
            person = identity('other-login')
    write_access(ctx, doc)
    with principal_scope(person):
        assert MaintenanceService(ctx).summary(p)['override'] is None
        with pytest.raises(PermissionError):
            ctx.authorize('maintenance.override', actor=person.actor, target=HOST)


@pytest.mark.parametrize('case', ['expiry', 'future_expiry', 'payload', 'policy', 'ownership', 'access', 'association',
                                'assurance', 'stale_auth', 'missing_acr', 'workload', 'reason', 'actor', 'apply_grant'])
def test_stale_override_or_missing_authority_refuses_unchanged(secure, clock, case):
    ctx, p, doc = secure
    person = identity()
    with principal_scope(person): request = override(ctx, p)
    host = deepcopy(fakes.HOSTS[HOST])
    if case == 'expiry': clock[0] += timedelta(seconds=120)
    if case == 'future_expiry': request['expires_at'] = iso(NOW + timedelta(seconds=121))
    if case == 'payload': ctx.library.get(p.fix_ref).payload += '\nchanged'
    if case == 'policy': schedule(ctx)
    if case == 'ownership':
        ctx.inventory.get(HOST).authorization_id = 'f' * 32; ctx.inventory.save()
    if case == 'access':
        doc['entries'][1]['grants'].pop(); write_access(ctx, doc)
    if case == 'association':
        doc.update(version=2, approval_identity=dict(mode='person', version=1, namespace='crew', revision=1))
        for entry in doc['entries']: entry['person_id'] = entry['subject']
        write_access(ctx, doc)
    if case == 'assurance': ctx.settings.step_up_max_age_s = 299
    if case == 'stale_auth': person = replace(person, auth_time=int(time.time()) - 301)
    if case == 'missing_acr': person = replace(person, acr=None)
    if case == 'workload': person = replace(person, kind='workload')
    if case == 'reason': request['reason'] = ' '
    if case == 'apply_grant':
        doc['entries'][1]['grants'][0]['actions'].remove('apply'); write_access(ctx, doc)
    with principal_scope(person), pytest.raises(Exception):
        ctx.engine.execute(p.id, actor='Typed Name' if case == 'actor' else person.actor, maintenance_override=request)
    assert ctx.gate.get(p.id).state.value == 'approved'
    assert fakes.HOSTS[HOST] == host


@pytest.mark.parametrize('change', ['policy', 'clock', 'ownership', 'grant', 'session', 'audit', 'payload'])
def test_override_rechecked_after_audit_at_execution(secure, clock, monkeypatch, change):
    ctx, p, doc = secure
    host = deepcopy(fakes.HOSTS[HOST])
    append = ctx.audit.append
    revoked = False
    def audit(action, *args, **kwargs):
        nonlocal revoked
        result = append(action, *args, **kwargs)
        if action == 'maintenance.override' and args[1]['boundary'] == 'execution':
            if change == 'policy': schedule(ctx)
            if change == 'clock': clock[0] += timedelta(seconds=120)
            if change == 'ownership':
                ctx.inventory.get(HOST).environment = 'new'; ctx.inventory.save()
            if change == 'grant':
                doc['entries'][1]['grants'].pop(); write_access(ctx, doc)
            if change == 'session': revoked = True
            if change == 'audit': raise OSError('cannot audit')
            if change == 'payload': ctx.library.get(p.fix_ref).payload += '\nchanged'
        return result
    def validity():
        if revoked: raise PermissionError('session revoked')
    monkeypatch.setattr(ctx.audit, 'append', audit)
    with principal_scope(identity(), validity=validity):
        request = override(ctx, p)
        with pytest.raises(PermissionError):
            ctx.engine.execute(p.id, actor=identity().actor, maintenance_override=request)
    assert fakes.HOSTS[HOST] == host
    assert not (ctx.store.snapshots_dir / p.id / 'apply.json').exists()


def test_concurrent_same_override_executes_at_most_once(secure):
    ctx, p, _ = secure
    person = identity()
    with principal_scope(person): request = override(ctx, p)
    def run():
        with principal_scope(person):
            try: return ctx.engine.execute(p.id, actor=person.actor, maintenance_override=request).state.value
            except Exception: return 'refused'
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(), range(2)))
    assert sorted(results) == ['refused', 'verified']
    assert sum(r['action'] == 'maintenance.override' and r['details']['boundary'] == 'execution'
               for r in ctx.audit.records()) == 1


@pytest.fixture
def api(secure, monkeypatch):
    from fastapi.testclient import TestClient
    from cyberthunder.api.app import create_app
    from tests.security.test_identity_boundary import headers
    ctx, p, doc = secure
    tokens, queued = {}, []
    class Validator:
        def validate(self, token):
            person = tokens[token]
            return dict(iss=person.issuer, sub=person.subject, name=person.display_name, ct_kind=person.kind,
                        ct_roles=list(person.roles), groups=list(person.groups), exp=person.expires_at,
                        auth_time=person.auth_time, acr=person.acr)
    monkeypatch.setattr('cyberthunder.api.auth.make_validator', lambda *_: Validator())
    monkeypatch.setattr('cyberthunder.api.util.run_background', lambda fn, _: queued.append(fn))
    with TestClient(create_app(ctx)) as client:
        yield ctx, p, doc, client, lambda person=None: headers(tokens, person), queued


def test_api_reports_hold_and_refuses_before_queue(api):
    ctx, p, _, client, headers, queued = api
    url = f'/api/v1/proposals/{p.id}'
    result = client.get(url, headers=headers())
    assert result.status_code == 200
    assert result.json()['maintenance']['status'] == 'held'
    assert result.json()['maintenance']['override']
    plan = client.post(url + '/plan', headers=headers())
    assert plan.status_code == 200 and plan.json()['maintenance']['status'] == 'held'
    result = client.post(url + '/apply', headers=headers(), json={})
    assert result.status_code == 403 and 'Outside maintenance window' in result.text
    assert not queued and ctx.gate.get(p.id).state.value == 'approved'


@pytest.mark.parametrize('case', ['allowed', 'stale_auth', 'other_account', 'unknown_field', 'wrong_binding', 'expired'])
def test_api_deliberate_override_submission(api, clock, case):
    ctx, p, _, client, headers, queued = api
    url = f'/api/v1/proposals/{p.id}'
    request = client.get(url, headers=headers()).json()['maintenance']['override']
    request['reason'] = 'Owner requested immediate restoration of service'
    person = identity()
    if case == 'stale_auth': person = replace(person, auth_time=int(time.time()) - 301)
    if case == 'other_account': person = identity('other-login')
    if case == 'unknown_field': request['actor'] = 'Forged operator'
    if case == 'wrong_binding': request['binding'] = '0' * 64
    if case == 'expired': clock[0] += timedelta(seconds=120)
    response = client.post(url + '/apply', headers=headers(person), json=dict(maintenance_override=request))
    expected = {'allowed': 202, 'stale_auth': 401, 'unknown_field': 400}.get(case, 403)
    assert response.status_code == expected, response.text
    if case == 'allowed':
        assert len(queued) == 1
        with principal_scope(person): queued[0]()
        assert ctx.gate.get(p.id).state.value == 'verified'
    else:
        assert not queued and ctx.gate.get(p.id).state.value == 'approved'
        if case == 'stale_auth': assert response.json()['error'] == 'insufficient_user_authentication'


def test_override_never_replaces_approval(secure):
    ctx, p, _ = secure
    with principal_scope(identity()):
        request = override(ctx, p)
        ctx.gate.cancel(p.id, identity().actor)
        with pytest.raises(Exception):
            ctx.engine.execute(p.id, actor=identity().actor, maintenance_override=request)
    assert ctx.gate.get(p.id).state.value == 'cancelled'


def test_override_does_not_grant_privilege_elevation(secure, monkeypatch):
    ctx, p, _ = secure
    adapter = ctx.engine._adapter(ctx.inventory.get(HOST))
    monkeypatch.setattr(adapter, 'apply', lambda *args: fakes.FakeLinuxAdapter.apply(adapter, *args))
    host = deepcopy(fakes.HOSTS[HOST])
    with principal_scope(identity()):
        request = override(ctx, p)
        with pytest.raises(PermissionError, match='privilege elevation'):
            ctx.engine.execute(p.id, actor=identity().actor, maintenance_override=request)
    assert fakes.HOSTS[HOST] == host


def test_verified_recovery_after_expiry_and_missing_policy(secure, clock):
    ctx, p, _ = secure
    host = sshd(ctx)
    with principal_scope(identity()):
        request = override(ctx, p)
        assert ctx.engine.execute(p.id, actor=identity().actor, maintenance_override=request).state.value == 'verified'
        clock[0] += timedelta(hours=1)
        (ctx.store.root / 'maintenance.json').unlink()
        assert ctx.engine.rollback(p.id, actor=identity().actor).state.value == 'rolled_back'
    assert sshd(ctx) == host


def test_schedule_rechecked_after_last_kill_guard(ctx, clock, monkeypatch):
    p = root_login_proposal(ctx)
    schedule(ctx)
    guard = ctx.killswitch.guard
    host = deepcopy(fakes.HOSTS[HOST])
    def stop_at_boundary(action, actor):
        result = guard(action, actor)
        if action == f'remediation.apply:{p.id}': clock[0] += timedelta(hours=1)
        return result
    monkeypatch.setattr(ctx.killswitch, 'guard', stop_at_boundary)
    with pytest.raises(MaintenanceBlocked): ctx.engine.execute(p.id, actor=SAILOR)
    assert fakes.HOSTS[HOST] == host


def test_refusal_audit_failure_cannot_trigger_rollback(ctx, clock, monkeypatch):
    p = root_login_proposal(ctx)
    schedule(ctx)
    host = deepcopy(fakes.HOSTS[HOST])
    append = ctx.audit.append
    def fail(action, *args, **kwargs):
        if action == 'maintenance.blocked': raise OSError('audit unavailable')
        result = append(action, *args, **kwargs)
        if action == 'remediation.before_state': clock[0] += timedelta(hours=1)
        return result
    monkeypatch.setattr(ctx.audit, 'append', fail)
    with pytest.raises(MaintenanceBlocked): ctx.engine.execute(p.id, actor=SAILOR)
    assert fakes.HOSTS[HOST] == host
    assert not any(r['action'] == 'remediation.rollback_mutation' for r in ctx.audit.records())


def test_backward_wall_clock_cannot_reopen_expired_window(ctx, monkeypatch):
    from cyberthunder.security import step_up
    p = root_login_proposal(ctx)
    schedule(ctx)
    wall, mono = [NOW.timestamp() + 3600], [100.0]
    monkeypatch.setattr(step_up.time, 'time', lambda: wall[0])
    monkeypatch.setattr(step_up.time, 'monotonic', lambda: mono[0])
    ctx.step_up_clock = step_up.FreshnessClock()
    assert MaintenanceService(ctx).summary(p)['status'] == 'held'
    wall[0] -= 1800
    mono[0] += 1
    assert MaintenanceService(ctx).summary(p)['status'] == 'held'


def test_override_preserves_distinct_person_quorum(secure):
    from cyberthunder.findings.schema import Severity
    ctx, old, doc = secure
    with principal_scope(identity()): ctx.gate.cancel(old.id, identity().actor)
    doc.update(version=2, approval_identity=dict(mode='person', version=1, namespace='crew', revision=1))
    for entry in doc['entries']:
        entry['person_id'] = 'proposer' if entry['subject'] == 'proposer' else 'one-person'
    second = deepcopy(doc['entries'][2])
    second.update(subject='independent-account', person_id='independent-person')
    doc['entries'].append(second)
    write_access(ctx, doc)
    finding = replace(ctx.store.get_finding(old.finding_id), severity=Severity.HIGH)
    ctx.store.save_findings(finding.scan_id, [finding])
    with principal_scope(identity('proposer')):
        p = ctx.engine.propose(finding, actor=identity('proposer').actor)
    with principal_scope(identity()):
        ctx.gate.approve(p.id, identity().actor)
        assert p.state.value == 'proposed' and p.required_approvals == 2
        assert MaintenanceService(ctx).summary(p)['override'] is None
        with pytest.raises(Exception): ctx.engine.execute(p.id, actor=identity().actor, maintenance_override={})
    with principal_scope(identity('other-login')), pytest.raises(PermissionError):
        ctx.gate.approve(p.id, identity('other-login').actor)
    with principal_scope(identity('independent-account')):
        ctx.gate.approve(p.id, identity('independent-account').actor)
    with principal_scope(identity()):
        request = override(ctx, p)
        assert ctx.engine.execute(p.id, actor=identity().actor, maintenance_override=request).state.value == 'verified'


def test_expiry_during_policy_read_is_observed(ctx, clock, monkeypatch):
    from cyberthunder.remediation import maintenance
    p = root_login_proposal(ctx)
    schedule(ctx)
    host = deepcopy(fakes.HOSTS[HOST])
    parse_policy = maintenance.parse
    def slow_parse(raw):
        result = parse_policy(raw)
        if p.state.value == 'applying': clock[0] += timedelta(hours=1)
        return result
    monkeypatch.setattr(maintenance, 'parse', slow_parse)
    with pytest.raises(MaintenanceBlocked): ctx.engine.execute(p.id, actor=SAILOR)
    assert fakes.HOSTS[HOST] == host


def test_override_expiry_during_binding_reads_is_observed(secure, clock, monkeypatch):
    ctx, p, _ = secure
    host = deepcopy(fakes.HOSTS[HOST])
    binding = MaintenanceService._binding
    def slow_binding(service, proposal, *args):
        result = binding(service, proposal, *args)
        if proposal.state.value == 'applying': clock[0] += timedelta(seconds=120)
        return result
    monkeypatch.setattr(MaintenanceService, '_binding', slow_binding)
    with principal_scope(identity()):
        request = override(ctx, p)
        with pytest.raises(MaintenanceBlocked):
            ctx.engine.execute(p.id, actor=identity().actor, maintenance_override=request)
    assert fakes.HOSTS[HOST] == host


def test_assurance_expiry_during_binding_reads_is_observed(secure, monkeypatch):
    ctx, p, _ = secure
    host = deepcopy(fakes.HOSTS[HOST])
    binding = MaintenanceService._binding
    def slow_binding(service, proposal, *args):
        result = binding(service, proposal, *args)
        if proposal.state.value == 'applying':
            monkeypatch.setattr(ctx.step_up_clock, 'now', lambda: time.time() + 301)
        return result
    monkeypatch.setattr(MaintenanceService, '_binding', slow_binding)
    with principal_scope(identity()):
        request = override(ctx, p)
        with pytest.raises(PermissionError):
            ctx.engine.execute(p.id, actor=identity().actor, maintenance_override=request)
    assert fakes.HOSTS[HOST] == host


@pytest.mark.parametrize('configured', [False, True])
def test_legacy_missing_ownership_requires_new_proposal_only_when_configured(ctx, clock, configured):
    ctx.gate.resource_scope = None
    p = root_login_proposal(ctx)
    assert p.authorization_scope is None
    if configured:
        schedule(ctx)
        host = deepcopy(fakes.HOSTS[HOST])
        with pytest.raises(MaintenanceBlocked, match='Original target ownership'):
            ctx.engine.execute(p.id, actor=SAILOR)
        assert p.state.value == 'approved' and fakes.HOSTS[HOST] == host
    else:
        assert ctx.engine.execute(p.id, actor=SAILOR).state.value == 'verified'
