"""Image baselines stay within explicit namespace and account permissions."""
from copy import deepcopy
from contextlib import contextmanager
from dataclasses import replace
import json
from pathlib import Path

import pytest

from cyberthunder.control.principal import Principal, principal_scope, operation_scope
from cyberthunder.inventory.targets import ScopeViolation
from tests.cluster.test_guardrails import (
    ACTOR, APP_IMAGE, completed, ctx, external_calls, fake_tools, target,
)
from tests.security.test_kubernetes_account_integration import assert_selected, selected_cluster
from tests.security.test_kube_credentials import cert_material


TYPES = {
    'deployments': ('Deployment', 'apps/v1'),
    'statefulsets': ('StatefulSet', 'apps/v1'),
    'daemonsets': ('DaemonSet', 'apps/v1'),
    'cronjobs': ('CronJob', 'batch/v1'),
    'jobs': ('Job', 'batch/v1'),
    'pods': ('Pod', 'v1'),
}


def list_result(resource, namespace):
    kind, api = TYPES[resource]
    items = []
    if resource == 'deployments':
        items = [{'apiVersion': api, 'kind': kind,
                  'metadata': {'namespace': namespace, 'name': 'web', 'uid': 'uid-' + namespace},
                  'spec': {'replicas': 0, 'template': {'spec': {
                      'containers': [{'name': 'nginx', 'image': APP_IMAGE}]}}}}]
    return {'kind': kind + 'List', 'apiVersion': api, 'metadata': {}, 'items': items}


def tools(argv, **kwargs):
    if argv[0] == 'trivy':
        return fake_tools(argv, **kwargs)
    if '-n' not in argv or '-A' in argv or 'namespaces' in argv:
        raise RuntimeError('Forbidden: fixture account has no cluster-wide list permission')
    namespace = argv[argv.index('-n') + 1]
    resource = argv[argv.index('get') + 1]
    return completed(argv, list_result(resource, namespace))


def restrict(ctx, target, namespaces=None):
    target.options['namespaces'] = namespaces or ['mission', 'ops']
    ctx.inventory.save()


def test_restricted_baseline_scans_only_selected_namespaces(ctx, target, external_calls):
    restrict(ctx, target)
    process, network = external_calls
    process.side_effect = tools
    doc = ctx.cluster.scan(actor=ACTOR)
    assert doc['status'] == 'done'
    assert doc['errors'] == []
    assert doc['target']['namespaces'] == ['mission', 'ops']
    scope = doc['survey']['collection_scope']
    assert scope == {'mode': 'namespace', 'namespaces': ['mission', 'ops'],
                     'cluster_complete': False, 'namespace_lists_complete': True}
    assert {n['name'] for n in doc['survey']['namespaces']} == {'mission', 'ops'}
    assert all(n['metadata_collected'] is False for n in doc['survey']['namespaces'])
    reads = [c.args[0] for c in process.call_args_list if c.args[0][0] != 'trivy']
    scans = [c.args[0] for c in process.call_args_list if c.args[0][0] == 'trivy']
    assert len(reads) == 12 and len(scans) == 1
    assert {tuple(a[a.index('get'):]) for a in reads} == {
        ('get', resource, '-n', namespace, '-o', 'json')
        for resource in TYPES for namespace in ['mission', 'ops']}
    findings = [f for f in ctx.store.current_findings() if f.source == 'trivy' and f.is_open]
    assert len(findings) == 2
    assert all(f.collection_provenance['kubernetes_scope'] == scope for f in findings)
    assert all(f.fix_ref is None for f in findings)
    network.assert_not_called()


@pytest.mark.parametrize('args', [
    ('get', 'pods', '-A'), ('get', 'namespaces'), ('get', 'pods', '-n', 'outside'),
    ('get', 'pods', '-n', 'mission', '--context', 'admin'),
    ('delete', 'pods', '-n', 'mission'), ('get', 'secrets', '-n', 'mission'),
])
def test_namespace_command_boundary_refuses_broader_calls(ctx, target, external_calls, args):
    restrict(ctx, target)
    binding = ctx.cluster._binding(target.id)
    external_calls[0].side_effect = tools
    with pytest.raises(PermissionError):
        ctx.cluster._kubectl_json(binding, ACTOR, *args)
    external_calls[0].assert_not_called()


@pytest.mark.parametrize('value', [None, [], '', ['*'], ['mission', 'mission'], ['a/b'], ['A']])
def test_invalid_present_namespace_scope_refused_before_io(ctx, target, external_calls, value):
    target.options['namespaces'] = value
    ctx.inventory.save()
    with pytest.raises(ScopeViolation):
        ctx.cluster.scan(actor=ACTOR)
    external_calls[0].assert_not_called()


@pytest.mark.parametrize('change', ['broaden', 'narrow', 'remove'])
@pytest.mark.parametrize('call_number', [1, 7])
def test_namespace_change_during_call_stops_publication(ctx, target, external_calls, change, call_number):
    restrict(ctx, target, ['mission'])
    process = external_calls[0]
    def mutate(argv, **kwargs):
        answer = tools(argv, **kwargs)
        if process.call_count != call_number:
            return answer
        if change == 'remove':
            target.options.pop('namespaces')
        else:
            target.options['namespaces'] = ['mission', 'ops'] if change == 'broaden' else ['ops']
        ctx.inventory.save()
        return answer
    process.side_effect = mutate
    with pytest.raises(ScopeViolation):
        ctx.cluster.scan(actor=ACTOR)
    assert process.call_count == call_number
    assert ctx.cluster.latest() is None
    assert ctx.store.current_findings() == []


@pytest.mark.parametrize('fault', ['foreign', 'kind', 'api', 'uid', 'duplicate', 'duplicate_uid', 'pagination', 'missing_items', 'duplicate_key'])
def test_bad_namespace_list_remains_unavailable_and_retains_prior(ctx, target, external_calls, fault):
    restrict(ctx, target, ['mission'])
    process = external_calls[0]
    process.side_effect = tools
    ctx.cluster.scan(actor=ACTOR)
    prior = {f.id for f in ctx.store.current_findings() if f.is_open}
    assert prior
    process.reset_mock()
    def broken(argv, **kwargs):
        answer = tools(argv, **kwargs)
        if 'deployments' not in argv:
            return answer
        doc = json.loads(answer.stdout)
        item = doc['items'][0]
        if fault == 'foreign':
            item['metadata']['namespace'] = 'outside'
        elif fault == 'kind':
            item['kind'] = 'Secret'
        elif fault == 'api':
            item['apiVersion'] = 'v1'
        elif fault == 'uid':
            item['metadata'].pop('uid')
        elif fault == 'duplicate':
            doc['items'].append(deepcopy(item))
        elif fault == 'duplicate_uid':
            other = deepcopy(item)
            other['metadata']['name'] = 'different-name'
            doc['items'].append(other)
        elif fault == 'pagination':
            doc['metadata']['continue'] = 'uncollected-page'
        elif fault == 'missing_items':
            doc.pop('items')
        elif fault == 'duplicate_key':
            answer.stdout = answer.stdout[:-1] + ',"items": []}'
            return answer
        return completed(argv, doc)
    process.side_effect = broken
    result = ctx.cluster.scan(actor=ACTOR)
    assert result['status'] == 'partial'
    assert result['survey']['collection_scope']['namespace_lists_complete'] is False
    assert result['survey']['errors']
    assert result['images'] == {}
    assert all(c.args[0][0] != 'trivy' for c in process.call_args_list)
    assert prior <= {f.id for f in ctx.store.current_findings() if f.is_open}


def test_verified_namespace_survey_keeps_account_credential(selected_cluster, monkeypatch):
    ctx, target, person, config, _, calls = selected_cluster
    restrict(ctx, target, ['mission'])
    def selected(argv, **kwargs):
        calls.append((argv, kwargs))
        return tools(argv, **kwargs)
    monkeypatch.setattr('subprocess.run', selected)
    with principal_scope(person):
        result = ctx.cluster.survey(actor=person.actor, target_id=target.id)
    assert result['target']['namespaces'] == ['mission']
    assert result['errors'] == []
    assert len(calls) == 6
    assert_selected(calls, config)
    assert all('-n' in argv and 'mission' in argv for argv, _ in calls)


def test_other_account_cannot_borrow_namespace_binding(selected_cluster):
    ctx, target, person, _, _, calls = selected_cluster
    restrict(ctx, target, ['mission'])
    other = Principal(person.issuer, 'other-account', 'Other account', kind='human',
                      roles=('admin', 'analyst'), expires_at=person.expires_at)
    with principal_scope(other), pytest.raises(PermissionError):
        ctx.cluster.survey(actor=other.actor, target_id=target.id)
    assert calls == []


def test_verified_namespace_revocation_stops_after_first_read(selected_cluster, monkeypatch):
    ctx, target, person, _, policy, calls = selected_cluster
    restrict(ctx, target, ['mission'])
    def revoked(argv, **kwargs):
        calls.append((argv, kwargs))
        answer = tools(argv, **kwargs)
        policy.write_text('{"version":1,"entries":[]}', encoding='utf-8')
        return answer
    monkeypatch.setattr('subprocess.run', revoked)
    with principal_scope(person), pytest.raises(PermissionError):
        ctx.cluster.survey(actor=person.actor, target_id=target.id)
    assert len(calls) == 1
    assert ctx.store.current_findings() == []


def test_denied_resource_is_visible_without_retrying_wider_access(ctx, target, external_calls):
    restrict(ctx, target, ['mission'])
    process = external_calls[0]
    def denied(argv, **kwargs):
        answer = tools(argv, **kwargs)
        if 'statefulsets' in argv:
            answer.returncode = 1
            answer.stderr = 'Forbidden: no list permission for statefulsets in mission'
        return answer
    process.side_effect = denied
    result = ctx.cluster.scan(actor=ACTOR)
    assert result['status'] == 'partial'
    assert any('statefulsets/mission' in error for error in result['errors'])
    assert result['namespaces'][0]['assessment_status'] == 'not_reviewed'
    assert any(f.is_open for f in ctx.store.current_findings())
    assert any(f.rule_id.startswith('cluster-survey:') for f in ctx.store.current_findings())
    assert len(process.call_args_list) == 7
    assert all('-A' not in c.args[0] and 'namespaces' not in c.args[0] for c in process.call_args_list)


def test_database_authority_denial_is_not_a_missing_database_result(ctx, target, external_calls):
    restrict(ctx, target, ['mission'])
    @contextmanager
    def denied():
        raise PermissionError('fixture authorization revoked')
        yield
    ctx.vulnerabilities.scan_context = denied
    with pytest.raises(PermissionError):
        ctx.cluster.scan(actor=ACTOR)
    external_calls[0].assert_not_called()
    assert ctx.store.current_findings() == []


@pytest.mark.parametrize('executable', ['range-kubectl', 'trivy'])
def test_os_execute_refusal_is_unavailable_and_sanitized(ctx, target, external_calls, executable):
    restrict(ctx, target, ['mission'])
    def denied(argv, **kwargs):
        if argv[0] == executable:
            raise PermissionError('private-fixture-executable-location')
        return tools(argv, **kwargs)
    external_calls[0].side_effect = denied
    result = ctx.cluster.scan(actor=ACTOR)
    assert result['status'] == 'partial'
    assert 'private-fixture-executable-location' not in json.dumps(result)
    assert any('could not execute (PermissionError)' in error for error in result['errors'])


@pytest.mark.parametrize('fault', ['byte_limit', 'count_limit', 'nonfinite', 'wrong_envelope'])
def test_namespace_response_bounds_and_envelope(fault, monkeypatch):
    from cyberthunder.cluster import scope
    doc = list_result('deployments', 'mission')
    if fault == 'byte_limit':
        monkeypatch.setattr(scope, 'MAX_LIST_BYTES', 4)
    elif fault == 'count_limit':
        monkeypatch.setattr(scope, 'MAX_LIST_ITEMS', 0)
    elif fault == 'wrong_envelope':
        doc['apiVersion'] = 'v99'
    payload = json.dumps(doc)
    if fault == 'nonfinite':
        payload = payload[:-1] + ',"untrusted": NaN}'
    with pytest.raises(ValueError):
        scope.decode_list(payload, 'deployments', 'mission')


@pytest.mark.parametrize('args', [('get', 'pods', '-A'), ('get', 'pods', '-n', 'outside')])
def test_review_selected_account_cannot_expand_namespace_reads(selected_cluster, monkeypatch, args):
    context, selected, person, _, _, calls = selected_cluster
    restrict(context, selected, ['mission'])
    # A backing tool that would allow the read must not expand the app's scope.
    def permissive(argv, **kwargs):
        calls.append((argv, kwargs))
        return completed(argv, {'items': []})
    monkeypatch.setattr('subprocess.run', permissive)
    with principal_scope(person), operation_scope('scan'):
        binding = context.cluster._binding(selected.id)
        with pytest.raises(PermissionError):
            context.cluster._kubectl_json(binding, person.actor, *args)
    assert calls == []


def test_review_broad_credential_never_scans_unselected_images(ctx, target, external_calls):
    restrict(ctx, target, ['mission'])
    def broad_account(argv, **kwargs):
        # The backing account would allow the legacy global survey, including ops.
        return tools(argv, **kwargs) if '-n' in argv else fake_tools(argv, **kwargs)
    external_calls[0].side_effect = broad_account
    result = ctx.cluster.scan(actor=ACTOR)
    requests = [c.args[0] for c in external_calls[0].call_args_list]
    assert result['status'] == 'done'
    assert {w['namespace'] for w in result['survey']['workloads']} == {'mission'}
    assert {p['namespace'] for p in result['namespaces']} == {'mission'}
    assert all('-A' not in argv and 'namespaces' not in argv for argv in requests)
    assert {argv[-1] for argv in requests if argv[0] == 'trivy'} == {APP_IMAGE}
    assert all(f.collection_provenance['workload']['namespace'] == 'mission'
               for f in ctx.store.current_findings() if f.is_open)


def test_review_verified_baseline_never_publishes_other_namespace(selected_cluster, monkeypatch):
    context, selected, person, _, _, calls = selected_cluster
    restrict(context, selected, ['mission'])
    @contextmanager
    def database():
        yield {'cache_dir': context.store.root / 'cache', 'generation': 'fixture-generation', 'state': 'ready'}
    monkeypatch.setattr(context.vulnerabilities, 'scan_context', database)
    def broad_account(argv, **kwargs):
        calls.append((argv, kwargs))
        return tools(argv, **kwargs) if '-n' in argv else fake_tools(argv, **kwargs)
    monkeypatch.setattr('subprocess.run', broad_account)
    with principal_scope(person):
        result = context.cluster.scan(actor=person.actor, target_id=selected.id)
    scanned = {argv[-1] for argv, _ in calls if argv[0] == 'trivy'}
    published = {f.collection_provenance['workload']['namespace']
                 for f in context.store.current_findings() if f.is_open}
    assert {'scanned_images': scanned, 'published_namespaces': published} == {
        'scanned_images': {APP_IMAGE}, 'published_namespaces': {'mission'}}
    assert result['status'] == 'done'
    assert all('-A' not in argv and 'namespaces' not in argv for argv, _ in calls)
    assert all(argv[argv.index('--image-src') + 1] == 'remote' for argv, _ in calls if argv[0] == 'trivy')


@pytest.mark.parametrize('namespaces', [None, ('mission', 'outside')])
def test_review_forged_binding_cannot_remove_namespace_limit(ctx, target, external_calls, namespaces):
    restrict(ctx, target, ['mission'])
    binding = replace(ctx.cluster._binding(target.id), namespaces=namespaces)
    with pytest.raises(ScopeViolation):
        ctx.cluster._kubectl_json(binding, ACTOR, 'get', 'pods', '-A')
    external_calls[0].assert_not_called()


def test_review_namespace_selection_comes_from_persisted_target(selected_cluster, monkeypatch):
    context, selected, person, _, _, calls = selected_cluster
    restrict(context, selected, ['mission'])
    selected.options['namespaces'] = ['cached-outside']  # deliberately unsaved
    def capture(argv, **kwargs):
        calls.append((argv, kwargs))
        return tools(argv, **kwargs)
    monkeypatch.setattr('subprocess.run', capture)
    with principal_scope(person):
        result = context.cluster.survey(actor=person.actor, target_id=selected.id)
    assert result['target']['namespaces'] == ['mission']
    assert len(calls) == 6
    assert all(argv[argv.index('-n') + 1] == 'mission' for argv, _ in calls)


def test_review_partial_rescan_clears_only_observed_namespace(ctx, target, external_calls):
    restrict(ctx, target)
    process = external_calls[0]
    process.side_effect = tools
    ctx.cluster.scan(actor=ACTOR)
    previous = {f.collection_provenance['workload']['namespace']: f.id
                for f in ctx.store.current_findings() if f.is_open}
    assert set(previous) == {'mission', 'ops'}
    def partial(argv, **kwargs):
        if argv[0] == 'trivy':
            return completed(argv, {'Results': [{'Target': 'fixture-image', 'Class': 'os-pkgs', 'Type': 'debian'}]})
        if 'deployments' in argv and 'ops' in argv:
            answer = completed(argv, {})
            answer.returncode, answer.stderr = 1, 'Forbidden: ops deployments'
            return answer
        return tools(argv, **kwargs)
    process.side_effect = partial
    result = ctx.cluster.scan(actor=ACTOR)
    assert result['status'] == 'partial'
    assert {f.id for f in ctx.store.current_findings() if f.is_open} == {previous['ops']}
    assert any(f.rule_id.startswith('cluster-survey:') for f in ctx.store.current_findings())


@pytest.mark.parametrize('filename', ['trivy-config.yaml', 'trivy-ignore', 'raw-report'])
def test_review_scanner_file_denial_is_unavailable(ctx, target, external_calls, monkeypatch, filename):
    restrict(ctx, target, ['mission'])
    external_calls[0].side_effect = tools
    original = Path.write_text
    def denied(path, *args, **kwargs):
        if path.name == filename or (filename == 'raw-report' and path.name.startswith('trivy_') and path.suffix == '.json'):
            raise PermissionError('private-fixture-workspace-path')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'write_text', denied)
    result = ctx.cluster.scan(actor=ACTOR)
    assert result['status'] == 'partial'
    assert 'private-fixture-workspace-path' not in json.dumps(result)
    assert any('workspace unavailable (PermissionError)' in error for error in result['errors'])
    findings = ctx.store.load_findings(result['id'])
    assert any(f.rule_id.startswith('cluster-coverage:') and f.status == 'error' for f in findings)
    assert all(f.collection_provenance['kubernetes_scope']['namespaces'] == ['mission'] for f in findings)


@pytest.mark.parametrize('error_type', [OSError, PermissionError])
def test_review_fatal_namespace_error_keeps_scope(ctx, target, external_calls, monkeypatch, error_type):
    restrict(ctx, target, ['mission'])
    external_calls[0].side_effect = tools
    original = Path.mkdir
    def failed(path, *args, **kwargs):
        if path.parent == ctx.cluster.root / 'baselines':
            raise error_type('private-fixture-run-path')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'mkdir', failed)
    with pytest.raises(RuntimeError, match='workspace unavailable'):
        ctx.cluster.scan(actor=ACTOR)
    findings = ctx.store.current_findings()
    assert len(findings) == 1 and findings[0].status == 'error'
    assert findings[0].collection_provenance['kubernetes_scope'] == {
        'mode': 'namespace', 'namespaces': ['mission'], 'cluster_complete': False, 'namespace_lists_complete': False}
    assert 'private-fixture-run-path' not in findings[0].evidence


@pytest.mark.parametrize('stage', ['execute', 'workspace'])
def test_review_revocation_overrides_scanner_os_denial(selected_cluster, monkeypatch, stage):
    context, selected, person, _, policy, calls = selected_cluster
    restrict(context, selected, ['mission'])
    @contextmanager
    def database():
        yield {'cache_dir': context.store.root / 'cache', 'generation': 'fixture-generation', 'state': 'ready'}
    monkeypatch.setattr(context.vulnerabilities, 'scan_context', database)
    original_mkdir = Path.mkdir
    def directory_denied(path, *args, **kwargs):
        if stage == 'workspace' and path.name == 'scanner-home':
            policy.write_text('{"version":1,"entries":[]}', encoding='utf-8')
            raise PermissionError('private-fixture-directory-path')
        return original_mkdir(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'mkdir', directory_denied)
    def revoked(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[0] == 'trivy':
            policy.write_text('{"version":1,"entries":[]}', encoding='utf-8')
            raise PermissionError('private-fixture-executable-path')
        return tools(argv, **kwargs)
    monkeypatch.setattr('subprocess.run', revoked)
    with principal_scope(person), pytest.raises(PermissionError):
        context.cluster.scan(actor=person.actor, target_id=selected.id)
    assert len(calls) == (7 if stage == 'execute' else 6)
    assert context.store.current_findings() == []
    assert context.store.read_json(context.cluster.root / 'latest.json') is None


@pytest.mark.parametrize('resource', list(TYPES))
@pytest.mark.parametrize('fault', ['container_name', 'foreign_namespace', 'missing_image', 'wrong_template'])
def test_review_all_workload_kinds_reject_malformed_identities(resource, fault):
    from cyberthunder.cluster.scope import decode_list
    kind, api = TYPES[resource]
    pod = {'containers': [{'name': 'nginx', 'image': APP_IMAGE}]}
    spec = pod if kind == 'Pod' else {'template': {'spec': pod}}
    if kind == 'CronJob':
        spec = {'jobTemplate': {'spec': spec}}
    item = {'apiVersion': api, 'kind': kind, 'metadata': {'name': 'valid-name', 'namespace': 'mission', 'uid': 'fixture-uid'}, 'spec': spec}
    if fault == 'container_name':
        pod['containers'][0]['name'] = '../../escape'
    elif fault == 'foreign_namespace':
        item['metadata']['namespace'] = 'outside'
    elif fault == 'missing_image':
        pod['containers'][0].pop('image')
    else:
        item['spec'] = {'unexpected': pod}
    doc = {'apiVersion': api, 'kind': kind + 'List', 'metadata': {}, 'items': [item]}
    with pytest.raises(ValueError):
        decode_list(json.dumps(doc), resource, 'mission')
