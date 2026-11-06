"""Independent publication boundaries using local processes and disposable state.

Unrelated findings may serialize when their locks collide. These tests require
evidence isolation and eventual progress after release, not a particular layout.
"""
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from contextlib import contextmanager
from dataclasses import replace
import gc
import multiprocessing
import os
from pathlib import Path
import sys
import threading
import time
import traceback
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cyberthunder.findings import lifecycle
from cyberthunder.findings.review import ReviewConflict, ReviewService
from cyberthunder.findings.schema import Finding, findings_doc
from cyberthunder.scan import ScanRun
from cyberthunder.scan_workers import ScanPublication
from tests.findings.test_reviews import context, decision, env, observation
from tests.findings.test_risk_acceptance import accept, revoke
from tests.engine.conftest import fake_adapter, make_ctx


MP = multiprocessing.get_context('spawn')


@pytest.fixture(autouse=True)
def collect_process_resources():
    yield
    # Collect completed process/event cycles outside resource-tracker registration.
    gc.collect()


@contextmanager
def process_call(function, *args):
    receive, send = MP.Pipe(duplex=False)
    process = MP.Process(target=function, args=(*args, send))
    process.start()
    send.close()
    try:
        yield process, receive
    finally:
        process.join(2)
        if process.is_alive():
            process.terminate()
            process.join(5)
        receive.close()
        process.close()


def result(process, receive, timeout=20):
    assert receive.poll(timeout), 'bounded publication process did not finish'
    value = receive.recv()
    process.join(5)
    assert process.exitcode == 0, value
    return value


def failure(exc):
    return {'error': type(exc).__name__, 'message': str(exc),
            'errno': getattr(exc, 'errno', None), 'traceback': traceback.format_exc()}


def hold_finding(root, backend, finding, entered, release, send):
    ctx = context(root, backend)
    try:
        with ReviewService(ctx).remediation_guard(Finding.from_dict(finding)):
            entered.set()
            assert release.wait(20), 'holder was not released'
        send.send({'released': True})
    except BaseException as exc:
        send.send(failure(exc))
    finally:
        ctx.store.close()
        send.close()


def publish_paused(root, backend, scan_id, rows, entered, release, inject_error, send):
    ctx = context(root, backend)
    path = ctx.store.scan_dir(scan_id) / 'findings.json'
    write = ctx.store.write_json

    def paused_write(destination, document):
        if destination == path:
            entered.set()
            assert release.wait(20), 'publisher was not released'
            if inject_error:
                raise OSError('injected observation write failure')
        return write(destination, document)

    ctx.store.write_json = paused_write
    try:
        ctx.store.save_findings(scan_id, [Finding.from_dict(row) for row in rows])
        send.send({'published': True})
    except BaseException as exc:
        send.send(failure(exc))
    finally:
        ctx.store.close()
        send.close()


def publish_on_signal(root, backend, scan_id, rows, start, started, send):
    ctx = context(root, backend)
    try:
        assert start.wait(20)
        started.set()
        ctx.store.save_findings(scan_id, [Finding.from_dict(row) for row in rows])
        send.send({'published': True})
    except BaseException as exc:
        send.send(failure(exc))
    finally:
        ctx.store.close()
        send.close()


def reentrant_publication(root, backend, row, send):
    ctx = context(root, backend)
    finding = Finding.from_dict(row)
    changed = replace(finding, evidence='changed in remediation callback')
    try:
        with ReviewService(ctx).remediation_guard(finding):
            started = time.monotonic()
            try:
                ctx.store.save_findings(finding.scan_id, [changed])
            except ReviewConflict:
                elapsed = time.monotonic() - started
            else:
                raise AssertionError('reentrant publication was admitted')
        assert ctx.store.load_findings(finding.scan_id)[0].evidence == finding.evidence
        ctx.store.save_findings(finding.scan_id, [changed])
        send.send({'refused_in_seconds': elapsed, 'retry_succeeded': True})
    except BaseException as exc:
        send.send(failure(exc))
    finally:
        ctx.store.close()
        send.close()


def bulk_terminal_removal(root, backend, send):
    """Exercise run publication removing 1,101 observations, not just adding rows."""
    ctx = None
    report = {'active_handles': 0, 'peak_handles': 0, 'error': None}
    try:
        if sys.platform == 'linux':
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            assert soft >= 1024
            resource.setrlimit(resource.RLIMIT_NOFILE, (1024, hard))
            report['nofile'] = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        ctx = context(root, backend)
        rows = [observation(source='native', rule_id=f'bulk-{index}', scan_id='old')
                for index in range(1101)]
        unrelated = observation(host='unrelated-host', source='native', rule_id='retained', scan_id='old')
        # The existing history is fixture state; the transition under test uses
        # the public store API with real lifecycle locks and review invalidation.
        ctx.store.docs.put('scans/old/run.json', {
            'id': 'old', 'status': 'done', 'started_at': '2026-11-05T10:00:00Z',
            'targets': [rows[0].host, unrelated.host],
        })
        ctx.store.docs.put('scans/old/findings.json', findings_doc([*rows, unrelated]))
        service = ReviewService(ctx)
        decision(service, rows[0])
        accept(service, rows[1])
        run = {'id': 'complete', 'status': 'running', 'started_at': '2026-11-05T11:00:00Z',
               'targets': [rows[0].host]}
        ctx.store.save_scan_run(run)
        ctx.store.save_findings(run['id'], [])
        original_open = Path.open

        @contextmanager
        def counted(path, args, kwargs):
            with original_open(path, *args, **kwargs) as handle:
                report['active_handles'] += 1
                report['peak_handles'] = max(report['peak_handles'], report['active_handles'])
                try:
                    yield handle
                finally:
                    report['active_handles'] -= 1

        def open_file(path, *args, **kwargs):
            if path.suffix == '.lock' and path.is_relative_to(ctx.store.root):
                return counted(path, args, kwargs)
            return original_open(path, *args, **kwargs)

        try:
            with patch.object(Path, 'open', open_file):
                ctx.store.save_scan_run(dict(run, status='done'))
        except BaseException as exc:
            report.update(failure(exc))
        # Even an exhausted descriptor budget must unwind acquired file locks.
        with lifecycle.review_coordination_lock(ctx.store.root):
            pass
        for finding in (rows[0], rows[len(rows) // 2], rows[-1], unrelated):
            with service.remediation_guard(finding):
                pass
        report['locks_reacquired'] = True
        current_ids = [f.id for f in ctx.store.current_findings()]
        report['current_count'] = len(current_ids)
        report['current_ids'] = current_ids[:3]
        report['unrelated_id'] = unrelated.id
        report['review'] = service.summary(rows[0])
        report['risk'] = service.summary(rows[1])
        report['run_status'] = ctx.store.load_scan_run(run['id'])['status']
        report['audit_valid'] = ctx.audit.verify().ok
    except BaseException as exc:
        report.update(failure(exc))
    finally:
        if ctx is not None:
            ctx.store.close()
        send.send(report)
        send.close()


def test_terminal_removal_over_1100_observations_fits_descriptor_budget(state_dir, record_property):
    backend = os.environ['CT_STATE_BACKEND']
    with process_call(bulk_terminal_removal, str(state_dir), backend) as child:
        report = result(*child, timeout=45)
    record_property('descriptor_report', repr(report))
    assert report['active_handles'] == 0 and report.get('locks_reacquired'), report
    assert report['error'] is None, report
    # Leave 64 descriptors for the interpreter, storage and audit under nofile=1024.
    # This checks capacity without fixing the number or identity of lock stripes.
    assert 0 < report['peak_handles'] <= 960, report
    if sys.platform == 'linux':
        assert report['nofile'] == 1024
    assert report['run_status'] == 'done'
    assert report['current_count'] == 1 and report['current_ids'] == [report['unrelated_id']]
    assert report['review']['revision'] == report['risk']['revision'] == 2
    assert not report['review']['active'] and report['risk']['risk_acceptance_status'] == 'reopened'
    assert report['audit_valid']


def test_authority_callback_rechecks_after_another_process_releases_guard(env):
    ctx, service, finding = env
    before = decision(service, finding)
    entered, release = MP.Event(), MP.Event()
    revoked, started = threading.Event(), threading.Event()
    callbacks = []
    publication = ScanPublication(SimpleNamespace(ctx=ctx), ScanRun(id='scan-1', targets=[finding.host]))

    def authority():
        callbacks.append(True)
        if revoked.is_set():
            raise PermissionError('publication authority revoked during lock wait')

    publication.guard = authority

    def publish():
        started.set()
        publication.store.save_findings('scan-1', [replace(finding, evidence='changed observation')])

    with process_call(hold_finding, str(ctx.store.root), ctx.store.backend_name,
                      finding.to_dict(), entered, release) as child:
        try:
            assert entered.wait(10)
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(publish)
                try:
                    assert started.wait(5)
                    with pytest.raises(FutureTimeout):
                        pending.result(timeout=0.15)
                    revoked.set()
                finally:
                    release.set()
                with pytest.raises(PermissionError, match='authority revoked'):
                    pending.result(timeout=10)
        finally:
            release.set()
        assert result(*child) == {'released': True}
    assert callbacks
    assert ctx.store.load_findings('scan-1')[0].to_dict() == finding.to_dict()
    assert service.history(finding) == before
    # A failure must release publication and finding locks for the next valid writer.
    publication.guard = lambda: None
    publication.store.save_findings('scan-1', [replace(finding, evidence='valid later observation')])
    assert service.summary(finding)['revision'] == 2


@pytest.mark.parametrize('existing', ['none', 'review', 'risk'])
@pytest.mark.parametrize('inject_error', [False, True])
def test_paused_publication_excludes_review_and_remediation_until_unwind(env, existing, inject_error):
    ctx, service, finding = env
    if existing == 'review':
        decision(service, finding)
    elif existing == 'risk':
        accept(service, finding)
    summary = service.summary(finding)
    entered, release = MP.Event(), MP.Event()
    changed = replace(finding, evidence='new scanner evidence')
    with process_call(publish_paused, str(ctx.store.root), ctx.store.backend_name, 'scan-1',
                      [changed.to_dict()], entered, release, inject_error) as child:
        try:
            assert entered.wait(10)
            assert ctx.store.load_findings('scan-1')[0].evidence == finding.evidence
            with pytest.raises(ReviewConflict):
                with service.remediation_guard(finding):
                    pytest.fail('remediation entered during changing publication')
            with pytest.raises(ReviewConflict):
                if existing == 'risk':
                    revoke(service, finding)
                else:
                    decision(service, finding, disposition='confirmed', expires_at=None)
        finally:
            release.set()
        report = result(*child)
    if inject_error:
        assert report['error'] == 'OSError', report
        assert ctx.store.load_findings('scan-1')[0].evidence == finding.evidence
        # Durable invalidations may conservatively precede an interrupted write.
        # Retrying must neither lose that ledger nor reactivate an old decision.
        ctx.store.save_findings('scan-1', [changed])
    else:
        assert report == {'published': True}
    with service.remediation_guard(changed):
        assert ctx.store.current_findings()[0].evidence == changed.evidence
    after = service.summary(changed)
    assert not after['active']
    if existing != 'none':
        assert after['revision'] == summary['revision'] + 1
    with pytest.raises(ReviewConflict):
        decision(service, finding, expected_revision=summary['revision'],
                 evidence_fingerprint=summary['evidence_fingerprint'])
    fresh = accept(service, changed) if existing == 'risk' else decision(service, changed)
    assert fresh['active'] and fresh['revision'] == after['revision'] + 1


def test_unrelated_publication_preserves_held_risk_even_when_locks_serialize(env):
    ctx, service, finding = env
    before = accept(service, finding)
    unrelated = observation(rule_id='independent-rule', scan_id='other')
    ctx.store.save_scan_run({'id': 'other', 'status': 'running', 'trigger': 'verify',
                             'targets': [unrelated.host], 'started_at': '2026-11-05T11:00:00Z'})
    entered, release = MP.Event(), MP.Event()
    with process_call(hold_finding, str(ctx.store.root), ctx.store.backend_name,
                      finding.to_dict(), entered, release) as child:
        try:
            assert entered.wait(10)
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(ctx.store.save_findings, 'other', [unrelated])
                # Completion before release and bounded collision serialization are
                # both permitted. Neither can reinterpret the held observation.
                try:
                    assert service.history(finding) == before
                finally:
                    release.set()
                pending.result(timeout=10)
        finally:
            release.set()
        assert result(*child) == {'released': True}
    assert service.history(finding) == before
    assert {f.id for f in ctx.store.current_findings()} == {finding.id, unrelated.id}


def test_reentrant_changing_publication_fails_without_waiting_or_leaking(env):
    ctx, service, finding = env
    # The parent watchdog kills a broken child instead of hanging the test runner.
    with process_call(reentrant_publication, str(ctx.store.root), ctx.store.backend_name,
                      finding.to_dict()) as child:
        report = result(*child)
    assert report.get('retry_succeeded') and report['refused_in_seconds'] < 2, report


def test_actual_remediation_apply_excludes_a_different_process_publisher(make_ctx, fake_adapter, monkeypatch):
    from cyberthunder.control.approvals import ProposalState
    from tests.engine import fakes
    from tests.engine.test_engine import SAILOR, scan

    ctx = make_ctx(auto_propose=False)
    finding = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    proposal = ctx.engine.propose(finding)
    ctx.gate.approve(proposal.id, SAILOR)
    rows = [replace(row, evidence='concurrent scanner change').to_dict() if row.id == finding.id else row.to_dict()
            for row in ctx.store.load_findings(finding.scan_id)]
    start, started = MP.Event(), MP.Event()
    apply = fake_adapter.apply
    applied = []
    try:
        with process_call(publish_on_signal, str(ctx.store.root), ctx.store.backend_name,
                          finding.scan_id, rows, start, started) as child:
            process, receive = child

            def apply_while_publication_waits(*args, **kwargs):
                start.set()
                assert started.wait(10)
                assert not receive.poll(0.25), 'publication changed evidence during apply'
                assert ctx.store.get_finding(finding.id).evidence == finding.evidence
                with pytest.raises(ReviewConflict):
                    accept(ReviewService(ctx), finding)
                applied.append(True)
                return apply(*args, **kwargs)

            monkeypatch.setattr(fake_adapter, 'apply', apply_while_publication_waits)
            try:
                assert ctx.engine.execute(proposal.id, actor=SAILOR).state == ProposalState.VERIFIED
            finally:
                start.set()
            assert result(process, receive) == {'published': True}
        assert applied == [True]
        assert ctx.store.get_finding(finding.id).evidence == 'concurrent scanner change'
        assert not ReviewService(ctx).summary(finding)['remediation_held']
    finally:
        assert ctx.close(5)
