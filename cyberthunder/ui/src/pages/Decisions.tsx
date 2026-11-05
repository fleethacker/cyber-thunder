// Decisions: the queue of proposals waiting on a human (proposed, approved, applying), with keyboard
// control (j/k move, a approve, d deny, enter open finding), filters, sort, bulk approve/deny.
import { Alert, Button, Checkbox, Group, MultiSelect, SegmentedControl, Stack, Text, TextInput } from '@mantine/core';
import { useHotkeys } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import { IconRadar } from '@tabler/icons-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api, errorText } from '../api/client';
import type { ProposalPlus } from '../api/types';
import { ASSET_TYPES } from '../api/types';
import { ConfirmReasonModal } from '../components/ConfirmReasonModal';
import { Empty, ErrorBox, Loading, PageTitle } from '../components/common';
import { FindingDrawer } from '../components/FindingDrawer';
import { ProposalCard, type ProposalActions } from '../components/ProposalCard';
import { RollbackConfirmation } from '../components/RollbackConfirmation';
import { actorProblem } from '../components/ActorChip';
import { ageSeconds, severityRank } from '../lib/format';
import { isSuppressed } from '../lib/findingAssurance';
import { useAsync, useInterval, useLocalPref } from '../lib/hooks';
import { useAppState, useAuditListener } from '../state/AppState';
import { canRequestRollback, HISTORY_STATES, matchesProposalDates, matchesProposalSearch, newestProposalFirst, QUEUE_STATES } from '../lib/proposalHistory';

const SHOWN_AFTER_ACTION = ['applied', 'verified', 'failed', 'rolled_back', 'denied', 'cancelled'];

type Sort = 'severity' | 'host' | 'age';

export default function Decisions() {
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const requestedId = params.get('proposal');
  const { status, statusError, actor } = useAppState();
  const list = useAsync(async () => (await api.proposals()).proposals, []);
  const [touched, setTouched] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [focus, setFocus] = useState(0);
  const [drawer, setDrawer] = useState<string | null>(null);
  const [denyFor, setDenyFor] = useState<ProposalPlus[] | null>(null);
  const [denyError, setDenyError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [startingScan, setStartingScan] = useState(false);
  const [rollbackFor, setRollbackFor] = useState<ProposalPlus | null>(null);
  const [rollbackError, setRollbackError] = useState<string | null>(null);
  const [watchingRollback, setWatchingRollback] = useState<Set<string>>(new Set());
  const rollbackRequests = useRef(new Set<string>());
  const [pollErrors, setPollErrors] = useState<Record<string, string>>({});
  const inFlight = useRef(new Set<string>());
  const pollInFlight = useRef(new Set<string>());
  const [savedView, setSavedView] = useLocalPref<'queue' | 'history'>('ct.dec.view', 'queue');
  const view = requestedId ? 'history' : savedView === 'history' ? 'history' : 'queue';
  const [search, setSearch] = useLocalPref('ct.dec.search', '');
  const [from, setFrom] = useLocalPref('ct.dec.history.from', '');
  const [through, setThrough] = useLocalPref('ct.dec.history.through', '');
  const [historyState, setHistoryState] = useLocalPref<string[]>('ct.dec.history.state', []);

  const [fHost, setFHost] = useLocalPref<string[]>('ct.dec.host', []);
  const [fSev, setFSev] = useLocalPref<string[]>('ct.dec.sev', []);
  const [fType, setFType] = useLocalPref<string[]>('ct.dec.type', []);
  const [fState, setFState] = useLocalPref<string[]>('ct.dec.state', []);
  const [sort, setSort] = useLocalPref<Sort>('ct.dec.sort', 'severity');
  const [showDone, setShowDone] = useLocalPref<boolean>('ct.dec.done', true);
  const actionBlock = status?.kill.engaged ? 'Kill switch engaged. Changes are blocked.'
    : !status || statusError ? 'Waiting for current node status before enabling changes.'
    : actorProblem(actor) ? 'Set a valid acting name in the header before making changes.'
    : list.error ? 'Refresh the proposal list before making changes.' : null;
  const actionBlockRef = useRef(actionBlock);
  actionBlockRef.current = actionBlock;

  // merge one updated proposal into the list
  const setList = list.setData;
  const upsert = useCallback((p: ProposalPlus) => {
    setList((cur) => {
      const rows = cur ?? [];
      return rows.some((x) => x.id === p.id) ? rows.map((x) => (x.id === p.id ? p : x)) : [...rows, p];
    });
  }, [setList]);
  const upsertRef = useRef(upsert);
  upsertRef.current = upsert;

  // Proposal and review audit events refresh action availability; applying ones are polled below.
  const reloadTimer = useRef<number | undefined>(undefined);
  useAuditListener((r) => {
    if (!r.action.startsWith('proposal.') && r.action !== 'action.blocked' && r.action !== 'finding.review') return;
    const id = r.subject;
    if (id && rollbackRequests.current.has(id) && (r.action === 'proposal.rollback_error' || r.action === 'action.blocked')) {
      rollbackRequests.current.delete(id);
      setWatchingRollback((current) => { const next = new Set(current); next.delete(id); return next; });
      setActionError(`Rollback for ${id} was not confirmed: ${String(r.details.error ?? r.details.reason ?? r.details.note ?? r.outcome)}. Review the audit record before retrying.`);
    }
    window.clearTimeout(reloadTimer.current);
    reloadTimer.current = window.setTimeout(() => void list.reload(), 300);
  });
  useEffect(() => () => window.clearTimeout(reloadTimer.current), []);
  const applyingIds = (list.data ?? []).filter((p) => p.state === 'applying').map((p) => p.id);
  const pollIds = Array.from(new Set([...applyingIds, ...watchingRollback]));
  useInterval(() => {
    pollIds.forEach((id) => {
      if (pollInFlight.current.has(id)) return;
      pollInFlight.current.add(id);
      void api.proposal(id).then((p) => {
        upsertRef.current(p);
        setPollErrors((current) => { if (!(id in current)) return current; const next = { ...current }; delete next[id]; return next; });
      }).catch((e) => {
        setPollErrors((current) => ({ ...current, [id]: `Could not refresh proposal ${id}: ${errorText(e)}. Completion is not confirmed.` }));
      }).finally(() => pollInFlight.current.delete(id));
    });
  }, 1500, pollIds.length > 0);

  const all = list.data ?? [];
  const requested = all.find((p) => p.id === requestedId);
  const currentRollback = rollbackFor ? all.find((p) => p.id === rollbackFor.id) ?? rollbackFor : null;
  useEffect(() => {
    if (requested?.id) document.getElementById(`proposal-${requested.id}`)?.scrollIntoView({ block: 'start' });
  }, [requested?.id]);
  useEffect(() => {
    setWatchingRollback((current) => {
      const done = all.filter((p) => current.has(p.id) && (p.state === 'rolled_back' || p.state === 'failed'));
      if (!done.length) return current;
      done.forEach((p) => rollbackRequests.current.delete(p.id));
      return new Set([...current].filter((id) => !done.some((p) => p.id === id)));
    });
  }, [list.data]);
  const hosts = useMemo(() => Array.from(new Set(all.map((p) => p.target?.name ?? p.host))).sort(), [all]);
  const visible = useMemo(() => {
    const rows = all.filter((p) => p.id !== requestedId && (view === 'history' || QUEUE_STATES.includes(p.state) || (showDone && touched.has(p.id) && SHOWN_AFTER_ACTION.includes(p.state))));
    const states = view === 'history' ? historyState : fState;
    const filtered = rows.filter((p) =>
      (!fHost.length || fHost.includes(p.target?.name ?? p.host))
      && (!fSev.length || fSev.includes(p.severity))
      && (!fType.length || fType.includes(p.target?.asset_type ?? p.fix?.asset_type ?? ''))
      && (!states.length || states.includes(p.state))
      && matchesProposalSearch(p, search)
      && (view !== 'history' || matchesProposalDates(p, from, through)));
    const cmp: Record<Sort, (a: ProposalPlus, b: ProposalPlus) => number> = {
      severity: (a, b) => severityRank(b.severity) - severityRank(a.severity) || ageSeconds(b.created_at) - ageSeconds(a.created_at),
      host: (a, b) => (a.target?.name ?? a.host).localeCompare(b.target?.name ?? b.host) || severityRank(b.severity) - severityRank(a.severity),
      age: (a, b) => ageSeconds(b.created_at) - ageSeconds(a.created_at),
    };
    return filtered.sort(view === 'history' ? newestProposalFirst : cmp[sort]);
  }, [all, touched, showDone, fHost, fSev, fType, fState, sort, requestedId, view, historyState, search, from, through]);

  useEffect(() => {
    if (focus >= visible.length) setFocus(Math.max(0, visible.length - 1));
  }, [visible.length, focus]);

  const run = useCallback(async (p: ProposalPlus, fn: () => Promise<unknown>, ok: string) => {
    if (actionBlockRef.current || inFlight.current.has(p.id)) {
      setActionError(actionBlockRef.current ?? 'An action is already in progress for this proposal.');
      return false;
    }
    inFlight.current.add(p.id);
    setBusy((b) => new Set(b).add(p.id));
    setActionError(null);
    try {
      const res = await fn();
      setTouched((t) => new Set(t).add(p.id));
      if (res && typeof res === 'object' && 'finding_id' in res) upsertRef.current(res as ProposalPlus);
      else upsertRef.current(await api.proposal(p.id));
      notifications.show({ color: 'green', message: ok });
      return true;
    } catch (e) {
      setActionError(`${p.title}: ${errorText(e)}`);
      notifications.show({ color: 'red', title: 'Refused', message: errorText(e) });
      return false;
    } finally {
      inFlight.current.delete(p.id);
      setBusy((b) => { const n = new Set(b); n.delete(p.id); return n; });
    }
  }, []);

  const actions: ProposalActions = useMemo(() => ({
    approve: (p) => void run(p, () => api.approve(p.id), `Approved: ${p.title}`),
    deny: (p) => { setDenyError(null); setDenyFor([p]); },
    apply: (p) => {
      if (isSuppressed(p.finding?.review)) {
        setActionError(`Apply blocked by human review: ${p.finding?.review?.current?.reason || 'Review the current finding before applying.'}`);
        return;
      }
      void run(p, () => api.apply(p.id), `Applying: ${p.title}`);
    },
    rollback: (p) => {
      if (actionBlock || watchingRollback.has(p.id) || !canRequestRollback(p)) return;
      setRollbackError(null);
      setRollbackFor(p);
    },
    verify: (p) => void run(p, () => api.verify(p.id), `Verification recorded: ${p.title}`),
    openFinding: (id) => setDrawer(id),
  }), [run, actionBlock, watchingRollback]);

  const confirmRollback = async () => {
    if (!currentRollback || actionBlockRef.current || !canRequestRollback(currentRollback) || inFlight.current.has(currentRollback.id) || watchingRollback.has(currentRollback.id)) return;
    const p = currentRollback;
    setRollbackError(null);
    const accepted = await run(p, async () => {
      try {
        // Recheck the selected proposal before requesting a rollback of an older change.
        const latest = await api.proposal(p.id);
        upsert(latest);
        if (actionBlockRef.current) throw new Error(actionBlockRef.current);
        if (!canRequestRollback(latest)) throw new Error('This proposal is no longer applied or verified.');
        rollbackRequests.current.add(p.id);
        setWatchingRollback((current) => new Set(current).add(p.id));
        try { return await api.rollback(p.id); }
        catch (e) {
          rollbackRequests.current.delete(p.id);
          setWatchingRollback((current) => { const next = new Set(current); next.delete(p.id); return next; });
          throw e;
        }
      } catch (e) {
        setRollbackError(errorText(e));
        throw e;
      }
    }, `Rollback requested: ${p.title}. Completion is not yet confirmed.`);
    if (accepted) setRollbackFor(null);
    else setRollbackError((current) => current ?? 'Rollback was not confirmed. Review the request error and current proposal state before retrying.');
  };

  const confirmDeny = async (note: string) => {
    if (!denyFor) return;
    if (actionBlockRef.current) { setDenyError(actionBlockRef.current); return; }
    setDenyError(null);
    try {
      if (denyFor.length === 1) {
        const p = await api.deny(denyFor[0].id, note || undefined);
        upsert(p);
        setTouched((t) => new Set(t).add(p.id));
      } else {
        const res = await api.bulk('deny', denyFor.map((p) => p.id), note || undefined);
        reportBulk(res.results);
        setTouched((t) => { const n = new Set(t); denyFor.forEach((p) => n.add(p.id)); return n; });
        setSelected(new Set());
        await list.reload();
      }
      setDenyFor(null);
    } catch (e) {
      setDenyError(errorText(e));
    }
  };

  const bulkApprove = async () => {
    if (actionBlockRef.current) { setActionError(actionBlockRef.current); return; }
    const ids = visible.filter((p) => selected.has(p.id) && p.state === 'proposed').map((p) => p.id);
    if (!ids.length) return;
    try {
      const res = await api.bulk('approve', ids);
      reportBulk(res.results);
      setTouched((t) => { const n = new Set(t); ids.forEach((i) => n.add(i)); return n; });
      setSelected(new Set());
      await list.reload();
    } catch (e) {
      setActionError(errorText(e));
    }
  };

  const focused = visible[focus];
  const scrollTo = (i: number) => {
    const p = visible[i];
    if (p) document.getElementById(`proposal-${p.id}`)?.scrollIntoView({ block: 'nearest', behavior: 'auto' });
  };
  useHotkeys([
    ['j', () => setFocus((i) => { const n = Math.min(visible.length - 1, i + 1); scrollTo(n); return n; })],
    ['k', () => setFocus((i) => { const n = Math.max(0, i - 1); scrollTo(n); return n; })],
    // approve/deny keys are ignored while the deny modal or finding drawer is open, so a stray key
    // press there never acts on the card behind it
    ['a', () => { if (!actionBlock && !rollbackFor && !drawer && !denyFor && focused?.state === 'proposed') actions.approve(focused); }],
    ['d', () => { if (!actionBlock && !rollbackFor && !drawer && !denyFor && focused?.state === 'proposed') actions.deny(focused); }],
    ['Enter', () => { if (focused && !rollbackFor && !drawer && !denyFor) actions.openFinding(focused.finding_id); }],
    ['x', () => { if (focused?.state === 'proposed' && !rollbackFor && !drawer && !denyFor) toggleSel(focused.id, !selected.has(focused.id)); }],
  ]);

  const toggleSel = (id: string, v: boolean) => setSelected((s) => { const n = new Set(s); if (v) n.add(id); else n.delete(id); return n; });

  const startScan = async () => {
    setStartingScan(true);
    try {
      await api.startScan({});
      nav('/scans');
    } catch (e) {
      setActionError(errorText(e));
    } finally {
      setStartingScan(false);
    }
  };

  const pending = all.filter((p) => p.state === 'proposed').length;
  const selectable = visible.filter((p) => p.state === 'proposed');
  const selCount = selectable.filter((p) => selected.has(p.id)).length;
  const clearRequested = () => { const next = new URLSearchParams(params); next.delete('proposal'); setParams(next); };

  return (
    <Stack gap="md">
      <PageTitle
        title="Decisions"
        subtitle={`${pending} waiting for approval · keys: j/k move · a approve · d deny · enter detail · x select`}
        right={<Button variant="light" onClick={() => void list.reload()} loading={list.loading}>Refresh</Button>}
      />
      <SegmentedControl aria-label="Decision view" value={view} onChange={(value) => {
        setSavedView(value as 'queue' | 'history'); setSelected(new Set()); setFocus(0);
        if (requestedId) clearRequested();
      }} data={[{ value: 'queue', label: 'Active queue' }, { value: 'history', label: 'Changes / history' }]} />
      <Text size="sm" c="dimmed">{view === 'history' ? 'All recorded proposals, including older applied, verified, failed and rolled-back changes. Most recent activity first; this view remains available after reload.' : 'Proposals awaiting a decision or application. Completed changes are also available in Changes / history.'}</Text>
      <TextInput label="Search proposals" placeholder="Proposal ID, title, machine or actor" value={search} onChange={(e) => setSearch(e.currentTarget.value)} />

      <Group gap="sm" align="flex-end" wrap="wrap">
        <MultiSelect label="Host" data={hosts} value={fHost} onChange={setFHost} clearable searchable w={200} placeholder="All" />
        <MultiSelect label="Severity" data={[{ value: 'high', label: 'CAT I' }, { value: 'medium', label: 'CAT II' }, { value: 'low', label: 'CAT III' }, { value: 'info', label: 'Info' }]} value={fSev} onChange={setFSev} clearable w={180} placeholder="All" />
        <MultiSelect label="Asset type" data={ASSET_TYPES} value={fType} onChange={setFType} clearable w={200} placeholder="All" />
        <MultiSelect label="State" data={(view === 'history' ? HISTORY_STATES : QUEUE_STATES).map((value) => ({ value, label: value.replace(/_/g, ' ') }))}
          value={view === 'history' ? historyState : fState} onChange={view === 'history' ? setHistoryState : setFState} clearable w={200} placeholder="All" />
        {view === 'queue' && <Stack gap={2}>
          <Text size="sm" fw={500}>Sort</Text>
          <SegmentedControl value={sort} onChange={(v) => setSort(v as Sort)} data={[{ value: 'severity', label: 'Severity' }, { value: 'host', label: 'Host' }, { value: 'age', label: 'Age' }]} />
        </Stack>}
        {view === 'queue' && <Checkbox label="Keep this session's completed cards" checked={showDone} onChange={(e) => setShowDone(e.currentTarget.checked)} mb={8} />}
        {view === 'history' && <><TextInput type="date" label="Last activity from" value={from} onChange={(e) => setFrom(e.currentTarget.value)} />
          <TextInput type="date" label="Last activity through" value={through} onChange={(e) => setThrough(e.currentTarget.value)}
            error={!!from && !!through && from > through ? 'Choose an end date on or after the start date.' : undefined} /></>}
        <Button variant="subtle" onClick={() => { setFHost([]); setFSev([]); setFType([]); setFState([]); setHistoryState([]); setSearch(''); setFrom(''); setThrough(''); }}>Clear filters</Button>
      </Group>
      {view === 'history' && <Text size="xs" c="dimmed">Date filters use the last recorded activity in this browser's local timezone, inclusive of both dates.</Text>}
      {actionBlock && <Alert color="yellow">{actionBlock}</Alert>}
      {watchingRollback.size > 0 && <Alert color="blue" role="status">Rollback requested for {Array.from(watchingRollback).join(', ')}. Checking for completion; no new scan has been requested.</Alert>}
      {requestedId && <Alert color={requested ? 'blue' : 'yellow'} title="Selected proposal">
        <Stack gap="xs"><Text size="sm">{requested ? `${requested.id} is shown below regardless of saved filters. Its current state is ${requested.state.replace(/_/g, ' ')}.` : list.loading ? 'Loading the linked proposal…' : list.error ? 'The linked proposal could not be checked. Refresh to retry.' : `Proposal ${requestedId} was not found on this node.`}</Text>
          <Group><Button variant="light" size="xs" onClick={clearRequested}>Clear selected proposal</Button></Group></Stack>
      </Alert>}
      {requested && <ProposalCard p={requested} actions={actions} busy={busy.has(requested.id) || watchingRollback.has(requested.id)} actionsDisabled={!!actionBlock} focused />}

      {selectable.length > 0 && (
        <Group gap="sm">
          <Checkbox
            label={`Select proposed (${selectable.length})`}
            checked={selCount > 0 && selCount === selectable.length}
            indeterminate={selCount > 0 && selCount < selectable.length}
            onChange={(e) => setSelected(e.currentTarget.checked ? new Set(selectable.map((p) => p.id)) : new Set())}
          />
          <Button size="sm" color="green" disabled={!selCount || !!actionBlock} onClick={() => void bulkApprove()}>Approve selected ({selCount})</Button>
          <Button size="sm" color="red" variant="light" disabled={!selCount || !!actionBlock}
            onClick={() => { setDenyError(null); setDenyFor(visible.filter((p) => selected.has(p.id) && p.state === 'proposed')); }}>
            Deny selected
          </Button>
        </Group>
      )}

      {actionError && <ErrorBox error={actionError} />}
      {Object.entries(pollErrors).map(([id, error]) => <ErrorBox key={id} error={error} onRetry={() => {
        void api.proposal(id).then((p) => {
          upsert(p);
          setPollErrors((current) => { const next = { ...current }; delete next[id]; return next; });
        }).catch((e) => setPollErrors((current) => ({ ...current, [id]: errorText(e) })));
      }} />)}
      {list.data === undefined ? (
        list.error ? <ErrorBox error={list.error} onRetry={() => void list.reload()} /> : <Loading what="Loading the decision queue" />
      ) : (
        <>
          {list.error && <ErrorBox error={list.error} onRetry={() => void list.reload()} />}
          {visible.length === 0 ? (
            <Empty
              title={view === 'history' ? 'No other proposals match these filters' : 'Nothing waiting for a decision'}
              action={view === 'queue' ? <Button leftSection={<IconRadar size={18} />} loading={startingScan} onClick={() => void startScan()}>Start a scan</Button> : undefined}
            >
              {all.length ? 'Clear filters to see more proposals, or switch views.' : 'No proposals have been recorded on this node.'}
            </Empty>
          ) : (
            visible.map((p, i) => (
              <div key={p.id} onMouseDown={() => setFocus(i)}>
                <ProposalCard
                  p={p}
                  actions={actions}
                  busy={busy.has(p.id) || watchingRollback.has(p.id)}
                  actionsDisabled={!!actionBlock}
                  selected={selected.has(p.id)}
                  onSelect={p.state === 'proposed' ? (v) => toggleSel(p.id, v) : undefined}
                  focused={i === focus}
                />
              </div>
            ))
          )}
        </>
      )}

      <FindingDrawer findingId={drawer} onClose={() => setDrawer(null)} onProposed={upsert} onReviewed={() => void list.reload()} />
      <RollbackConfirmation proposal={currentRollback} busy={!!currentRollback && busy.has(currentRollback.id)}
        blockedReason={actionBlock} error={rollbackError} onConfirm={() => void confirmRollback()} onClose={() => setRollbackFor(null)} />
      <ConfirmReasonModal
        opened={!!denyFor}
        onClose={() => setDenyFor(null)}
        title={denyFor && denyFor.length > 1 ? `Deny ${denyFor.length} proposals` : 'Deny this fix'}
        body={denyFor && denyFor.length === 1 ? <Text size="sm">{denyFor[0].title} on {denyFor[0].target?.name ?? denyFor[0].host}</Text> : undefined}
        reasonLabel="Note"
        confirmLabel="Deny"
        confirmColor="red"
        error={denyError}
        onConfirm={(n) => void confirmDeny(n)}
      />
    </Stack>
  );
}

function reportBulk(results: { id: string; state?: string; error?: string }[]) {
  const errs = results.filter((r) => r.error);
  const ok = results.length - errs.length;
  notifications.show({
    color: errs.length ? 'orange' : 'green',
    title: `${ok} done${errs.length ? `, ${errs.length} refused` : ''}`,
    message: errs.length ? errs.map((e) => `${e.id}: ${e.error}`).join('\n') : 'Bulk action recorded in the audit trail',
  });
}
