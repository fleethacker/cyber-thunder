// Decisions: the queue of proposals waiting on a human (proposed, approved, applying), with keyboard
// control (j/k move, a approve, d deny, enter open finding), filters, sort, bulk approve/deny.
import { Button, Checkbox, Group, MultiSelect, SegmentedControl, Stack, Text } from '@mantine/core';
import { useHotkeys } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import { IconRadar } from '@tabler/icons-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, errorText } from '../api/client';
import type { ProposalPlus } from '../api/types';
import { ASSET_TYPES } from '../api/types';
import { ConfirmReasonModal } from '../components/ConfirmReasonModal';
import { Empty, ErrorBox, Loading, PageTitle } from '../components/common';
import { FindingDrawer } from '../components/FindingDrawer';
import { ProposalCard, type ProposalActions } from '../components/ProposalCard';
import { ageSeconds, severityRank } from '../lib/format';
import { useAsync, useInterval, useLocalPref } from '../lib/hooks';
import { useAuditListener } from '../state/AppState';

const QUEUE_STATES = ['proposed', 'approved', 'applying'];
const SHOWN_AFTER_ACTION = ['applied', 'verified', 'failed', 'rolled_back', 'denied', 'cancelled'];

type Sort = 'severity' | 'host' | 'age';

export default function Decisions() {
  const nav = useNavigate();
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

  const [fHost, setFHost] = useLocalPref<string[]>('ct.dec.host', []);
  const [fSev, setFSev] = useLocalPref<string[]>('ct.dec.sev', []);
  const [fType, setFType] = useLocalPref<string[]>('ct.dec.type', []);
  const [fState, setFState] = useLocalPref<string[]>('ct.dec.state', []);
  const [sort, setSort] = useLocalPref<Sort>('ct.dec.sort', 'severity');
  const [showDone, setShowDone] = useLocalPref<boolean>('ct.dec.done', true);

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

  // live: any proposal.* audit event reloads the list (debounced); applying ones are polled below
  const reloadTimer = useRef<number | undefined>(undefined);
  useAuditListener((r) => {
    if (!r.action.startsWith('proposal.') && r.action !== 'action.blocked') return;
    window.clearTimeout(reloadTimer.current);
    reloadTimer.current = window.setTimeout(() => void list.reload(), 300);
  });
  const applyingIds = (list.data ?? []).filter((p) => p.state === 'applying').map((p) => p.id);
  useInterval(() => {
    applyingIds.forEach((id) => api.proposal(id).then((p) => upsertRef.current(p)).catch(() => undefined));
  }, 1000, applyingIds.length > 0);

  const all = list.data ?? [];
  const hosts = useMemo(() => Array.from(new Set(all.map((p) => p.target?.name ?? p.host))).sort(), [all]);
  const visible = useMemo(() => {
    const rows = all.filter((p) => QUEUE_STATES.includes(p.state) || (showDone && touched.has(p.id) && SHOWN_AFTER_ACTION.includes(p.state)));
    const filtered = rows.filter((p) =>
      (!fHost.length || fHost.includes(p.target?.name ?? p.host))
      && (!fSev.length || fSev.includes(p.severity))
      && (!fType.length || fType.includes(p.target?.asset_type ?? p.fix?.asset_type ?? ''))
      && (!fState.length || fState.includes(p.state)));
    const cmp: Record<Sort, (a: ProposalPlus, b: ProposalPlus) => number> = {
      severity: (a, b) => severityRank(b.severity) - severityRank(a.severity) || ageSeconds(b.created_at) - ageSeconds(a.created_at),
      host: (a, b) => (a.target?.name ?? a.host).localeCompare(b.target?.name ?? b.host) || severityRank(b.severity) - severityRank(a.severity),
      age: (a, b) => ageSeconds(b.created_at) - ageSeconds(a.created_at),
    };
    return filtered.sort(cmp[sort]);
  }, [all, touched, showDone, fHost, fSev, fType, fState, sort]);

  useEffect(() => {
    if (focus >= visible.length) setFocus(Math.max(0, visible.length - 1));
  }, [visible.length, focus]);

  const run = useCallback(async (p: ProposalPlus, fn: () => Promise<unknown>, ok: string) => {
    setBusy((b) => new Set(b).add(p.id));
    setActionError(null);
    try {
      const res = await fn();
      setTouched((t) => new Set(t).add(p.id));
      if (res && typeof res === 'object' && 'finding_id' in res) upsertRef.current(res as ProposalPlus);
      else upsertRef.current(await api.proposal(p.id));
      notifications.show({ color: 'green', message: ok });
    } catch (e) {
      setActionError(`${p.title}: ${errorText(e)}`);
      notifications.show({ color: 'red', title: 'Refused', message: errorText(e) });
    } finally {
      setBusy((b) => { const n = new Set(b); n.delete(p.id); return n; });
    }
  }, []);

  const actions: ProposalActions = useMemo(() => ({
    approve: (p) => void run(p, () => api.approve(p.id), `Approved: ${p.title}`),
    deny: (p) => { setDenyError(null); setDenyFor([p]); },
    apply: (p) => void run(p, () => api.apply(p.id), `Applying: ${p.title}`),
    rollback: (p) => void run(p, () => api.rollback(p.id), `Rollback started: ${p.title}`),
    verify: (p) => void run(p, () => api.verify(p.id), `Verification recorded: ${p.title}`),
    openFinding: (id) => setDrawer(id),
  }), [run]);

  const confirmDeny = async (note: string) => {
    if (!denyFor) return;
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
    ['a', () => { if (!drawer && !denyFor && focused?.state === 'proposed') actions.approve(focused); }],
    ['d', () => { if (!drawer && !denyFor && focused?.state === 'proposed') actions.deny(focused); }],
    ['Enter', () => { if (focused && !drawer && !denyFor) actions.openFinding(focused.finding_id); }],
    ['x', () => { if (focused) toggleSel(focused.id, !selected.has(focused.id)); }],
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
  const selCount = visible.filter((p) => selected.has(p.id)).length;

  return (
    <Stack gap="md">
      <PageTitle
        title="Decisions"
        subtitle={`${pending} waiting for approval · keys: j/k move · a approve · d deny · enter detail · x select`}
        right={<Button variant="light" onClick={() => void list.reload()} loading={list.loading}>Refresh</Button>}
      />

      <Group gap="sm" align="flex-end" wrap="wrap">
        <MultiSelect label="Host" data={hosts} value={fHost} onChange={setFHost} clearable searchable w={200} placeholder="All" />
        <MultiSelect label="Severity" data={[{ value: 'high', label: 'CAT I' }, { value: 'medium', label: 'CAT II' }, { value: 'low', label: 'CAT III' }, { value: 'info', label: 'Info' }]} value={fSev} onChange={setFSev} clearable w={180} placeholder="All" />
        <MultiSelect label="Asset type" data={ASSET_TYPES} value={fType} onChange={setFType} clearable w={200} placeholder="All" />
        <MultiSelect label="State" data={QUEUE_STATES} value={fState} onChange={setFState} clearable w={200} placeholder="All" />
        <Stack gap={2}>
          <Text size="sm" fw={500}>Sort</Text>
          <SegmentedControl value={sort} onChange={(v) => setSort(v as Sort)} data={[{ value: 'severity', label: 'Severity' }, { value: 'host', label: 'Host' }, { value: 'age', label: 'Age' }]} />
        </Stack>
        <Checkbox label="Keep cards I acted on" checked={showDone} onChange={(e) => setShowDone(e.currentTarget.checked)} mb={8} />
      </Group>

      {visible.length > 0 && (
        <Group gap="sm">
          <Checkbox
            label={`Select all (${visible.length})`}
            checked={selCount > 0 && selCount === visible.length}
            indeterminate={selCount > 0 && selCount < visible.length}
            onChange={(e) => setSelected(e.currentTarget.checked ? new Set(visible.map((p) => p.id)) : new Set())}
          />
          <Button size="sm" color="green" disabled={!selCount} onClick={() => void bulkApprove()}>Approve selected ({selCount})</Button>
          <Button size="sm" color="red" variant="light" disabled={!selCount}
            onClick={() => { setDenyError(null); setDenyFor(visible.filter((p) => selected.has(p.id) && p.state === 'proposed')); }}>
            Deny selected
          </Button>
        </Group>
      )}

      {actionError && <ErrorBox error={actionError} />}
      {list.data === undefined ? (
        list.error ? <ErrorBox error={list.error} onRetry={() => void list.reload()} /> : <Loading what="Loading the decision queue" />
      ) : (
        <>
          {list.error && <ErrorBox error={list.error} onRetry={() => void list.reload()} />}
          {visible.length === 0 ? (
            <Empty
              title="Nothing waiting for a decision"
              action={<Button leftSection={<IconRadar size={18} />} loading={startingScan} onClick={() => void startScan()}>Start a scan</Button>}
            >
              {all.length ? 'Filters may be hiding some proposals.' : 'Scan the in-scope assets; fixes for open findings will be proposed here for your approval.'}
            </Empty>
          ) : (
            visible.map((p, i) => (
              <div key={p.id} onMouseDown={() => setFocus(i)}>
                <ProposalCard
                  p={p}
                  actions={actions}
                  busy={busy.has(p.id)}
                  selected={selected.has(p.id)}
                  onSelect={p.state === 'proposed' ? (v) => toggleSel(p.id, v) : undefined}
                  focused={i === focus}
                />
              </div>
            ))
          )}
        </>
      )}

      <FindingDrawer findingId={drawer} onClose={() => setDrawer(null)} onProposed={upsert} />
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
