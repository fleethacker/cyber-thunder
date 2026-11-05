// One pass over an enclave: receive, discover, scan, explain, propose, apply, report, roll back.
// Each step calls the workflow routes and shows the API detail when a step is refused.
import {
  Badge, Button, Checkbox, Group, Paper, Select, Stack, Table, Text, TextInput,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconPlayerPlay } from '@tabler/icons-react';
import { useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { api, errorText } from '../api/client';
import type { DiscoveredTarget, Explanation, FindingPlus, ProposalPlus, ScanRun, TargetOutcome, TargetReport } from '../api/types';
import { AssetIcon, Empty, ErrorBox, Loading, Mono, PageTitle, SeverityBadge, SimulatedBadge, StateBadge } from '../components/common';
import { useAsync, useInterval } from '../lib/hooks';

const RUNNING = new Set(['pending', 'running']);

function Step({ n, title, hint, children }: { n: number; title: string; hint: string; children: ReactNode }) {
  return (
    <Paper withBorder p="md" radius="md">
      <Stack gap="sm">
        <Group gap="sm" align="baseline">
          <Badge circle size="lg">{n}</Badge>
          <Text fw={700}>{title}</Text>
        </Group>
        <Text size="sm" c="dimmed">{hint}</Text>
        {children}
      </Stack>
    </Paper>
  );
}

function OutcomeTable({ results }: { results: Record<string, TargetOutcome> | null }) {
  if (!results) return null;
  const rows = Object.values(results);
  if (!rows.length) return null;
  return (
    <Table withTableBorder striped>
      <Table.Thead>
        <Table.Tr><Table.Th>Target</Table.Th><Table.Th>Result</Table.Th><Table.Th>Detail</Table.Th></Table.Tr>
      </Table.Thead>
      <Table.Tbody>
        {rows.map((row) => {
          const changes = [...(row.applied ?? []), ...(row.rolled_back ?? [])];
          return (
            <Table.Tr key={row.target}>
              <Table.Td><Mono>{row.target}</Mono></Table.Td>
              <Table.Td><Badge color={row.ok ? 'green' : 'yellow'} variant="light">{row.ok ? 'done' : 'nothing applied'}</Badge></Table.Td>
              <Table.Td>
                <Stack gap={2}>
                  {row.scan_id && <Text size="sm">Scan <Mono>{row.scan_id}</Mono> · {row.status} · {row.open ?? 0} open</Text>}
                  {changes.map((c) => (
                    <Text key={c.proposal_id} size="sm"><Mono>{c.proposal_id}</Mono> · {c.state} · version <Mono>{c.version}</Mono></Text>
                  ))}
                  {row.skipped.map((s) => <Text key={s.id + s.reason} size="sm" c="dimmed">{s.id}: {s.reason}</Text>)}
                  {row.errors.map((e) => <Text key={e} size="sm" c="red" ff="monospace">{e}</Text>)}
                </Stack>
              </Table.Td>
            </Table.Tr>
          );
        })}
      </Table.Tbody>
    </Table>
  );
}

export default function Mission() {
  const targets = useAsync(async () => (await api.targets()).targets, []);
  const received = useAsync(async () => {
    const [cves, stigs] = await Promise.all([api.receiveCves(), api.receiveStigs()]);
    return { cves: cves.cves, stigs: stigs.stigs };
  }, []);

  const [system, setSystem] = useState<string | null>(null);
  const [discovered, setDiscovered] = useState<DiscoveredTarget[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [scanTarget, setScanTarget] = useState<string | null>(null);
  const [scanRun, setScanRun] = useState<ScanRun | null>(null);
  const [scanOutcome, setScanOutcome] = useState<Record<string, TargetOutcome> | null>(null);
  const [findings, setFindings] = useState<FindingPlus[]>([]);
  const [checked, setChecked] = useState<string[]>([]);

  const [explanations, setExplanations] = useState<Explanation[] | null>(null);
  const [proposals, setProposals] = useState<ProposalPlus[] | null>(null);
  const [skippedPropose, setSkippedPropose] = useState<{ id: string; reason: string }[]>([]);

  const [applyTargets, setApplyTargets] = useState<string[]>([]);
  const [applyOutcome, setApplyOutcome] = useState<Record<string, TargetOutcome> | null>(null);
  const [versions, setVersions] = useState('');
  const [rollbackOutcome, setRollbackOutcome] = useState<Record<string, TargetOutcome> | null>(null);

  const [reportTarget, setReportTarget] = useState<string | null>(null);
  const [report, setReport] = useState<TargetReport | null>(null);

  const scanId = scanRun?.id ?? scanOutcome?.[scanTarget ?? '']?.scan_id;
  const scanning = !!scanRun && RUNNING.has(scanRun.status);
  useInterval(() => {
    if (!scanId) return;
    void api.scan(scanId).then((run) => {
      setScanRun(run);
      if (!RUNNING.has(run.status) && scanTarget) void loadFindings(scanTarget);
    }).catch((e) => setError(errorText(e)));
  }, 1500, scanning);

  const run = async (name: string, fn: () => Promise<void>) => {
    setBusy(name);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(null);
    }
  };

  const loadFindings = async (host: string) => {
    const page = await api.findings({ host, status: 'open', limit: 200 });
    setFindings(page.findings);
    setChecked(page.findings.filter((f) => f.proposal?.state === 'approved').map((f) => f.rule_version || f.rule_id));
  };

  const resultsBody = () => {
    if (scanOutcome) return scanOutcome && { target: scanTarget, results: scanOutcome };
    if (scanRun) return { scan_id: scanRun.id, target: scanTarget };
    return null;
  };

  const inventory = targets.data ?? [];
  const inScope = inventory.filter((t) => t.in_scope);
  const options = inScope.map((t) => ({ value: t.id, label: `${t.name} (${t.asset_type})` }));
  const workTargets = (discovered ?? inScope).filter((t) => t.in_scope);

  return (
    <Stack gap="md">
      <PageTitle
        title="Mission"
        subtitle="Receive what crossed the link, then discover, scan, explain, approve, apply, report, and roll back."
      />
      {error && <ErrorBox error={error} />}
      {targets.loading && !targets.data ? <Loading what="Loading inventory" /> : null}
      {targets.data && inScope.length === 0 && (
        <Empty title="No systems in scope" action={<Button component={Link} to="/assets">Open assets</Button>}>
          Add a target, or load the simulated range, before running this pass.
        </Empty>
      )}

      <Step n={1} title="Receive" hint="CVE bulletins and STIG releases already on this node.">
        {received.loading && !received.data ? <Loading what="Reading the inbox" /> : received.error ? <ErrorBox error={received.error} onRetry={() => void received.reload()} /> : (
          <Group align="flex-start" grow>
            <Stack gap={4}>
              <Text fw={600} size="sm">CVEs ({received.data?.cves.length ?? 0})</Text>
              {(received.data?.cves.length ?? 0) === 0 && <Text size="sm" c="dimmed">No bulletins received.</Text>}
              {received.data?.cves.map((c) => (
                <Text key={c.id ?? c.title} size="sm"><Mono>{c.id}</Mono> {c.title} {c.cves?.length ? `· ${c.cves.join(', ')}` : ''}</Text>
              ))}
            </Stack>
            <Stack gap={4}>
              <Text fw={600} size="sm">STIGs ({received.data?.stigs.length ?? 0})</Text>
              {(received.data?.stigs.length ?? 0) === 0 && <Text size="sm" c="dimmed">No STIG releases received.</Text>}
              {received.data?.stigs.map((s) => (
                <Text key={s.id} size="sm"><Mono>{s.benchmark_id ?? s.id}</Mono> {s.old_release ?? '—'} → {s.new_release ?? '—'}</Text>
              ))}
            </Stack>
          </Group>
        )}
      </Step>

      <Step n={2} title="Discover" hint="Read one in-scope system and list the targets that belong to it.">
        <Group align="flex-end">
          <Select label="System" data={options} value={system} onChange={setSystem} placeholder="Choose a system" searchable w={320} />
          <Button loading={busy === 'discover'} disabled={!system} leftSection={<IconPlayerPlay size={16} />}
            onClick={() => void run('discover', async () => {
              const res = await api.discoverSystem(system as string);
              setDiscovered(res.targets);
              const first = res.targets[0]?.id ?? null;
              setScanTarget(first);
              setApplyTargets(res.targets.map((t) => t.id));
              setReportTarget(first);
              notifications.show({ message: `${res.targets.length} target${res.targets.length === 1 ? '' : 's'} on ${system}` });
            })}>Discover</Button>
        </Group>
        {discovered && discovered.length === 0 && <Text size="sm" c="dimmed">Discovery returned no targets.</Text>}
        {discovered && discovered.length > 0 && (
          <Table withTableBorder striped>
            <Table.Thead><Table.Tr><Table.Th>Target</Table.Th><Table.Th>Type</Table.Th><Table.Th>Facts</Table.Th></Table.Tr></Table.Thead>
            <Table.Tbody>
              {discovered.map((t) => (
                <Table.Tr key={t.id}>
                  <Table.Td><Group gap="xs"><AssetIcon type={t.asset_type} /><Mono>{t.name}</Mono><SimulatedBadge simulated={t.simulated} /></Group></Table.Td>
                  <Table.Td>{t.asset_type}</Table.Td>
                  <Table.Td>{t.facts ? <Text size="sm">{String(t.facts.hostname ?? '')} {String(t.facts.os_name ?? '')}</Text> : <Text size="sm" c="dimmed">—</Text>}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Step>

      <Step n={3} title="Scan" hint="Scan one target. The run keeps going in the background; this page follows it.">
        <Group align="flex-end">
          <Select label="Target" data={workTargets.map((t) => ({ value: t.id, label: t.name }))} value={scanTarget} onChange={setScanTarget} w={320} />
          <Button loading={busy === 'scan'} disabled={!scanTarget} onClick={() => void run('scan', async () => {
            const res = await api.scanTarget(scanTarget as string);
            setScanOutcome(res.results);
            const id = res.results[scanTarget as string]?.scan_id;
            if (id) setScanRun(await api.scan(id));
            notifications.show({ message: `Scan started on ${scanTarget}` });
          })}>Scan</Button>
        </Group>
        {scanRun && (
          <Text size="sm">
            <Badge color={scanRun.status === 'done' ? 'green' : scanRun.status === 'error' ? 'red' : 'yellow'} variant="light">{scanRun.status}</Badge>
            {' '}<Mono>{scanRun.id}</Mono> · {scanRun.findings_count} findings
            {scanRun.error ? ` · ${scanRun.error}` : ''}
          </Text>
        )}
      </Step>

      <Step n={4} title="Explain and propose" hint="Turn this scan's open findings into cited explanations and library proposals. Nothing is applied.">
        <Group>
          <Button variant="light" loading={busy === 'explain'} disabled={!resultsBody()} onClick={() => void run('explain', async () => {
            const body = resultsBody();
            if (!body) return;
            const res = await api.explainResults(body);
            setExplanations(res.explanations);
            notifications.show({ message: res.truncated ? `${res.explanations.length} explanations, ${res.truncated} left for a later pass` : `${res.explanations.length} explanations` });
          })}>Explain</Button>
          <Button variant="light" loading={busy === 'propose'} disabled={!resultsBody()} onClick={() => void run('propose', async () => {
            const body = resultsBody();
            if (!body) return;
            const res = await api.proposeResults(body);
            setProposals(res.proposals);
            setSkippedPropose(res.skipped);
            if (scanTarget) await loadFindings(scanTarget);
            notifications.show({ message: `${res.proposals.length} proposals` });
          })}>Propose fixes</Button>
        </Group>
        {explanations && explanations.map((e) => (
          <Text key={e.finding_id} size="sm"><Mono>{e.finding_id}</Mono> — {e.risk}</Text>
        ))}
        {proposals && proposals.map((p) => (
          <Group key={p.id} gap="xs"><StateBadge state={p.state} /><Mono>{p.id}</Mono><Text size="sm">{p.title}</Text></Group>
        ))}
        {skippedPropose.map((s) => <Text key={s.id} size="sm" c="dimmed">{s.id}: {s.reason}</Text>)}
      </Step>

      <Step n={5} title="Apply checklist" hint="Only approved proposals that match a selected rule are applied. Approve them on Decisions first.">
        {findings.length === 0 && <Text size="sm" c="dimmed">Open findings show up here after the scan finishes.</Text>}
        <Stack gap={6}>
          {findings.map((f) => {
            const token = f.rule_version || f.rule_id;
            return (
              <Checkbox
                key={f.id}
                checked={checked.includes(token)}
                onChange={(ev) => setChecked((cur) => ev.currentTarget.checked ? [...cur, token] : cur.filter((x) => x !== token))}
                label={<Group gap="xs"><SeverityBadge severity={f.severity} size="sm" /><Mono>{token}</Mono><Text size="sm">{f.title}</Text>{f.proposal && <StateBadge state={f.proposal.state} />}</Group>}
              />
            );
          })}
        </Stack>
        <Group align="flex-end">
          <Select label="Targets" data={workTargets.map((t) => ({ value: t.id, label: t.name }))} value={applyTargets[0] ?? null}
            onChange={(v) => setApplyTargets(v ? [v] : [])} w={320} />
          <Button color="red" loading={busy === 'apply'} disabled={!applyTargets.length || !checked.length}
            onClick={() => void run('apply', async () => {
              const res = await api.applyChecklists(applyTargets, checked);
              setApplyOutcome(res.results);
              const ids = Object.values(res.results).flatMap((r) => (r.applied ?? []).map((c) => c.proposal_id));
              if (ids.length) setVersions(ids.join(', '));
              if (scanTarget) await loadFindings(scanTarget);
            })}>Apply</Button>
        </Group>
        <OutcomeTable results={applyOutcome} />
      </Step>

      <Step n={6} title="Report" hint="Write the per-target report, then read it back.">
        <Group align="flex-end">
          <Select label="Target" data={workTargets.map((t) => ({ value: t.id, label: t.name }))} value={reportTarget} onChange={setReportTarget} w={320} />
          <Button loading={busy === 'report'} disabled={!reportTarget} onClick={() => void run('report', async () => {
            setReport(await api.generateTargetReport(reportTarget as string));
          })}>Write report</Button>
          <Button variant="default" loading={busy === 'read-report'} disabled={!reportTarget} onClick={() => void run('read-report', async () => {
            setReport(await api.targetReport(reportTarget as string));
          })}>Read report</Button>
        </Group>
        {report && (
          <Text size="sm">
            {report.target.name}: {report.open} open of {report.findings} findings
            {report.checklist ? ' · checklist attached' : ''}
            {report.checklist_error ? ` · checklist: ${report.checklist_error}` : ''}
            {' '}· written by {report.generated_by}
          </Text>
        )}
      </Step>

      <Step n={7} title="Roll back" hint="Undo applied changes by proposal id, scan id, or benchmark release.">
        <Group align="flex-end">
          <TextInput label="Versions" value={versions} onChange={(e) => setVersions(e.currentTarget.value)} placeholder="proposal id, scan id, or release" w={420} />
          <Button color="orange" loading={busy === 'rollback'} disabled={!applyTargets.length || !versions.trim()}
            onClick={() => void run('rollback', async () => {
              const list = versions.split(',').map((v) => v.trim()).filter(Boolean);
              setRollbackOutcome((await api.rollbackVersions(applyTargets, list)).results);
              if (scanTarget) await loadFindings(scanTarget);
            })}>Roll back</Button>
        </Group>
        <OutcomeTable results={rollbackOutcome} />
      </Step>
    </Stack>
  );
}
