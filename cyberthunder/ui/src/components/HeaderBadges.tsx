// Header indicators: audit chain, link, model. Each is its own small component so pages can reuse them.
import { Badge, Tooltip } from '@mantine/core';
import { IconCpu, IconLink, IconLinkOff, IconShieldCheck, IconShieldX } from '@tabler/icons-react';
import { short } from '../lib/format';
import { linkLabel, rateLabel } from '../lib/linkPresentation';
import { useAppState } from '../state/AppState';

export function ChainBadge() {
  const { verify, stream, status } = useAppState();
  if (status?.global_details === false) return <Badge color="gray" variant="light" size="lg">Chain: restricted</Badge>;
  if (!verify) return <Badge color="gray" variant="light" size="lg">Chain: unknown</Badge>;
  const streamNote = stream === 'open' ? 'live' : stream === 'connecting' ? 'connecting to stream' : 'stream reconnecting';
  if (verify.ok) {
    return (
      <Tooltip label={`head ${verify.head} (${streamNote})`} withArrow multiline maw={480}>
        <Badge color="green" variant="light" size="lg" leftSection={<IconShieldCheck size={14} />} tt="none">
          Chain verified · {verify.count} records · <span style={{ fontFamily: 'monospace' }}>{short(verify.head)}</span>
        </Badge>
      </Tooltip>
    );
  }
  return (
    <Tooltip label={verify.reason ?? 'verification failed'} withArrow multiline maw={480}>
      <Badge color="red" variant="filled" size="lg" leftSection={<IconShieldX size={14} />} tt="none">
        TAMPERED at #{verify.bad_seq ?? '?'}
      </Badge>
    </Tooltip>
  );
}

export function LinkBadge() {
  const { status } = useAppState();
  if (status?.global_details === false) return <Badge color="gray" variant="light" size="lg">Link and queue: restricted</Badge>;
  const link = status?.link;
  if (!link) return <Badge color="gray" variant="light" size="lg">Link: unknown</Badge>;
  const pending = status?.outbox?.pending;
  const queue = pending == null ? 'queue unknown' : `${pending} queued`;
  return (
    <Tooltip label={`${rateLabel(link)} · physical latency unknown · ${queue}`} withArrow>
      <Badge
        color={link.reachability === 'unknown' ? 'gray' : link.connected ? 'teal' : 'orange'}
        variant="light"
        size="lg"
        tt="none"
        leftSection={link.connected ? <IconLink size={14} /> : <IconLinkOff size={14} />}
      >
        {linkLabel(link)} · {queue}
      </Badge>
    </Tooltip>
  );
}

export function ModelBadge() {
  const { status } = useAppState();
  if (status?.global_details === false) return <Badge color="gray" variant="light" size="lg">Model: restricted</Badge>;
  const llm = status?.llm;
  if (!llm) return <Badge color="gray" variant="light" size="lg">Model: unknown</Badge>;
  const name = `${llm.backend}${llm.model ? `/${llm.model}` : ''}`;
  return (
    <Tooltip label={llm.detail ?? (llm.available ? 'model available' : 'model unavailable: template fallback')} withArrow multiline maw={400}>
      <Badge color={llm.available ? 'blue' : 'yellow'} variant="light" size="lg" tt="none" leftSection={<IconCpu size={14} />}>
        {name} · {llm.available ? 'available' : 'fallback'}
      </Badge>
    </Tooltip>
  );
}
