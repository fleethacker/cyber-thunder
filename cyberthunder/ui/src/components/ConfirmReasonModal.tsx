// Confirmation modal with an optional or required reason. Used for kill switch, deny with note,
// policy enable and scope changes (the only places the spec allows modals).
import { Button, Group, Modal, Stack, Text, Textarea } from '@mantine/core';
import { useEffect, useState, type ReactNode } from 'react';

export interface ConfirmReasonModalProps {
  opened: boolean;
  title: string;
  body?: ReactNode;
  reasonLabel?: string;
  reasonRequired?: boolean;
  /** placeholder override, e.g. where the reason is stored */
  reasonHint?: string;
  /** hide the reason box (plain confirmation) */
  noReason?: boolean;
  confirmLabel: string;
  confirmColor?: string;
  busy?: boolean;
  error?: string | null;
  onConfirm: (reason: string) => void;
  onClose: () => void;
}

export function ConfirmReasonModal(p: ConfirmReasonModalProps) {
  const [reason, setReason] = useState('');
  useEffect(() => {
    if (p.opened) setReason('');
  }, [p.opened]);
  const blocked = p.reasonRequired && !reason.trim();
  return (
    <Modal opened={p.opened} onClose={p.onClose} title={<Text fw={700}>{p.title}</Text>} centered>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!blocked) p.onConfirm(reason.trim());
        }}
      >
        <Stack>
          {p.body}
          {!p.noReason && <Textarea
            label={p.reasonLabel ?? 'Reason'}
            withAsterisk={p.reasonRequired}
            placeholder={p.reasonHint ?? (p.reasonRequired ? 'Required: recorded in the audit trail' : 'Optional: recorded in the audit trail')}
            value={reason}
            onChange={(e) => setReason(e.currentTarget.value)}
            autosize
            minRows={2}
            data-autofocus
          />}
          {p.error && <Text c="red" size="sm" ff="monospace">{p.error}</Text>}
          <Group justify="flex-end">
            <Button variant="default" onClick={p.onClose}>Cancel</Button>
            <Button type="submit" color={p.confirmColor ?? 'blue'} disabled={blocked} loading={p.busy}>{p.confirmLabel}</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
