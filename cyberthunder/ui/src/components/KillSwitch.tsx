// Kill switch: always visible. Engaging asks for confirmation (reason optional); releasing needs a reason.
import { Button } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconHandStop, IconPlayerPlay } from '@tabler/icons-react';
import { useState } from 'react';
import { api, errorText } from '../api/client';
import { useAppState } from '../state/AppState';
import { ConfirmReasonModal } from './ConfirmReasonModal';

export function KillSwitch() {
  const { status, refresh, actor } = useAppState();
  const engaged = !!status?.kill.engaged;
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (reason: string) => {
    setBusy(true);
    setError(null);
    try {
      if (engaged) await api.killRelease(reason);
      else await api.killEngage(reason);
      notifications.show({ color: engaged ? 'green' : 'red', message: engaged ? 'Kill switch released' : 'Kill switch engaged: all changes blocked' });
      setOpen(false);
      await refresh();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Button
        color={engaged ? 'gray' : 'red'}
        variant={engaged ? 'white' : 'filled'}
        size="md"
        leftSection={engaged ? <IconPlayerPlay size={18} /> : <IconHandStop size={18} />}
        onClick={() => { setError(null); setOpen(true); }}
        aria-label={engaged ? 'Release kill switch' : 'Engage kill switch'}
      >
        {engaged ? 'Release' : 'KILL SWITCH'}
      </Button>
      <ConfirmReasonModal
        opened={open}
        onClose={() => setOpen(false)}
        title={engaged ? 'Release the kill switch' : 'Engage the kill switch'}
        body={engaged
          ? 'Releasing lets approved changes be applied again. A reason is required.'
          : `This halts the agent and blocks every apply and rollback until released. Recorded as ${actor || '(set your name first)'}.`}
        reasonRequired={engaged}
        confirmLabel={engaged ? 'Release' : 'Engage kill switch'}
        confirmColor={engaged ? 'green' : 'red'}
        busy={busy}
        error={error}
        onConfirm={(r) => void submit(r)}
      />
    </>
  );
}
