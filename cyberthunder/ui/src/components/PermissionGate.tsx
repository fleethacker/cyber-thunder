import { Alert, Button, Group, Modal, Stack, Text, Tooltip, VisuallyHidden, type ButtonProps } from '@mantine/core';
import { cloneElement, createContext, useCallback, useContext, useId, useRef, type ComponentPropsWithoutRef, type ReactElement, type ReactNode } from 'react';
import { ConfirmReasonModal, type ConfirmReasonModalProps } from './ConfirmReasonModal';

export type PermissionRequirement = string | readonly string[];
export type CanAction = (action: string) => boolean;
const Context = createContext<CanAction | null>(null);

/** The identity owner supplies can(action). This layer neither assigns roles nor grants target access. */
export function PermissionProvider({ can, children }: { can: CanAction; children: ReactNode }) {
  return <Context.Provider value={can}>{children}</Context.Provider>;
}

/** Explicit permissions only; development-mode behavior belongs to the identity owner. */
export function rolePermits(permissions: readonly string[] | null | undefined, action: string): boolean {
  return Array.isArray(permissions) && permissions.includes(action);
}

const LABELS: Record<string, string> = {
  approve: 'approve changes', deny: 'deny changes', apply: 'apply changes', rollback: 'roll back changes',
  verify: 'verify changes', review: 'record reviews', plan: 'request change assessments or previews',
  scan: 'start scans', discover: 'collect asset facts', propose: 'propose fixes', explain: 'generate explanations',
  admin: 'manage inventory and configuration', policy: 'change standing approval policy',
  'kill.engage': 'engage the kill switch', 'kill.release': 'release the kill switch', read: 'read this information',
};

export function usePermissions() {
  const context = useContext(Context);
  const source = useRef(context);
  source.current = context;
  const can = useCallback((requirement: PermissionRequirement): boolean => {
    const actions = typeof requirement === 'string' ? [requirement] : requirement;
    if (!source.current || !actions.length) return false;
    try { return actions.every((action) => source.current!(action) === true); }
    catch { return false; }
  }, []);
  const reason = useCallback((requirement: PermissionRequirement): string | null => {
    if (can(requirement)) return null;
    if (!source.current) return 'Account permissions are unavailable. Refresh sign-in before making changes.';
    const actions = typeof requirement === 'string' ? [requirement] : requirement;
    const action = actions.find((value) => !can(value));
    return action ? `Your account cannot ${LABELS[action] ?? 'perform this action'} (${action} permission required).`
      : 'This action is unavailable for your account.';
  }, [can]);
  return { can, reason };
}

type Control = { id?: string; disabled?: boolean; 'aria-describedby'?: string };

/** A disabled native control plus a keyboard-focusable explanation; color alone never conveys denial. */
export function PermissionGate({ allowed, reason, children }: {
  allowed: boolean; reason: string; children: ReactElement<Control>;
}) {
  const id = useId();
  if (allowed) return children;
  const controlId = children.props.id ?? `${id}-control`;
  const descriptionId = `${id}-reason`;
  return <>
    <Tooltip label={reason} withArrow events={{ hover: true, focus: true, touch: true }}>
      <span role="group" tabIndex={0} aria-disabled="true" aria-labelledby={controlId} aria-describedby={descriptionId}
        style={{ display: 'inline-flex', verticalAlign: 'middle' }}
        onClickCapture={(event) => { event.preventDefault(); event.stopPropagation(); }}>
        {cloneElement(children, { id: controlId, disabled: true,
          'aria-describedby': [children.props['aria-describedby'], descriptionId].filter(Boolean).join(' ') })}
      </span>
    </Tooltip>
    <VisuallyHidden id={descriptionId}>{reason}</VisuallyHidden>
  </>;
}

type PermissionButtonProps = ButtonProps & Omit<ComponentPropsWithoutRef<'button'>, keyof ButtonProps> & {
  action?: PermissionRequirement;
  allowed?: boolean;
  reason?: string | null;
};

export function PermissionButton({ action, allowed, reason, disabled, loading, onClick, ...props }: PermissionButtonProps) {
  const permission = usePermissions();
  const permitted = allowed ?? (action ? permission.can(action) : false);
  const why = reason || (action ? permission.reason(action) : null) || 'This action is unavailable for your account.';
  return <PermissionGate allowed={permitted} reason={why}>
    <Button {...props} loading={loading} disabled={disabled || !permitted} onClick={(event) => {
      if (disabled || loading || !(allowed ?? (action ? permission.can(action) : false))) { event.preventDefault(); return; }
      onClick?.(event);
    }} />
  </PermissionGate>;
}

/** Replaces an open confirmation if permissions change, while keeping its reason and close control visible. */
export function PermissionConfirm({ action, ...props }: ConfirmReasonModalProps & { action: PermissionRequirement }) {
  const permission = usePermissions();
  if (permission.can(action)) return <ConfirmReasonModal {...props} onConfirm={(reason) => {
    if (permission.can(action)) props.onConfirm(reason);
  }} />;
  return <Modal opened={props.opened} onClose={props.onClose} title={<Text fw={700}>{props.title}</Text>} centered>
    <Stack>
      {props.body}
      <Alert color="yellow">{permission.reason(action)}</Alert>
      {props.error && <Alert color="red">{props.error}</Alert>}
      <Group justify="flex-end">
        <Button variant="default" onClick={props.onClose}>Cancel</Button>
        <PermissionButton action={action} color={props.confirmColor}>{props.confirmLabel}</PermissionButton>
      </Group>
    </Stack>
  </Modal>;
}
