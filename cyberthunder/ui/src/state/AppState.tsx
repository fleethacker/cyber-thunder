// Shared app state: node status, audit chain verification, actor, and ONE audit SSE connection that any
// component can listen to (header badges, the Audit page, apply timelines).
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { api, errorText, getActor, setActor as persistActor, setAuthMode, subscribeAudit, type AuditStreamState } from '../api/client';
import type { AuditRecord, AuditVerify, Status } from '../api/types';

type Listener = (r: AuditRecord) => void;

interface AppStateValue {
  status: Status | null;
  statusError: string | null;
  verify: AuditVerify | null;
  actor: string;
  identityLocked: boolean;
  identityError: string | null;
  setActor: (name: string) => void;
  stream: AuditStreamState;
  /** most recent records seen on the stream this session, newest last (bounded) */
  recent: AuditRecord[];
  onAudit: (fn: Listener) => () => void;
  refresh: () => Promise<void>;
}

const Ctx = createContext<AppStateValue | null>(null);
const RECENT_MAX = 1000;

export function AppStateProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [verify, setVerify] = useState<AuditVerify | null>(null);
  const [actor, setActorState] = useState<string>(getActor());
  const [identityLocked, setIdentityLocked] = useState(false);
  const [identityError, setIdentityError] = useState<string | null>(null);
  const [stream, setStream] = useState<AuditStreamState>('connecting');
  const [recent, setRecent] = useState<AuditRecord[]>([]);
  const listeners = useRef(new Set<Listener>());
  const verifyTimer = useRef<number | undefined>(undefined);

  const loadStatus = useCallback(async () => {
    try {
      setStatus(await api.status());
      setStatusError(null);
    } catch (e) {
      setStatusError(errorText(e));
    }
  }, []);

  const loadVerify = useCallback(async () => {
    try {
      setVerify(await api.auditVerify());
    } catch {
      /* the badge shows "unknown" */
    }
  }, []);

  const refresh = useCallback(async () => {
    await Promise.all([loadStatus(), loadVerify()]);
  }, [loadStatus, loadVerify]);

  // status poll (link, outbox, kill, model) every 5 s
  useEffect(() => {
    void refresh();
    const id = window.setInterval(() => void loadStatus(), 5000);
    return () => window.clearInterval(id);
  }, [refresh, loadStatus]);

  // single audit stream, started after the current head so we only see new records
  useEffect(() => {
    let stop: (() => void) | undefined;
    let cancelled = false;
    (async () => {
      let after = 0;
      try {
        after = (await api.auditVerify()).count;
      } catch {
        after = 0;
      }
      if (cancelled) return;
      stop = subscribeAudit(
        (rec) => {
          setRecent((r) => {
            const next = r.length >= RECENT_MAX ? r.slice(r.length - RECENT_MAX + 1) : r.slice();
            next.push(rec);
            return next;
          });
          listeners.current.forEach((fn) => fn(rec));
          // chain badge refreshes on each event (debounced so a burst costs one call)
          window.clearTimeout(verifyTimer.current);
          verifyTimer.current = window.setTimeout(() => {
            void loadVerify();
            void loadStatus();
          }, 250);
        },
        { afterSeq: after, onState: setStream },
      );
    })();
    return () => {
      cancelled = true;
      stop?.();
    };
  }, [loadVerify, loadStatus]);

  useEffect(() => {
    let cancelled = false;
    api.whoami().then((who) => {
      if (cancelled) return;
      if (who.mode === 'mesh') {
        setAuthMode('mesh');
        setIdentityLocked(true);
        setIdentityError(null);
        setActorState(who.actor ?? '');
      }
    }).catch((e) => {
      if (cancelled || !(e instanceof Error)) return;
      const status = 'status' in e ? Number((e as { status: number }).status) : 0;
      if (status === 401) {
        setAuthMode('mesh');
        setIdentityLocked(true);
        setActorState('');
        setIdentityError(errorText(e));
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const h = (e: Event) => setActorState((e as CustomEvent<string>).detail);
    window.addEventListener('ct:actor', h);
    return () => window.removeEventListener('ct:actor', h);
  }, []);

  const setActor = useCallback((name: string) => {
    persistActor(name);
    setActorState(name.trim());
  }, []);

  const onAudit = useCallback((fn: Listener) => {
    listeners.current.add(fn);
    return () => {
      listeners.current.delete(fn);
    };
  }, []);

  const value = useMemo<AppStateValue>(
    () => ({ status, statusError, verify, actor, identityLocked, identityError, setActor, stream, recent, onAudit, refresh }),
    [status, statusError, verify, actor, identityLocked, identityError, setActor, stream, recent, onAudit, refresh],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAppState(): AppStateValue {
  const v = useContext(Ctx);
  if (!v) throw new Error('useAppState outside AppStateProvider');
  return v;
}

/** Run `fn` for every new audit record while mounted. */
export function useAuditListener(fn: Listener): void {
  const { onAudit } = useAppState();
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => onAudit((r) => ref.current(r)), [onAudit]);
}
