import type { Status } from '../api/types';
import { useAppState } from '../state/AppState';
import { actorProblem } from './ActorChip';

/** Static previews do not authorize writes or network probes. Recheck this before every action. */
export function setupActionProblem({ actor, status, statusError }: {
  actor: string; status: Pick<Status, 'kill'> | null; statusError?: string | null;
}): string | null {
  const actorError = actorProblem(actor);
  if (actorError) return actorError;
  if (/^(agent|llm|system|policy):/i.test(actor.trim())) return 'Use a named operator for setup and scope decisions.';
  if (statusError || !status || typeof status.kill?.engaged !== 'boolean') return 'Kill switch status is unavailable. Refresh status before continuing.';
  if (status.kill.engaged) return 'Kill switch engaged. Setup changes and network probes are blocked.';
  return null;
}

export function useSetupAccess(): string | null {
  return setupActionProblem(useAppState());
}
