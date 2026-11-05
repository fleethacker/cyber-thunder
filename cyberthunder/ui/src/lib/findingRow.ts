import type { KeyboardEvent, MouseEvent } from 'react';
import type { FindingPlus } from '../api/types';

export function findingResultLabel(finding: Pick<FindingPlus, 'needs_rescan' | 'remediated'>): string {
  if (finding.needs_rescan) return 'Current result · needs rescan after rollback';
  return finding.remediated ? 'Current result after verified fix' : 'Current result';
}

const CONTROLS = 'a, button, input, select, textarea, label, summary, [role="button"], [role="checkbox"], [role="switch"], [role="link"], [contenteditable="true"], [data-row-action]';

export function findingRowHandlers(open: () => void) {
  return {
    onClick(event: MouseEvent<HTMLTableRowElement>) {
      const target = event.target as Element;
      // Popovers can bubble through React even when their DOM is outside the row.
      if (event.defaultPrevented || event.button !== 0 || !event.currentTarget.contains(target) || target.closest(CONTROLS)) return;
      open();
    },
    onKeyDown(event: KeyboardEvent<HTMLTableRowElement>) {
      if (event.target !== event.currentTarget || event.defaultPrevented || !['Enter', ' '].includes(event.key)) return;
      event.preventDefault();
      if (!event.repeat) open();
    },
  };
}
