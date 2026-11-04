// Cited identifiers as chips. In a card they open the finding drawer; in the drawer they are plain links.
import { Anchor, Badge, Group, Text, Tooltip } from '@mantine/core';
import { citationHref, citationKind } from '../lib/format';

export function CitationChips({ ids, onOpen, links = false }: { ids: string[]; onOpen?: (id: string) => void; links?: boolean }) {
  if (!ids.length) return <Text size="sm" c="dimmed">No citations.</Text>;
  return (
    <Group gap={6}>
      {ids.map((id) => {
        const kind = citationKind(id);
        const chip = (
          <Badge
            key={id}
            variant="outline"
            color="gray"
            radius="sm"
            tt="none"
            style={{ cursor: onOpen || links ? 'pointer' : 'default', fontFamily: 'monospace' }}
            onClick={onOpen ? () => onOpen(id) : undefined}
            leftSection={<Text span size="xs" c="dimmed" ff="sans-serif">{kind}</Text>}
          >
            {id}
          </Badge>
        );
        const href = links ? citationHref(id) : null;
        if (href) {
          return (
            <Tooltip key={id} label={`${href} (does not resolve offline)`} withArrow>
              <Anchor href={href} target="_blank" rel="noreferrer" underline="never">{chip}</Anchor>
            </Tooltip>
          );
        }
        return chip;
      })}
    </Group>
  );
}
