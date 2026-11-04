import { createTheme, type MantineColorsTuple } from '@mantine/core';

// Deep navy replaces Mantine's default dark greys. No web fonts: system stacks only (offline).
const navy: MantineColorsTuple = [
  '#c9d3e6', '#a7b5cf', '#8193b4', '#5b6f93', '#34476b', '#22335a', '#17264a', '#111d3b', '#0c152d', '#080f22',
];

export const theme = createTheme({
  primaryColor: 'blue',
  colors: { dark: navy },
  fontFamily: 'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
  fontFamilyMonospace: 'ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace',
  headings: { fontFamily: 'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif' },
  defaultRadius: 'md',
  cursorType: 'pointer',
});
