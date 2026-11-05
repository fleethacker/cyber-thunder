import type { LibraryPreferencesInput, LibraryProduct } from '../api/types';

export type ContentTask = 'downloaded' | 'maintained' | 'updates' | 'browse' | 'transfers';
export function contentTask(value: string | null, product: string | null = null): ContentTask {
  if (value === 'library') return 'downloaded';
  if (value === 'selections') return 'maintained';
  if (['downloaded', 'maintained', 'updates', 'browse', 'transfers'].includes(value ?? '')) return value as ContentTask;
  return product ? 'browse' : 'downloaded';
}
export const isMaintained = (product: LibraryProduct, preferences: LibraryPreferencesInput) =>
  preferences.mode === 'inventory' ? product.recommended : preferences.products.includes(product.product_key);

export const productSearch = (product: LibraryProduct) => [
  product.title, product.product_key, ...product.kinds.map((kind) => kind.replace(/_/g, ' ')), ...product.targets,
  ...product.available.flatMap((release) => [release.filename, release.version_label, release.upload_date]),
  ...product.held.flatMap((file) => [file.filename, file.version_label, file.benchmark_release]),
].filter(Boolean).join(' ');

// Router-relative link: HashRouter emits #/content?tab=browse&product=...
export const libraryProductHref = (productKey: string) => `/content?tab=browse&product=${encodeURIComponent(productKey)}`;
