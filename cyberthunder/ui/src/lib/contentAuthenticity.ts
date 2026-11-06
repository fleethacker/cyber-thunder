import { sessionIdentity, type SessionIdentity } from '../api/identity';
import type { ContentAuthenticity, ContentManifest } from '../api/types';

export function contentProvenance(value?: ContentAuthenticity) {
  switch (value?.status) {
    case 'operator_attested': return value.operator_attested === true
      ? { color: 'blue', text: 'Operator attestation verified at import; no DISA signature claimed.' }
      : { color: 'gray', text: 'Attestation evidence is incomplete; authenticity not established.' };
    case 'trusted_https_source': return { color: 'blue', text: 'Downloaded through verified HTTPS; no publisher signature.' };
    case 'human_override': return { color: 'orange', text: 'Accepted by a human exception; authenticity not established.' };
    case 'unsigned_dev': return { color: 'orange', text: 'Unsigned development import; authenticity not established.' };
    default: return { color: 'gray', text: 'Content authenticity not established in this record.' };
  }
}

export function canOverrideContent(identity: SessionIdentity | null = sessionIdentity()): boolean {
  const principal = identity?.principal;
  return !!identity?.authenticated && identity.mode !== 'dev' && principal?.verified === true
    && principal.source === identity.mode && principal.kind === 'human'
    && identity.permissions.includes('admin') && identity.permissions.includes('import');
}

export function contentAccount(identity: SessionIdentity | null = sessionIdentity()): string {
  return JSON.stringify([identity?.mode, identity?.principal?.issuer, identity?.principal?.subject,
    identity?.principal?.actor]);
}

export function manifestText(manifest: ContentManifest): string {
  if (typeof manifest.download_text === 'string' && manifest.download_text.length) return manifest.download_text;
  if (manifest.authenticity?.operator_attested || manifest.authenticity?.status === 'operator_signed') {
    throw new Error('The server did not supply the signed download. Refresh before exporting.');
  }
  // Older development nodes returned a summary; strip local paths and receipt fields.
  const { generated_at, generated_by, node, index_source, items } = manifest;
  return JSON.stringify({ generated_at, generated_by, node, index_source, items });
}
