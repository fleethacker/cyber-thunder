# Finding catalog reference panel

The Finding detail drawer displays a read-only catalog reference when the saved
finding includes `catalog_rule_metadata`. The native observation, evidence,
confidence and human review appear first. A missing or null annotation preserves
the existing drawer without a reference panel.

This is a bounded consumer of the version 1 contract in
[CATALOG_RULE_METADATA.md](CATALOG_RULE_METADATA.md). It does **not close VAL-03**.
A matching stable STIG ID does not establish that the existing native checker
assesses the referenced release. Every supported annotation has
`assessment: not_assessed`. The collection summary's `coverage_added: 0` is not a
finding field; the panel states the fixed reference-only boundary of zero added
checks without treating the catalog rule count as assessment coverage.

## What the operator sees

- **Checked native release** comes from the original finding benchmark and
  release, separately from **Active catalog at collection**. The latter is a
  saved snapshot, with no claim of present activation or the newest release.
- **Not assessed** remains visible for every outcome, including a unique match.
  The catalog title, severity, rule ID and group ID are explicitly reference
  metadata. They never replace the original finding fields or citations.
- Exact selected product and benchmark identity, catalog benchmark, version,
  release text, release scheme and numeric release values identify the reference.
  Selection remains an operator declaration, not platform applicability evidence.
- Publication evidence is described as a recorded receipt. Operator attestation
  at import is distinct from publisher signing. HTTPS provenance, an authorized
  human exception, unsigned development content and incomplete evidence have
  separate labels. No browser-side trust decision is made. Publication bookkeeping
  status remains explicit, including `committed_with_bookkeeping_pending`.
  The public provenance summary supplies status, attestation/signature flags,
  document/key digests and optional original exception status. Private receipt
  extensions (actors, reasons, signer labels, scopes, URLs and paths) are ignored,
  including when an older server supplies them; they are not required for display.
- Snapshot/publication generations, bundled extract path, SHA-256 digests, byte
  sizes and catalog rule count are in a collapsed native disclosure. Its count is
  labeled **not coverage**. Hashes are displayed as recorded, not verified here.

| Mapping status | Display behavior |
| --- | --- |
| `matched` | A unique reference rule is shown, with the not-assessed warning. |
| `withdrawn` | A unique reference is shown as marked withdrawn, deprecated or obsolete; the native observation remains intact. |
| `missing` | The exact STIG ID is absent; absence alone is not withdrawal. No reference rule is shown. |
| `ambiguous` | No reference rule is selected. |
| `no_active_catalog` | The selected lineage had no active manual catalog in that snapshot. |
| `untrusted_active_catalog` | Available publication metadata is shown as untrusted; rule metadata is not used. |
| `not_configured` | No local catalog was requested or read. |

## Input and action boundaries

The optional API field is `unknown` so rendering must narrow runtime values.
The component accepts only the supported version, assessment, mapping/catalog
state and metadata-source combination. It checks annotation identity against the
finding ID, source, rule/STIG IDs, benchmark, release and original scanner result.
The original result uses the drawer's existing scanner-status/remediation fallback
before the current result. Reference STIG and selected benchmark IDs must agree
with their recorded counterparts. Inconsistent or unsupported annotations display
**Reference unavailable**, using neutral finding-release labels and keeping the
core drawer evidence visible.

Only named scalar fields are rendered as React text. Missing or malformed nested
fields use **Not recorded or unsupported**; they are never filled from a similar
rule or native title/severity. Strings longer than 4,096 characters, release arrays
longer than four safe nonnegative integers, invalid hashes/counts, and CCI lists
longer than 64 or containing invalid IDs use the same placeholder. Identities are
never silently truncated. The panel does not render arbitrary JSON, metadata URLs,
HTML, check/fix text, or executable content.

The component performs no API requests, scanning, credential access, imports or
publication changes. Its only interaction is expanding recorded provenance.
It supplies no approval, proposal or remediation action and does not change the
drawer's existing action permissions, confidence, review or finding identity.

## Validation

With the existing local UI dependencies, from `cyberthunder/ui`:

```powershell
node --test src/components/FindingCatalogReference.test.mjs
node node_modules/typescript/bin/tsc -b
node --test
```

Focused tests use actual React server rendering and Mantine components. Drawer
integration inlines only the portal and supplies in-memory async data; the real
drawer content, child components, badges and permission controls render. Tests
cover all seven mappings, distinct releases, provenance modes, collapsed details,
old findings, unsupported/malformed values, bounded output, escaped markup,
unchanged native evidence/confidence/review and enabled/disabled proposal states.
Rendering must not mutate the finding or invoke the network.

These checks do not claim browser interaction or visual acceptance, backend
validation, operational platform acceptance, a full Python gate or a rebuilt
distribution. Final combined distribution rebuilding belongs to release
integration; this change is source-only.
