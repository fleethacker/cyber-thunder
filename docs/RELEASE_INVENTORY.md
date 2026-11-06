# Offline release inventory — FUTURE ATO-02 candidate

`scripts/release_inventory.py` collects bounded local release evidence into a
**partial CycloneDX 1.6 JSON inventory**. This is a separate FUTURE candidate,
not an ATO-02 completion claim, release gate, deployment approval, or vulnerability
assessment. It has no application integration and needs only Python 3.12 and Git.
It does not install, import, execute, or resolve dependency packages.

## Generate evidence

Run from the repository root against a quiescent checkout. Create a dedicated
output directory; use new output names for every run. Existing files are never
overwritten. Existing private build fixtures are not inputs.

```powershell
New-Item -ItemType Directory -Force .build/release-inventory
python scripts/release_inventory.py --repo . --output .build/release-inventory/release.cdx.json --receipt .build/release-inventory/release.receipt.json
```

```sh
mkdir -p .build/release-inventory
python3.12 scripts/release_inventory.py --repo . --output .build/release-inventory/release.cdx.json --receipt .build/release-inventory/release.receipt.json
```

Outputs can also go outside the repository. Inside the repository, only
`.build/release-inventory/` is permitted, keeping output out of the input set and
Git dirty status. Output parents must already exist. Exit 0 means generation
succeeded with **partial** coverage; exit 2 means unsafe, malformed, changed, or
over-budget input, or an I/O failure. Parser failures emit no artifact. An output
I/O failure can leave a partial file: accept only a successful run whose receipt
hash matches the artifact. The receipt hash is an integrity check, not a signature.

The BOM omits timestamp and serial number for byte reproducibility. A separate
receipt records UTC generation time, artifact SHA-256 and byte count, and source
metadata. Compare artifact bytes or SHA-256 across runs; receipts intentionally
differ. Reproducibility requires the same HEAD, Git status, generator bytes, and
input bytes, including ignored UI assets. Different line-ending conversions or
dirty status produce different evidence even at the same commit.

## Evidence and meaning

| Input | Recorded evidence | What remains unknown |
| --- | --- | --- |
| `pyproject.toml` | Project name/version, Python requirements, build-system and optional dependency declarations; source SHA-256 | Resolved or installed versions; build dependency closure |
| `requirements.txt`, `requirements-dev.txt` | Literal declarations and file SHA-256 | Included requirements files and direct URLs are not followed; no solver runs |
| Direct `vendor/*.whl` | Whole-wheel SHA-256, exactly one top-level dist-info METADATA identity, Requires-Dist/Requires-Python/License-Expression declarations, CRC check of every ZIP member | Installation, platform compatibility, signature/origin, RECORD authenticity, dependency closure, verified licenses |
| `cyberthunder/ui/package.json` | UI identity and direct runtime/dev requirements | Actual install/build state |
| `cyberthunder/ui/package-lock.json` v2/v3 | Every non-root packages entry, exact version when present, resolved reference, integrity string, path, dependency maps, optional/link/inBundle flags | Downloaded tarball integrity and dependency graph resolution |
| `cyberthunder/ui/dist/**` | SHA-256 of each actual regular asset | Build provenance and which packages contributed to each bundle |
| `Dockerfile`, `Containerfile`, tracked YAML under `deploy/` and `packages/` | Source digests; literal FROM/image/images references and line numbers; digest-pinned flag; ARG names ending VERSION and declared defaults | Image contents, approved-image status, registry resolution, deployment, OS packages, fetched binaries |
| Explicit optional metadata | Local model/runtime declarations | Actual deployment, artifact bytes, trust, completeness |

Npm `dev: true` is labeled development; `devOptional: true` is labeled
development-or-optional-runtime; other entries are runtime-eligible. None of those
labels proves shipment. `inBundle` is retained as a lock declaration about package
bundling, **not** proof of membership in the built UI. No CycloneDX dependency graph
is emitted because a lock declaration alone is insufficient to claim a complete,
resolved cross-ecosystem graph. Missing version/integrity and local links remain
explicit unresolved entries. Licenses are not populated as verified license fields.

All components have `release-inventory:component-coverage=incomplete`. Components
with directly hashed bytes have `artifact-evidence=complete-observed-bytes`;
declaration-only components have `artifact-evidence=declaration-only`. This narrow
byte-evidence completeness does not imply complete component provenance or coverage.
Global `compositions.aggregate=incomplete`, limitations, and unresolved entries
remain present even when all expected local files exist. Missing ordinary inputs
produce gaps; malformed present inputs fail the run. Missing explicitly requested
external metadata fails the run.

Manifest extraction is deliberately limited to literal line forms, including
`- image:`, and indented block `images:` lists. It does not parse YAML anchors,
flow collections, Helm templates, compose services, build recipes, or shell logic.
All selected manifest bytes are hashed so a reviewer can inspect omitted forms.
Referenced paths are never followed. Example/range package references may appear;
they are not declarations that those images ship in the application release.
Tag-only image references are explicitly unresolved; even digest-pinned references
do not prove that image bytes were available or inspected.

## Optional external declarations

Use `--external-metadata release-metadata.json` for a deliberately prepared,
repo-relative, non-secret JSON file. No discovery of model directories, running
processes, environment variables, installed packages, hosts, or real targets occurs.
Only this shape is accepted; additional fields are rejected:

```json
{
  "components": [
    {"kind": "model", "name": "example-model", "version": "1", "reference": "local-release-model"},
    {"kind": "runtime", "name": "example-runtime", "reference": "registry.example/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
  ]
}
```

`kind` and `name` are required; `version`, `reference`, and lowercase 64-character
`sha256` are optional. Declared digests stay in custom properties, not verified
artifact hash fields. Without explicit metadata, external runtime/model coverage
is unknown; with metadata, deployment is still unknown. References are not fetched.

## Bounds and provenance

No network client is used. Git is invoked read-only with no shell, no optional
locks, no filesystem monitor, no global/system Git config, a 20-second command
timeout, and an 8 MiB output limit. Inherited Git overrides are excluded. Environment
values are not recorded. Git status records only a dirty boolean and a status-byte
hash, not unrelated untracked filenames or file contents.

The source root must equal the Git worktree root. Source paths cannot be absolute,
contain traversal, drive/alternate-stream separators, or backslashes. Symlinks,
junctions, hard-linked files and special files are rejected. There are no wheel,
lockfile, or bundle path overrides. Only the explicit local metadata option adds
an input. Credential-bearing URL authority and URL query strings in recorded
references are rejected without echoing their values. This is not a general secret
scanner: prepare non-secret metadata before using the collector.

Limits are constants, not user-expandable CLI options: 8 MiB text/Git output,
128 MiB per binary input, 512 MiB cumulative input, 10,000 traversed directory
entries/source files/components, 10,000 ZIP entries, 8 MiB ZIP central directory,
256 MiB expanded bytes per wheel, 200:1 per-member expansion ratio, 1 MiB METADATA,
4,096-character scalar metadata, and 32 MiB encoded BOM. ZIP directory counts are
checked before allocating ZIP member objects. Encrypted, linked, duplicate
(case-insensitive), ZIP64/multipart, or non-stored/non-deflated members are rejected.
No archive extraction occurs. Large legitimate inputs may require a separately
reviewed bounds change. Files under private `.build` directories are never scanned.

Metadata includes exact HEAD commit and HEAD tree, dirty status, SHA-256/size for
each consumed source, and a SHA-256 of the canonical source list. The generator
itself is hashed when present in the expected location. Sources and Git status
are checked again after collection. This detects ordinary concurrent changes;
it is not an atomic filesystem snapshot or protection against a malicious process
mutating files during reads. Use a fixed isolated checkout for release evidence.
The HEAD tree does not describe dirty or ignored bytes; use the source hashes too.

## Validation and follow-on work

Focused tests use only the standard library and create representative wheel,
npm lock, manifest, and bundle fixtures in temporary repositories:

```sh
python -m unittest discover -s tests -p test_release_inventory.py -v
```

Validate the resulting JSON independently against the primary versioned
[CycloneDX 1.6 schema](https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json),
with its corresponding `spdx.schema.json` and `jsf-0.82.schema.json` available
locally. Schema validation is not performed by the generator and is not proof of
coverage. Keep schema hashes and validator version in a separate validation
receipt; do not install a runtime dependency or retrieve schemas during offline
generation. Native Windows Python 3.12 and Linux Python 3.12 tests, real repository
generation, cross-platform artifact comparison, and an independent local schema
validation are the bounded candidate checks. No full gate is implied.

Before using this as complete release evidence, resolve and reconcile Python
dependencies per supported platform, verify wheel provenance and RECORD/signatures,
verify npm tarballs, capture bundler membership and build attestations, supply
release-specific image selection and verified digest manifests/layers/OS packages,
and provide explicit runtime/model artifact provenance. Verify licenses separately.
A vulnerability report requires an actual scanner and dated local database receipt;
this collector never invents scan results. Integration into release policy, signing,
full gates, publication, and deployment are separate follow-on decisions.
