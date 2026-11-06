# Container OS XCCDF results import

Import an existing `NAME-xccdf.xml` emitted by `scripts/scan-container-os.sh` into
persisted findings, scan history and the existing report views. This is the bounded
MVP-04 application integration sidecar. It does not run OpenSCAP, pull images,
connect to targets, modify inventory, publish benchmark content, propose fixes or
apply changes. Actual live **nginx-bad evaluation remains open**.

## Explicit manifest

Supply one existing inventory target for exactly one TestResult. XML target names,
addresses, CPEs and local file paths never determine inventory identity or platform
applicability. All fields below are required; `image_digest` is optional.

```json
{
  "source_id": "range-container-evaluation",
  "test_result_id": "xccdf_org.open-scap_testresult_example",
  "target_id": "container-range",
  "benchmark_id": "xccdf_org.ssgproject.content_benchmark_RHEL-9",
  "profile_id": "xccdf_org.ssgproject.content_profile_stig",
  "expected_rule_ids": ["xccdf_org.ssgproject.content_rule_example"],
  "provenance": {
    "engine": "openscap",
    "engine_version": "1.3.10",
    "mode": "rootfs",
    "image_ref": "registry.example.test/ubi9:range",
    "image_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "subject_ref": "/mounted/container-rootfs",
    "platform": "UBI 9, declared by the operator",
    "exit_code": 2
  }
}
```

Use the exact IDs from the actual export. `source_id` names the evaluation source;
keep it stable when replacing observations from that source. `expected_rule_ids`
is the nonempty, unique list of rules expected for the requested evaluation, supplied
explicitly by the operator. The importer does not resolve profile inheritance or
infer that a published benchmark applies to a container. Observed rules outside
that list are retained; expected rules absent from the XML become `not_reviewed`
observations with `raw_result: "missing"`.

`mode` accepts `rootfs`, `podman-image` or `podman-container`. `subject_ref` records
the mounted rootfs, local image or container actually evaluated. It is an inert
provenance string, never a file to read or an argument to execute. `image_ref` is
required even for rootfs input. Prefer an immutable image digest when available;
tags and caller-supplied digests are declarations, not verified image identity.
Supply the original OpenSCAP exit code, before any wrapper converts code 2 to 0.
Manifest declarations and rule titles are retained as supplied. Keep credentials
and other secrets out of those fields; the importer is not a content redactor.

## API

`POST /api/v1/ingest/scap-results` accepts `application/json` with exactly two keys:

```json
{"xml_base64": "BASE64_OF_ORIGINAL_XML_BYTES", "manifest": {"...": "manifest above"}}
```

Build that envelope on the client from local files, then send its bytes using the
application's authenticated HTTP session. No API field accepts an arbitrary server
path. File references inside XML are never opened or fetched. JSON duplicate keys,
unknown envelope/manifest fields and non-strict base64 are rejected.

Verified mode requires a current principal with the `import` role permission,
explicit node `import`, and `import` plus `read` grants on the exact destination.
Both human and workload verified principals may import when explicitly granted;
`import` is not a human-only role action. The reserved actor-label filter does not
establish principal kind. The service rechecks expiry/session validity, grants, kill state and persisted
target ownership before publication and exact-repeat responses, including after
publication lock waits. `X-Actor` cannot
override a verified principal. Development mode requires a named actor and retains
the application's loopback restriction. Report export permissions remain separate.

Successful responses contain `scan_id`, `import_id`, `source_sha256`, the source
and TestResult IDs, destination, original result counts, missing/notselected rule
IDs, `evaluation_finished`, `evaluated_at`, `result_scope_complete`, counts and
`repeated`. Every response has `platform_applicability: "unverified"` and
`compliance_claim: false`. `imported_count` includes original rule results and
explicit missing-rule observations; `coverage_finding_count` is 1;
`findings_count` is their sum. Current findings and reports use their existing APIs.

Errors: 400 malformed/unsupported input (including missing development actor),
401 authentication or required step-up, 403 denied authority/ownership,
413 bounded upload exceeded, 415 wrong media type, 423 kill engaged,
503 storage unavailable. Diagnostics do not echo XML, upload paths or storage paths.
Request cancellation or a disconnect observed before publication stops the worker
at its next guard. Parsing and lock acquisition are not forcibly interrupted.
Cancellation after the run marker is committed does not undo the import; retry
the same source and manifest to obtain its original receipt.

## CLI

The separate module works immediately in local development mode:

```text
python -m cyberthunder.ingest.scap_cli --state-dir STATE --actor "Joshua Ott" NAME-xccdf.xml --manifest manifest.json
```

It reads each explicitly supplied local regular file with a byte cap. Symlinks,
pipes and devices are rejected; the opened file's identity is checked again before
reading. Verified mode refuses
the local actor shortcut; use the authenticated upload API. It opens no connection
and cannot establish a verified session itself.

The main CLI exposes the same development-only import:

```text
cyberthunder --state-dir STATE --actor "Joshua Ott" scap-results-import NAME-xccdf.xml --manifest manifest.json
```

The dedicated route is registered in `api/app.py`. Its module registers exactly
`POST /ingest/scap-results -> import` in `WRITE_ACTIONS` and the same tuple in
`SCOPED`, before authentication setup validates route coverage. These two entries
can be moved to the central policy tables by their owner at integration time;
no shared identity implementation or existing importer is changed.

## Result semantics and publication

| Original result | Finding status |
| --- | --- |
| pass, fixed | not_a_finding |
| fail | open |
| error | error |
| notapplicable | not_applicable |
| notchecked, unknown, informational, notselected | not_reviewed |
| expected rule missing | not_reviewed, explicit missing marker |

Each rule's exact original result remains in `collection_provenance.raw_result`
and its `xccdf-result:` tag. Notselected observations are retained, and their IDs
are returned explicitly; no rules are silently skipped. An expected notselected
rule makes the result scope incomplete. An unexpected notselected rule is still
unreviewed. Source evaluation timestamps remain the finding's collection time;
the run timestamp records import publication time.
When both source timestamps are present, completion cannot precede the start and
their timezone awareness must agree. Either both may omit a timezone or both must
include one; the importer does not infer the source timezone.

One separate `container-scap:coverage` finding makes limitations visible in existing
findings/report summaries: it is `error` for absent completion or engine exit codes
other than 0/2, otherwise `not_reviewed` because platform applicability is unverified.
It is not an original scanner rule, has `observation_kind: "coverage"`, and carries
no `raw_result`. Missing/unchecked/unknown/error/informational results prevent a
complete result-scope claim. Every run has `coverage_incomplete: true`; even an
all-pass or all-notapplicable export cannot certify a host or container as clean.

Findings use source `openscap-container`, a separate namespace from host OpenSCAP
findings. Observation IDs include the explicit source, TestResult, benchmark,
profile, container subject and persisted target generation/environment. A revised
export of that same observation overlays it; a different source/TestResult/subject
remains distinct. Engine version/exit-code changes do not change observation IDs.
Omitted rules never erase earlier findings. No platform STIG mapping, executable
fix content or automatic proposals are created.

Exact import identity hashes original XML bytes plus the canonical manifest.
The XML itself is not archived by this sidecar; retain the original export alongside
its receipt if independent byte-for-byte verification is needed later.
Manifest key order and expected-rule order are irrelevant. An exact repeat returns
the original receipt without changing observation timestamps, scan history or
current precedence. A different account or changed target generation/environment
cannot adopt either a committed receipt or an interrupted staged import. Intentional
new source declarations are new imports and require current destination grants.

Publication uses the existing passive scanner lock and public StateStore methods,
including observation/review lifecycle locks. Findings and ownership metadata are
staged before the discoverable run marker. Failure before the marker leaves no
current findings or scan/report history entry; the same owner may retry. A crash
after the marker can leave a valid published run without the final completion audit
entry; the preceding publish-intent audit exists, and retry is idempotent. History
and ownership use the same documents on JSON and SQLite. Partial-run accumulation
preserves unrelated observations without copying or relabeling them.

A request-local store view rechecks current authority and cancellation at document
writes after lifecycle contention. SQLite writer acquisition precedes this final
check. The shared store and backend ownership remain unchanged. These are
cooperative checks, not a transaction with external identity-policy updates or
disconnect delivery. The shared JSON review ledger, audit log and run marker are
separate writes: an interrupted review invalidation may conservatively leave a
prior review invalidated even though a new run was not published. No automatic
rollback of review history or audit entries is attempted.

## Parser and engine limits

- Original XML: 16 MiB; manifest: 256 KiB; API envelope: base64 expansion of 16 MiB,
  plus 256 KiB and 1 KiB framing. Streamed requests have the same cap as declared lengths.
- At most 250,000 XML elements, depth 32, 64 attributes per element, 1,024-character
  names/identifiers, 65,536-character fields, 50,000 Rule definitions and 50,000
  result observations including explicit missing rules.
- Namespace-qualified XCCDF 1.1/1.2 Benchmark with one direct TestResult, or one
  standalone TestResult with explicit benchmark/profile identity. Multiple results,
  ARF/datastream wrappers, mixed critical namespaces, duplicate/conflicting rule IDs,
  duplicate result elements and unknown result values are rejected.
- ElementTree parses the original bytes with a bounded tree builder. A parser-level
  doctype callback rejects DTD/internal/external/parameter entity declarations,
  including UTF-16 encodings; it does not rely on an ASCII byte search. Normal
  predefined XML character entities are accepted. No new dependency is required.
- This is a bounded semantic importer, not full XCCDF XSD validation. It does not
  resolve profiles, OVAL, CPE or remote benchmark references, verify an engine binary,
  verify provenance declarations, infer host identity or prove evaluation coverage.
- OpenSCAP rootfs/container results concern filesystem-visible checks. Host kernel,
  services, boot controls and other host STIG assumptions may be unavailable or
  inapplicable. A RHEL host STIG evaluated against UBI is never normalized into UBI
  certification. Use an authorized, platform-appropriate evaluation plan.

## Focused validation

```text
python -m pytest tests/ingest/test_scap_results.py tests/api/test_scap_results.py tests/ingest/test_scap_review.py tests/api/test_scap_review.py
```

State-dependent tests run on JSON and SQLite by default. They exercise malformed
sources and manifests, DTD/UTF-16 entities and structural caps, raw status retention,
missing results, repeated/current history, interrupted publication, grant/session
revocation, account and target reuse, API streaming, report filtering, passive CLI
behavior and the existing Linux XCCDF fixture. That fixture is parser compatibility
evidence, not a new live evaluation receipt. No shell integration is modified.
Independent review regressions additionally exercise cancellation/disconnection,
revocation while publication waits, minimal human/workload permissions, storage
and kill-switch diagnostics, timestamp ordering, bounded expected-rule lookup and
regular-file input. The FIFO case requires native POSIX; it is skipped on Windows.
