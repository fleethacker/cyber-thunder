# Independent container hardening review

Reviewed on 2026-11-06. **No blocking implementation defect found in this
bounded patch.** The evidence supports accepting the Dockerfile hardening as
a measured vulnerability reduction. The candidate still contains 198 reported
finding entries, including 49 high entries; this review grants no production,
deployment, compliance, or clean-image approval.

## Exact scope

| Input | Revision or identity |
| --- | --- |
| Baseline | `c9566db8e58021a7bfa26426cede86d9ef72e969` |
| Implementation | `5a7388b662485739f8e851138ed86144b7ca2afd` |
| Implementation tree | `41bb26076d3711592b536bb473be83f09291d843` |
| Reviewed documentation follow-up | `6edc803bfee75f0306217bdfe62ac32c209363be` |
| Candidate local image | `sha256:465767944c6316e8df034abb9ead01bc637639d3f1c77af8aa9e9635e76d050c` |

The implementation diff changes only `Dockerfile`, `docs/CONTAINER_BUILD.md`,
`docs/CONTAINER_VULNERABILITY_REVIEW.md`, `tests/test_container_tools.py`, and
`tests/test_package_identity.py`. The follow-up changes only the vulnerability
report. This independent review adds this document; no implementation fix was
needed. Existing installer, parser, and engine sources were read to assess
compatibility. Release, application, authentication, deployment, UI, dependency
lockfiles, and CI changes are outside this review.

## Findings and remaining risk

There are no actionable correctness or security regressions identified in the
changed implementation. The following disclosed limitations remain material:

| Observation | Review conclusion |
| --- | --- |
| OS high findings rise from 37 to 46 while overall highs fall from 87 to 49 | This is a tradeoff, not improvement in every package. Retain the complete report and added-entry list. |
| 45 added entries include 30 high | Independently recomputed: 29 high entries are util-linux source-family matches; one is a setuptools SBOM match. No blanket dismissal is justified. |
| Three setuptools entries come from bundled SBOM inventory | The retained inspection has no installed top-level setuptools distribution, importable package, or `package_index.py`. That supports the report's limited applicability language, not a claim of patched vendored content. |
| ARM64 and BuildKit have no actual build/run receipt | Both architecture pin chains and shell branches were checked. Simulated architecture selection does not establish ARM64 execution. |
| Application dependencies still resolve through `pyproject.toml` | The base/tool pins and pip wheel hash do not lock the entire dependency graph or make later builds byte-identical. |
| Runtime smoke uses explicitly unverified loopback development identity | It supports local package/runtime compatibility only. It does not validate verified users, external gateways, live clusters, or durable external volumes. |

No findings were removed from the reports or converted to ignore entries.
The separate `Containerfile`, discarded build-stage operating systems, Java
coverage without a Java database, database publisher authenticity, and
application-specific exploitability remain outside the evidence established
here. See [the measured vulnerability report](CONTAINER_VULNERABILITY_REVIEW.md)
for the retained advisory-level detail.

## Pin and architecture review

Fresh, read-only requests to Docker Hub's registry resolved all three selected
tags to the exact Dockerfile index digests. Independently hashing the retained
amd64 and arm64 manifests and configurations verified both child chains under
each index, including declared OS, architecture, and content sizes. No image
pull was needed for this review. The captured Node pull receipt also associates
the previous `node:22-bookworm-slim` tag with the selected index.

Fresh upstream [amd64](https://dl.k8s.io/release/v1.36.6/bin/linux/amd64/kubectl.sha256)
and [arm64](https://dl.k8s.io/release/v1.36.6/bin/linux/arm64/kubectl.sha256)
checksum responses match the two kubectl build arguments. Fresh
[pip 26.3 metadata](https://pypi.org/pypi/pip/26.3/json) matches the
`pip-26.3-py3-none-any.whl` hash and does not mark that wheel yanked. These
checks establish agreement with the named public sources, not release signing.
The pip install uses the documented
[hash checking and binary-only options](https://pip.pypa.io/en/stable/topics/secure-installs/).

The installer selects explicit `TARGETARCH` or a supported native Linux
architecture when it is empty. The Dockerfile's second checksum check selects
the native/emulated stage architecture before invoking kubectl. Consequently,
an explicit target inconsistent with that stage fails the reviewed checksum.
The stage declares `ARG TARGETARCH`, as required to expose BuildKit's
[automatic platform argument](https://docs.docker.com/reference/dockerfile/#automatic-platform-args-in-the-global-scope).
Changing the release requires a corresponding reviewed checksum; a version
override alone cannot pass for different bytes. Builder-controlled checksum
overrides remain a deliberate trust boundary.

## Independent checks performed

| Check | Result |
| --- | --- |
| Original evidence index | All 108 recorded files match their recorded byte sizes and SHA-256 hashes. |
| Source archive | All 994 file contents match both the implementation Git tree and the recorded blob map. Archive SHA-256: `c97554444a2434d782fd72a860bcc00b4e144f15006426cd9a77208a968d6665`. |
| Retained Linux source export | All 994 files still match those committed blobs. |
| Database and scanner inputs | Original scanner, database, metadata, and copied database hashes still match the receipts. Empty ignore file and empty explicit configuration verified. |
| Image archives | Both current archive hashes match the retained receipts. Both original and candidate image IDs remain present locally. |
| Actual image metadata | Candidate is amd64, has `USER 10001:10001`, and retains the implementation revision label. |
| Shell failure handling | 14 cases passed under the actual image's `/bin/sh` (`dash`) with inert fixtures. |
| Scan comparison | All four report hashes, package counts, severities, and finding identity multisets agree with the receipts. |
| Existing focused test receipts | Windows and Linux XML each contain 264 tests with zero failures, errors, or skips. These were inspected, not rerun. |
| UI parity | All three committed bundle hashes match the smoke receipt; JS remains `bcd1cb4daa7673a9b9a2de57068d65b60d8bc8b2834054c15003a0b1f97707aa`. |

The shell probe executes the Dockerfile's extracted `RUN` command, substituting
only temporary installer/tool paths and inert fixture payloads. Six success
cases cover four native aliases and two explicit architecture selections.
Seven cases reject execution: mismatched architecture in either direction,
unsupported native architecture, installer failure with an existing valid
binary, and wrong, malformed, or empty reviewed checksums. The fourteenth case
confirms a failing client command propagates its nonzero status. In particular,
the `case ... | sha256sum --check --strict` pipeline fails on empty input from
an unsupported architecture; installer failure short-circuits before it.

The probe ran with no network, a read-only root, UID/GID 10001, one CPU, and
256 MiB memory. Its first harness attempt used a no-exec temporary mount and
correctly failed to execute the fixture after its valid checksum. That receipt
is retained as `attempt1-*`. The successful attempt explicitly permitted
execution only in its disposable fixture mount. This changes neither the image
nor the previously captured application smoke. Both probe containers were
removed automatically.

## Scan and compatibility conclusions

| Image | Scanner versions checked in retained reports | Critical | High | Total |
| --- | --- | ---: | ---: | ---: |
| Baseline | 0.71.1 and 0.76.2 | 2 | 87 | 387 |
| Candidate | 0.71.1 and 0.76.2 | 0 | 49 | 198 |

The engines agree on the complete `(component, package, advisory)` identity
multiset for each image. The independent difference is 234 removed, 153
retained, and 45 added entries: 30 high, eight medium, seven low. The database
remains schema 2 with SHA-256
`2ce29bda5b2483d84da3f4365398addcf03a7decf5c79e29dc73db8f0fa454ed`.
Both original critical advisory IDs disappear from the candidate reports;
the baseline SQLite `CVE-2025-7458` remains the positive calibration.

The inspected parser harness asserts that all three parsers retain that
positive. Its successful receipt records 387 cluster entries and 357 distinct
package/advisory pairs in each deduplicating parser for the baseline; all three
retain 198 candidate entries without parser errors. The engine's minimum
version check accepts 0.76.2. The actual-image CLI receipt uses the application's
offline options, a read-only database/archive, and the memory cache backend;
it returns all 387 baseline entries. Archive input substitutes for remote image
resolution, so this does not establish registry, daemon, or cluster access.

The original smoke harness and receipt establish client versions, pip dependency
consistency, UID/GID 10001, offline/read-only execution, UI/API HTTP success,
JSON/SQLite writes and reopening, audit verification, and clean shutdown. The
Dockerfile retains the numeric user, state-directory ownership, single-worker
default, and CLI entry point. These checks provide bounded compatibility
evidence for the base/tool changes without repeating a full build or suite.

## Evidence location and limits

Original receipts remain in the `oidc-validation` worktree under
`.build/container-hardening-20261106/`; the original baseline scan remains in
the `account-authorization` worktree under `.build/image-vulnerability-c9566db/`.
The verified original evidence-index SHA-256 is
`6964e052471db1eecbc51f3eadfb33c867cd5a4b4b9ac81fae22bcbcadbb69c1`.

Independent scripts, fetched metadata, receipts, and the failed probe attempt
are retained locally under `.build/hardening-review/20261106-6edc803b/` in this
review worktree. Its 21-file `review-evidence-index.json` has SHA-256
`8b65d294e2caca0f56fa186796e51283972658494555eedf670d60a92d49a35d`.
The main results are `evidence-verification.json`, `native-verification.json`,
`upstream-verification.json`, `shell-probe-receipt.json`, and
`shell-probe-stdout.json`. The local evidence directories are not committed
artifacts or signed attestations.

No full gate, full suite, image rebuild, fresh vulnerability scan, push,
deployment, or image upload was performed for this independent review. The
existing build and smoke are reused only after checking their source and
receipt identities. Additional acceptance for another architecture, build
engine, dependency resolution, or deployment environment requires its own
evidence.
