# MVP-04 isolated container image evaluation — two attempts on 2026-11-06

**The second bounded attempt produced real XCCDF, and JSON/SQLite import,
report reads and restart persistence passed on combined source `0261297`.
Effective UBI STIG evaluation remains unresolved.**

| Actual evaluation | Scanner authority | Original exit | Outcome |
| --- | --- | --- | --- |
| 1 | UID 1000, all capabilities dropped | 134 | Chroot denied; no XCCDF; import not exercised |
| 2 | UID 0, all capabilities dropped except SYS_CHROOT | 0 | 393 raw notapplicable results; three RPM database diagnostics; import accepted on both state backends |

The initial no-capability setting was a chosen harness constraint. The second
attempt added only SYS_CHROOT for the RPM probe in the isolated scanner.
Exactly one new evaluation was performed. No attempt used privileged mode,
host namespaces, host system mounts, target entrypoint execution or remediation.
Neither outcome establishes a clean/compliant image or trustworthy RHEL host
STIG applicability. The first attempt's receipts and source identities remain
unchanged. Historical evidence follows, then the second attempt's acceptance.

## Attempt 1: source and environment

- Product source: `4870fef533dc75b29ecd3e8572e2cece76b3d86a`.
- Preserved review commit: `c6c8ed38e538c7c36dda3ceed363a553bc08c294`.
  The importer, standalone CLI and import route match that review. No product
  files, backlog, validation receipt, API, importer or UI were changed.
- Windows execution host; WSL Ubuntu 26.04.1 LTS, x86_64;
  kernel `6.18.54.1-microsoft-standard-WSL2`.
- Docker client/server `29.1.3`, API `1.52`, containerd `2.2.2`,
  runc `1.4.0-0ubuntu1`. Every command explicitly used
  `--host unix:///var/run/docker.sock`.
- Existing `k3d-cyber-thunder-server-0` and `k3d-cyber-thunder-serverlb`
  remained running. No Kubernetes command or workload change was made.
  The package's nginx Deployment was not installed; the subject was its public
  image, not a live workload or its Kubernetes configuration.

Evaluation ran from **2026-11-06T05:39:32.734306339Z** to
**2026-11-06T05:39:33.992299735Z**. Docker reported `OOMKilled: false` and an
empty runtime error string. The original attach exit and container exit were
both **134**. The shell reported that the `oscap` child aborted (SIGABRT).
The initial orchestration command completed receipt collection with status 0;
that status is not the engine result. The committed runner now propagates the
attach status after collecting receipts.

## Attempt 1: immutable inputs and scanner versions

Package image: `registry.access.redhat.com/ubi9/nginx-124:1-1756913337`, from
`packages/nginx-bad/zarf.yaml`. The actual image was created by immutable
repository digest, never started, and exported with `docker export`.

| Input or artifact | Recorded identity |
| --- | --- |
| Target repository digest | `sha256:49c71b7a13b151b282d52c13323021235529d44d82f9b875699bc4e9f6139a91` |
| Evaluated Docker export SHA-256 | `68d8202a4d8e34a14f22e3f4853ba2908553641667ca73cf5ef2688d831f90e5` |
| Debian scanner base repository digest | `debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc` |
| Built scanner local image ID | `sha256:8493d5d22754330c887614d5989129ae6cb61a845a34f3f12f1b4a0ef69c2ec1` |
| Uploaded benchmark SHA-256 | `7f75e5aca981c95dd9435bf0a323b63017a3f02785bfdc7961dfedaeb1cf792f` |

The scanner was built from public official Debian Bookworm packages, with
`apt-get update` and `apt-get install -y --no-install-recommends openscap-scanner
openscap-utils`. The build had ordinary Docker networking; the evaluation had
none. No packages were installed into the shared WSL operating system.

- `oscap --version`: **1.3.7**.
- `openscap-scanner`, `openscap-utils`, `libopenscap25`:
  **1.3.7+dfsg-1+deb12u1**.
- `librpm9`: **4.18.0+dfsg-1+deb12u1**.

The build log records dependency versions; the Dockerfile records the pinned
base. The built scanner ID identifies this local build, not a published scanner
registry digest. A later package installation may produce a different image.

Content was the existing
`STIG/U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.xml`, copied without modification.
`oscap info` recognized it as a SCAP 1.3 source datastream and listed the chosen
profile:

```text
benchmark: xccdf_mil.disa.stig_benchmark_RHEL_9_STIG
profile:   xccdf_mil.disa.stig_profile_MAC-1_Public
```

This profile explicitly selects **393 groups**, each containing one Rule,
without profile inheritance. `declared-scope.json` retains all 393 rule IDs,
derived from the original benchmark/profile independently of scanner output.
The recorder refuses other profile shapes rather than inferring scope from
returned results. Selecting this public profile does not establish UBI platform
applicability. No CPE override, tailoring, remediation, validation bypass or
remote content fetch was requested.

## Attempt 1: execution and protection limits

The export container used `--network none --entrypoint /bin/false` and remained
in `created` state, with a zero `StartedAt` timestamp. Its entrypoint never ran.
The exported archive was extracted into a new empty task directory on the
Linux filesystem. Extraction rejected absolute/traversal member paths,
duplicate paths, nondirectory parents and hardlinks outside regular archive
files. Regular files preceded links; original symlink text was retained only
after file writes. No device, FIFO or socket was created. Actual extraction:
1,758 directories, 9,309 regular files, 2,116 hardlinks, 1,724 symlinks, zero
special entries skipped.

File contents, ordinary modes, link targets and regular-file timestamps were
retained. **Original numeric ownership and extended attributes were not
preserved.** The extracted tree is not full-fidelity metadata evidence. It was
not executed or scanned by a host scanner.

The exact evaluated container creation command is retained in
`evaluation-command.txt`; expanded equivalent:

```bash
docker --host unix:///var/run/docker.sock create \
  --name ct-container-scap-2fwh7wsg-eval \
  --network none --cap-drop ALL --security-opt no-new-privileges \
  --read-only --pids-limit 128 --memory 1536m --cpus 2 \
  --user 1000:1000 --ipc none --hostname ct-scap-offline \
  --mount type=bind,src=/tmp/ct-container-scap-2fWH7wsG/rootfs,dst=/target,readonly \
  --mount type=bind,src=/tmp/ct-container-scap-2fWH7wsG/content,dst=/content,readonly \
  --mount type=bind,src=/tmp/ct-container-scap-2fWH7wsG/output,dst=/output \
  --workdir /output -e TMPDIR=/output --entrypoint /usr/bin/oscap-chroot \
  sha256:8493d5d22754330c887614d5989129ae6cb61a845a34f3f12f1b4a0ef69c2ec1 \
  /target xccdf eval --profile xccdf_mil.disa.stig_profile_MAC-1_Public \
  --results /output/image-xccdf.xml --report /output/image-report.html \
  /content/benchmark.xml
```

```bash
timeout 300 docker --host unix:///var/run/docker.sock start --attach \
  ct-container-scap-2fwh7wsg-eval
```

Docker inspection confirmed the limits and read-only binds. `/output` was the
only writable bind and the designated engine temporary directory. Docker's
private runtime pseudo-filesystems remained; no host `/proc`, host filesystem,
Docker socket, service credentials, host network or host PID namespace was
mounted. The scanner was unprivileged, with no capabilities. Public package
pulls/builds had 300/600-second limits; the one evaluation had a 300-second
limit and finished by aborting after about 1.3 seconds.

The packaged `oscap-chroot` script sets `OSCAP_PROBE_ROOT` to `/target` and
`OSCAP_EVALUATION_TARGET` to `chroot:///target`, then calls `oscap` and returns
its status. This matches the
[upstream wrapper](https://raw.githubusercontent.com/OpenSCAP/openscap/1.3.7/utils/oscap-chroot).
It does not guarantee that individual probes work without chroot capability.

## Attempt 1: actual results and import acceptance

Exact diagnostic excerpts:

```text
E: oscap:     chroot failed: Operation not permitted
E: oscap:     RPM: cannot open Packages database in
error: cannot open Packages database in
E: oscap:     chroot(".") failed: Operation not permitted
/usr/bin/oscap-chroot: line 104:     8 Aborted                 oscap "$@"
```

Stdout named only the first rule,
`xccdf_mil.disa.stig_rule_SV-257777r1155676_rule`, with its title and CCI.
It contained **no completed rule result**. The output directory was empty.

| Measure | Observed result |
| --- | --- |
| Actual evaluation attempts | 1 |
| Declared expected rules | 393 |
| Raw XCCDF pass/fail/error/NA/notchecked/notselected counts | Unavailable: no XCCDF was emitted |
| Completed raw rule observations available | 0; not evidence of zero findings or zero errors |
| Evaluation outcome | Engine abort, exit 134; no OOM or timeout |
| Result scope / platform applicability | Incomplete / unverified |
| JSON import, findings/report reads, restart persistence | Not exercised; actual XCCDF unavailable |
| SQLite import, findings/report reads, restart persistence | Not exercised; actual XCCDF unavailable |
| Verified-user or live-cluster acceptance | Not performed |

No TestResult ID exists to put in a valid import manifest. No fabricated XML,
synthetic statuses, expected-rule-derived results, CPE substitutions or modified
product parser were used. No actual findings or reports were published. This
run provides no evidence of a real-format importer compatibility bug because
the importer never received a real-format result.

A development-mode application context was initialized only to check harness
availability (Python 3.12.10, FastAPI 0.162.0, HTTPX 0.28.1). It had no inventory
target, imported run or published findings, and its empty temporary state was
removed. That check is not import acceptance or verified identity. The unused
acceptance harness was discarded. Both state backends still require a genuine
engine export, an explicit persisted target and manifest, report reads, and
fresh-process persistence checks. No additional capability was tried during
attempt 1. The later user direction authorized attempt 2 below.

## Attempt 1: receipts, cleanup and bounded automation

Ignored local evidence is under
`.build/owner-evidence/container-scap-live-20261106-run2/`:
`engine-state.json`, `engine-stdout.txt`, `engine-stderr.txt`,
`scanner-protection.json`, `evaluation-command.txt`, `scanner-version.txt`,
`scanner-build.txt`, `Dockerfile`, image identities, benchmark info/hash,
`extraction.json`, `declared-scope.json`, `result-summary.json`,
`importer-source-sha256.json`, `preservation.json`, cleanup receipts and
`receipt-sha256.json`. No service credentials or private target content were
copied. There is no raw XCCDF file to hash.

| Raw evidence | SHA-256 |
| --- | --- |
| Engine stdout (151 bytes) | `e3b4cc0c231d9cd39fb9a01f2373bf299cd9aa23b1fe3f51a5900807da29cab2` |
| Engine stderr (280 bytes) | `5e7356a07600493c913ffa51ae6ca01d4ff6f08068af0d831bc13231b4dbc34c` |
| Engine state JSON | `efb3ba60bfb583491f613c44819e28c976488abcdee12e10d27cf05513692dae` |
| Scanner build log | `d36d41bef969fba3c0a36083d96c6c7a644d187a5eec2903ec4e143183ffe716` |

An earlier **pre-evaluation** extraction attempt applied restrictive directory
modes before creating symlinks and failed with `PermissionError`. Its separate
receipts remain under `.build/owner-evidence/container-scap-live-20261106/`.
The task extractor was corrected to apply directory metadata last, in a fresh
directory. That first attempt never built a scanner or evaluated the image.

Both unique export containers, the evaluation container, local scanner image
and both unique Linux directories were removed. Public downloaded image caches
were retained; no global Docker prune was run. The two k3d containers and the
unrelated `ct-cli-device-fdde23e1cdda` container that appeared during this task
were left untouched. All 37 pre-existing top-level ignored receipts matched
their initial hashes; existing ignored dependency environments were reused
without installation or edits. The original review branch is unchanged.

The isolated helpers under `scripts/container-scap-live/` provide the bounded
runner, safe export extraction, evidence summarization and exact-directory
cleanup. They are not a supported scanner integration or a successful
acceptance suite. Shell syntax and all three Python helper parses passed.
Six native Linux extraction checks passed: read-only directory/link ordering,
parent traversal, absolute member paths, symlink parents, external hardlinks
and external symlinks. Their isolated script and results are retained with the
receipts. These checks did not repeat the evaluation.

The original runner used this invocation. The current runner implements the
second attempt's configuration and still requires a new empty receipt directory:

```bash
bash scripts/container-scap-live/run.sh "$PWD" "$receipt_dir"
python3 scripts/container-scap-live/cleanup_task.py "$receipt_dir"
python3 scripts/container-scap-live/record_result.py "$PWD" "$receipt_dir"
```

Cleanup is a separate command so an engine failure cannot skip it through
shell `&&` chaining. The recorder only reads receipts and the benchmark; it
does not run another evaluation or import anything. No full project gate,
push or merge was performed.

## Attempt 2: supported capability revision

The [OpenSCAP developer manual](https://raw.githubusercontent.com/OpenSCAP/openscap/main/docs/developer/developer.adoc)
explains that some offline probes invoke `chroot` and need authority unavailable
to an ordinary unprivileged process. Docker's
[capability documentation](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
identifies `SYS_CHROOT` as the ability to change the process root and supports
dropping all capabilities before adding one. The
[RPM manual](https://rpm.org/docs/6.1.x/man/rpm-common.8)
describes alternate-root database operations and the caller's responsibility
for the root's environment. These sources support trying this scoped
configuration; they do not promise a successful UBI database evaluation.

The new runner began at `4cd3645c6e4ede36dcc48453dd1579aa081d1675`, continuing
the same branch/worktree. Both the image and Debian base were pulled by the
exact repository digests recorded above, not a newly resolved tag. The uploaded
benchmark digest, selected profile, 393 independently declared rule IDs and
OpenSCAP/RPM package versions were unchanged.

| Second-attempt identity | Value |
| --- | --- |
| Evaluated Docker export SHA-256 | `57db202e7f56f930990eaa911df6a32e2d140cbc3a46f3763d0f4d949859751e` |
| Local scanner image ID | `sha256:bab24e518ca05fc5335a3dc9cab85b9deb6c520abf335f9d30b4915bebcfaf5b` |
| Start, UTC | `2026-11-06T05:52:59.456687839Z` |
| Finish, UTC | `2026-11-06T05:53:01.239156396Z` |
| Engine / Docker attach exit | `0` / `0` |
| Runtime error / OOM / timeout | Empty / false / none |

The same safe extractor created a fresh copy. It added read permission to
regular files and read/search permission to directories (`mode OR 0444` and
`mode OR 0555`); **21 entries changed modes**. This permits UID 0 to read the
copy without DAC override. Original numeric ownership, modes and extended
attributes are explicitly **not preserved as image metadata**. No claim about
original ownership, permission or extended-attribute compliance can be made
from this copy. Regular-file bytes and original link targets were retained.

The second exact command is retained in its own `evaluation-command.txt`:

```bash
docker --host unix:///var/run/docker.sock create \
  --name ct-container-scap-gmob5epm-eval \
  --network none --cap-drop ALL --cap-add SYS_CHROOT \
  --security-opt no-new-privileges --read-only \
  --pids-limit 128 --memory 1536m --cpus 2 --user 0:0 --ipc none \
  --hostname ct-scap-offline \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777 \
  --mount type=bind,src=/tmp/ct-container-scap-Gmob5epM/rootfs,dst=/target,readonly \
  --mount type=bind,src=/tmp/ct-container-scap-Gmob5epM/content,dst=/content,readonly \
  --mount type=bind,src=/tmp/ct-container-scap-Gmob5epM/output,dst=/output \
  --workdir /output -e TMPDIR=/tmp --entrypoint /usr/bin/oscap-chroot \
  sha256:bab24e518ca05fc5335a3dc9cab85b9deb6c520abf335f9d30b4915bebcfaf5b \
  /target xccdf eval --profile xccdf_mil.disa.stig_profile_MAC-1_Public \
  --results /output/image-xccdf.xml --report /output/image-report.html \
  /content/benchmark.xml
```

```bash
timeout 300 docker --host unix:///var/run/docker.sock start --attach \
  ct-container-scap-gmob5epm-eval
```

Only the task output bind and private bounded temporary filesystem were
writable data locations. Docker's private runtime pseudo-filesystems remained.
No additional capability, privileged mode, host network/PID namespace,
host `/proc`, Docker socket, shared profile/state or service credential mount
was added. The export container was created but never started. Target and
benchmark binds were read-only during evaluation. No CPE override, tailoring,
remote fetch, remediation or target code execution was requested.

## Attempt 2: raw results and their limits

The engine emitted **393 `notapplicable` rows** and no other raw status:
pass 0, fail 0, error 0, notchecked 0, unknown 0, notselected 0, fixed 0,
informational 0. All 393 independently expected rules appeared, with no
unexpected or missing IDs. The XML was retained unchanged (1,616,287 bytes),
alongside the generated HTML report (2,028,642 bytes).

However, stderr contained this diagnostic pair three times:

```text
E: oscap:     RPM: cannot open Packages database in
error: cannot open Packages database in
```

The chroot-denied diagnostics and abort did not recur. The remaining database
diagnostics undermine confidence in platform detection: **all-notapplicable
does not establish that the controls genuinely do not apply**. No database
repair, path/CPE override, additional capability or third evaluation was tried.
Raw XCCDF error count 0 must not be confused with absence of engine diagnostics.

| Second-attempt raw evidence | SHA-256 |
| --- | --- |
| XCCDF | `dca566e7c8c1223498b28fd23e59eb1255b8d3e14558b243dd3a330decdb0177` |
| HTML report | `1671235dfac4795d2b92003107203eeebccf0f6928397ad813661af541c45b7e` |
| Engine stderr (285 bytes) | `b356d4714ae80a1376109edc8c631aa182bfc1baed3cceef3a286d1b71051ce4` |
| Engine stdout | `f5edc3eb8a5d8433dcb016fd687f8927c755a1624fe5a57601116ca709fdef3c` |

## Attempt 2: combined-source import acceptance

Product source was **`0261297db3d1ae1fdbbe7e9595bff8881d9945fd`**, extracted
from a local `git archive` into a task-owned directory. This includes the
standalone CLI's early authorization refusal before context initialization.
That guard's presence was inspected; verified/fleet refusal is not claimed as
part of this development acceptance. The importer, CLI and API source bytes
were checked against the commit and recorded in `source-identity.json`.
No product code or shared state was changed, and the source archive was not
merged into the runner branch.

Each separate disposable state used an explicit persisted inventory target:
`ubi9-nginx-image-20261106`, type `containers`, transport `fixture`,
`in_scope: false`, environment `isolated-image-acceptance`. Its authorization
generation and full harmless declaration are in each backend's inventory
receipt. There was no target connection. The original XCCDF and one explicit
`manifest.json` mapped this target to:

```text
source_id: ubi9-nginx-sys-chroot-20261106
test_result_id: xccdf_org.open-scap_testresult_xccdf_mil.disa.stig_profile_MAC-1_Public
benchmark_id: xccdf_mil.disa.stig_benchmark_RHEL_9_STIG
profile_id: xccdf_mil.disa.stig_profile_MAC-1_Public
expected_rule_ids: all 393 IDs from the original declared profile
engine: openscap 1.3.7; mode: rootfs; subject_ref: /target; exit_code: 0
```

The manifest also retains the exact image reference/digest and explicitly
declares normalized metadata and unverified RHEL host applicability. No expected
scope was inferred from returned rows. The same original XML bytes went through
the committed CLI and exact-repeat API requests; no compatibility edits were
needed.

The isolated runner used the existing Python 3.12.10 dependency environment.
It removed inherited service configuration, selected development/range mode
with a template explanation backend, disabled scheduling/proposals/content
updates, and used no HTTP listener. API reads used an in-process test client
without application startup tasks. Actor `Joshua Ott` was a development label,
**not a verified identity**. No live-cluster, verified-user, shared-profile,
transport or remediation acceptance is implied.

```text
python scripts/container-scap-live/accept.py PRODUCT_SOURCE RECEIPTS
```

For each backend the runner initialized inventory, then invoked a separate
product process with `CT_STATE_BACKEND=json` or `sqlite`:

```text
python -m cyberthunder.ingest.scap_cli --state-dir STATE --actor "Joshua Ott" image-xccdf.xml --manifest manifest.json
```

It then read findings, scan, commander JSON, POA&M CSV and checklist through
their existing API routes, repeated the exact import, closed the store and
repeated these reads in another process.

| Acceptance measure | JSON | SQLite |
| --- | --- | --- |
| Original CLI import exit | 0 | 0 |
| Exact-repeat import API | 200, repeated | 200, repeated |
| Findings / scan / commander / POA&M / checklist reads | All 200 | All 200 |
| Persisted raw observations | 393 not_applicable | 393 not_applicable |
| Coverage observation | 1 not_reviewed | 1 not_reviewed |
| Total findings / discoverable runs | 394 / 1 | 394 / 1 |
| Commander scanner pass / error | 0 / 0 | 0 / 0 |
| POA&M rows | 1 not_reviewed coverage row | 1 not_reviewed coverage row |
| Checklist rules | 394 across 2 checklist groups | 394 across 2 checklist groups |
| Observation hash and import receipt after restart | Identical | Identical |
| First / restarted reader PID | 23460 / 7092 | 11544 / 8840 |

The importer reports `result_scope_complete: true` because every declared rule
has a returned supported status and a completed exit-0 export. This is limited
to result presence: `platform_applicability: unverified`, `compliance_claim:
false` and scan `coverage_incomplete: true` remain. The separate coverage
finding stays `not_reviewed`. Commander output preserves 393 scanner NA,
1 scanner not-reviewed and explicit unverified-applicability text; these are
not passes. Reports do not ingest external engine stderr, so the retained
three RPM diagnostics must accompany any interpretation of these reports.
Fresh reports may have fresh rendering timestamps; byte-identical report
exports were not required or claimed.

No real-format product compatibility issue was found. Effective filesystem
coverage, trustworthy platform evaluation, original metadata compliance,
verified-user authorization and live-cluster behavior remain unverified.

## Attempt 2: retained artifacts and cleanup

Evidence is in
`.build/owner-evidence/container-scap-live-20261106-attempt2/`:

- `result-summary.json`, `acceptance-summary.json`, `report-outcomes.json`.
- Unchanged `image-xccdf.xml`, `image-report.html`, stdout/stderr, engine state,
  original exits, exact command and Docker protection inspection.
- `declared-scope.json`, `manifest.json`, extraction metadata, source identities,
  package/build receipts, per-backend inventories and CLI receipts.
- `json-first.json`, `json-restart.json`, `sqlite-first.json`,
  `sqlite-restart.json`, report exports and the isolated evidence states.
- Preservation, cleanup, handoff and receipt-hash manifests.

All **56 pre-existing receipt files** from preparation and attempt 1 were
hash-checked and preserved byte for byte. The new export/evaluation containers,
scanner image and Linux temporary directory were removed. The large disposable
product source archive and extracted source were also removed; their hashes
remain. The retained JSON/SQLite states are evidence-only directories under
this receipt root. Shared app/model fixtures and both k3d containers were left
untouched. No global image/cache prune, WSL package installation, full gate,
push, PR change or merge was performed.

Validation also passed shell syntax, parsing of the four Python helpers, all
six original extraction safety cases, and one additional readable-copy case
that checks unchanged file bytes, changed modes and explicit metadata caveats.
These checks did not rerun the scanner. `state-artifact-sha256.json` retains
hashes for the 822 final files across the two disposable evidence states.
