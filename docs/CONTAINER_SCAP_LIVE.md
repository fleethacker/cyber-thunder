# MVP-04 isolated container image evaluation — 2026-11-06

**Outcome: the single actual OpenSCAP evaluation aborted with exit 134 and
produced no XCCDF or HTML report. Real-image import acceptance remains open.**
The RPM probe attempted `chroot`, which was denied under the required dropped
capabilities. The engine was not rerun with more access. This is not evidence
that UBI is clean, compliant, applicable to the RHEL host STIG, or entirely
not applicable.

## Source and environment

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

## Immutable inputs and scanner versions

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

## Execution and protection limits

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

## Actual results and import acceptance

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
fresh-process persistence checks. The failure does not authorize increasing
scanner capabilities or changing the existing cluster.

## Receipts, cleanup and bounded automation

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

From WSL, any separately authorized future attempt would use
a new empty receipt directory:

```bash
bash scripts/container-scap-live/run.sh "$PWD" "$receipt_dir"
python3 scripts/container-scap-live/cleanup_task.py "$receipt_dir"
python3 scripts/container-scap-live/record_result.py "$PWD" "$receipt_dir"
```

Cleanup is a separate command so an engine failure cannot skip it through
shell `&&` chaining. The recorder only reads receipts and the benchmark; it
does not run another evaluation or import anything. No full project gate,
push or merge was performed.
