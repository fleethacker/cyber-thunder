# Scoped scanner coverage: k3s/k3d and compatible Linux range platforms

This implements SCAN-01 and SCAN-04 capabilities. Neither live-platform acceptance
is closed by fixture tests. No changes to cluster resources, host configuration,
remediation deletion behavior, authentication, or the central backlog are part of
this work.

## k3s configuration and k3d collection (SCAN-01)

An explicitly configured Kubernetes target can read its local k3d servers:

```json
{
  "kubeconfig": "/operator/range/kubeconfig",
  "context": "k3d-range",
  "k3d_cluster": "range"
}
```

The normal kubeconfig collector obtains the cluster version and control-plane
node names. Only matching `k3d-<cluster>-server-<number>` nodes are eligible.
Docker must report the same container name, matching `k3d.cluster` and
`k3d.role=server` labels, a running state, and a full immutable container ID.
The collector reads the server process command line, environment and fixed
configuration paths through that ID. It does not accept a Docker executable,
daemon URL, container name, command, or file path through target options.
Docker environment overrides are removed and the default local context is used.
The inventory declaration, scope and kill switch are checked before every Docker
operation. The operator must already have local Docker access.

Use either `k3d_cluster` or the existing SSH `node_target`, never both. A k3d
cluster on another machine, another Docker context, or inside stopped WSL is not
automatically accessed. The collector does not start containers, WSL or VMs.

The fixed reader collects `/etc/rancher/k3s/config.yaml` followed by
`/etc/rancher/k3s/config.yaml.d/*.yaml` in bytewise alphabetical order. It limits
collection to 128 files of at most 1 MiB each, rejects symlinks and non-regular
files, and distinguishes absent files from failed or truncated reads. Later
component argument lists replace earlier lists; a key ending in `+` appends.
Command-line component argument lists replace the configured list. Only parsed
component flags and source paths are retained; join tokens and raw environment,
Docker inspection, and configuration bodies are not saved.

All six API-server rules produce explicit pass/fail findings when their k3s
configuration is collected. Missing, invalid or partial data produces
`not_reviewed`, including a failed read from any server in a multi-server k3d
cluster. Findings name their server and retain the limitation that configured
flags and documented defaults do not prove runtime activation after a config edit.
Historical or partial flag records without a complete collection marker and
required default fields require a fresh scan rather than producing passes.
Unsupported custom config paths, influencing environment overrides, and ambiguous
server process layouts are unavailable coverage rather than inferred defaults.

The existing SSH path also reads sorted drop-ins. It requires successful config,
ExecStart and service-environment queries. Service environment/environment-file
declarations currently require manual review; this conservative limitation avoids
assuming that unread environment files cannot override the collected settings.

The precedence follows the [K3s configuration documentation](https://docs.k3s.io/installation/configuration).

## Explicit compatible-platform alias (SCAN-04)

The alias is optional and disabled unless explicitly present on a Linux target:

```json
{
  "benchmark_path": "/var/lib/cyberthunder/scap/U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.xml",
  "profile": "xccdf_mil.disa.stig_profile_MAC-1_Classified",
  "cpe_alias": {
    "source_os": "rocky",
    "source_major": 9,
    "cpe": "cpe:/o:redhat:enterprise_linux:9.0",
    "reason": "Authorized isolated Rocky 9 compatibility range assessment"
  }
}
```

Only the declared `rocky` or `almalinux` distribution on observed major release 9
can use that exact RHEL 9 CPE. The reason is mandatory and bounded to 300 printable
characters. Unknown keys, missing observed identity, another major release,
another CPE, and fleet mode are rejected. There is no automatic RHEL fallback.
Execution requires SSH to Linux or a POSIX local transport; a Windows local shell
is rejected because the collector's quoting and commands are POSIX-specific.
The compatible distribution is still the observed OS; the alias is not a claim
of vendor support or full benchmark applicability.

The target must already hold a self-contained DISA RHEL 9 source datastream, with
the expected benchmark identity and platform declaration. Reads are bounded to
32 MiB of UTF-8 XML; DTD/entity declarations and external component references are rejected.
The selected profile must exist in the captured benchmark. The supplied original
is never modified. An identical copy and a small additional CPE dictionary/OVAL
document are placed in a private per-run temporary directory. OpenSCAP receives
the dictionary through `--cpe`. The additional OVAL definition checks the actual
`/etc/os-release` distribution ID AND major version during evaluation; it does
not return an unconditional true result. Rule content, applicability expressions,
and scanner statuses are unchanged. The
[OpenSCAP applicability documentation](https://static.open-scap.org/openscap-1.4.1/oscap_user_manual.html#_cpe_applicability)
describes additional dictionaries and fallback lookup after an embedded CPE does
not apply.

Target scope, configuration identity and kill state are rechecked before reads,
staging writes, evaluation, fetch and cleanup. Commands use quoted arguments;
only generated fixed filenames are used inside the validated private directory.
Exit codes other than 0 or 2 do not produce accepted results. Cleanup deletes
only those files and removes the empty directory. If the kill switch or scope
changes, no additional target commands are sent and retained staging is reported.
The scan performs no remediation and never passes `--remediate`.

The saved result contains the exact alias and reason, observed OS facts, target
identity/address/port/transport, original path and benchmark ID, profile, collection
time, and SHA-256 hashes of the original content and both generated alias files.
These appear in `Collected.raw.cpe_alias`, `cpe_alias/provenance.json`, and every
parsed OpenSCAP finding's `collection_provenance.cpe_alias`. The original and
generated content are retained alongside provenance for reproducibility.
Findings carry `platform:cpe-alias` and a visible applicability warning; merging
native evidence preserves that warning and provenance.

The existing scanner audits collector diagnostics in `scan.target`. The override
is deliberately inserted as the first diagnostic (labelled a warning), so the
engine's twenty-entry diagnostic limit cannot drop it. This makes affected scans
visibly partial even when evaluation succeeds. No adapter writes the audit log
directly. Normal applicability remains `unverified`; alias use does not clear
platform warnings or convert `notapplicable` results to a pass.
Missing/invalid/wrong-benchmark result files are not accepted. If no rules produce
pass/fail results, the observation is partial and explicitly leaves platform
acceptance open.

## Acceptance and handoff

| Item | Implemented and tested | Acceptance still open |
| --- | --- | --- |
| SCAN-01 | Sorted replace/append drop-ins; CLI precedence; real isolated file collection; guarded k3d multi-server collection; explicit API-server pass/fail and missing-data states | A scan of an already-running authorized k3d cluster showing measured per-server pass/fail. No local Docker executable or running WSL distribution was available during this work. |
| SCAN-04 | Explicit bounded range alias; inspection of repository DISA RHEL 9 content; exact-byte preservation; conditional OVAL generation; result provenance, audit persistence, warning retention and failure/guard tests | Actual OpenSCAP execution of DISA RHEL 9 rules on Rocky 9, showing evaluated rules and the recorded override. No available OpenSCAP executable or running WSL distribution was found; no VM was started. |

`scan_content.CONFIG_OPTIONS` includes the complete `cpe_alias` declaration in
the preflight freshness fingerprint. Changing the declaration invalidates a
previous observation; stored results retain the exact declaration originally
used. Each new alias evaluation validates the current inventory.

Dependencies: no new packages. The implementation uses the existing PyYAML and
Python standard library. Focused tests run with the shared Windows interpreter
and `PYTHONPATH` pointing at this checkout. No UI changes require a UI build.

Changed paths:

- `cyberthunder/adapters/kubernetes/adapter.py`
- `cyberthunder/adapters/kubernetes/checks.py`
- `cyberthunder/adapters/kubernetes/k3s.py`
- `cyberthunder/adapters/kubernetes/k3d.py`
- `cyberthunder/adapters/linux/adapter.py`
- `cyberthunder/adapters/linux/checks.py`
- `cyberthunder/adapters/linux/cpe_alias.py`
- `tests/kubernetes/test_k3s_and_review_fixes.py`
- `tests/kubernetes/test_scanner_coverage.py`
- `tests/linux/test_cpe_alias.py`
- `docs/SCANNER_COVERAGE.md`

Validation commands (PowerShell, from the assigned checkout):

```powershell
$env:PYTHONPATH = 'C:/Users/joshu/.codex/worktrees/kubernetes-fix-safety/cyber-thunder'
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' `
  -m pytest tests/kubernetes tests/linux tests/scan_content/test_collectors.py -o addopts= -q
git diff --check
```

Final measured result on 2026-11-05: **394 passed in 43.57s** for the command
above, covering both state backends where parametrized. `git diff --check` and
the staged diff check were clean. All eleven changed files use LF, and all ten
Python files parsed successfully. No UI tests or whole-project gates were run;
the parent owns combined gates after integration.

The real-file collector test uses a temporary directory with the fixed paths
redirected only in the test, including a non-regular file rejection. CPE tests
inspect the repository's DISA RHEL 9 datastream and simulate transport/engine
responses; they do not constitute a real OpenSCAP or Rocky platform evaluation.
