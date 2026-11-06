# Node hardening independent review

Reviewed base: `2c9d755903446ee2ef6edcccf34f9bf94b7e84ff`.
This follow-up is separate from the frozen identity candidate. It changes only
the assessment, its dedicated CLI handler, focused tests and these documents.
The shared Windows trust validator, main CLI dispatcher, configuration, host
policy and CI skip policy are unchanged.

## Findings and fixes

1. **Final metadata overrun could report protected.** The native-check fixture
   completed its final validation after the configured budget, but the original
   assessment returned a complete protected observation. The final checkpoint now
   returns incomplete/unknown after that call returns. This remains a cooperative
   budget: it cannot interrupt a blocked filesystem call or bound cleanup time.
2. **Unknown inheritable Windows rights could report protected.** A real native
   DACL containing a foreign inherit-only allow with reserved mask `0x200` passed
   the original whole-directory assessment. Unknown inherited rights now produce
   `unknown / unrecognized_inherited_rights`. The native SID/handle validator is
   still used; no effective-access interpretation or host ACL repair is added.
3. **The CLI's default relative state path was unusable.** Even an existing private
   `state` directory returned unknown. The dedicated handler now anchors ordinary
   relative paths to the current directory using `Path.absolute()`, without
   `resolve()`. Tests cover the default, explicit argument and environment value,
   rejection of `..` and empty paths, and Windows drive-relative/root-relative
   rejection. The core assessment retains its absolute-path requirement.

The first two findings were reproduced as failing regressions before their fixes.
The relative-path improvement also had three failing CLI regressions before its
implementation. No unresolved defect was found in the reviewed command's
application-authorization exception: it compares handler identity, and the
regressions exercise refusal of status, proposal approval, kill release, audit
tail and discovery sweep in OIDC, mesh and development/fleet configurations.

## Native evidence

The same selected test set was run on Windows and on a fresh Linux source copy:

```text
python -m pytest -o addopts= -q -ra tests/security/test_node_hardening.py tests/security/test_node_hardening_review.py tests/security/test_windows_file_trust.py tests/security/test_windows_file_trust_review.py tests/security/test_identity_boundary.py::test_local_cli_cannot_bypass_verified_mode
```

The receipt runner records collection IDs and actual outcomes from pytest hooks.
It verifies each source file's SHA-256 before importing the assessment and checks
that the imported module belongs to the tested source directory. Both platforms
verified the same 613-file source manifest, including the original tests and the
new review test module, excluding the UI and documentation:

```text
399b3d859a064f1a4ad91eda148a29cebea0719bc448674d44f15eeed7a0d3b0
```

The digest is SHA-256 of sorted lines `file_sha256`, two spaces, relative path,
newline. The receipts retain hashes for the assessment, dedicated handler, main
CLI, shared trust validator, fixtures and both assessment test modules.

| Platform | Full focused run | Assessment modules only | Receipt |
| --- | --- | --- | --- |
| Windows 11, Python 3.12.10 | 118 passed, 13 skipped; 7.14 seconds | 54 passed, 13 skipped | [Windows](node-hardening-review/windows.json) |
| WSL2 Linux, Python 3.14.4 | 59 passed, 72 skipped; 2.69 seconds | 58 passed, 9 skipped | [Linux](node-hardening-review/linux.json) |

Both runs had zero failures and one existing Starlette/httpx deprecation warning.
Receipt elapsed times include the surrounding pytest runner overhead. The
assessment modules collected exactly the same **67 IDs** on both platforms;
every ID passed on at least one platform. JSON and SQLite fixture parametrization
remained enabled. Linux source files were copied to its native home filesystem
(`stat -f` reports `ext2/ext3`); pytest fixtures used native `/tmp` tmpfs. Neither
test execution nor permission fixtures used the Windows-mounted checkout.

Windows fixtures use real disposable SID/DACL descriptors, native held handles,
revoked directory permissions, directory inheritance, protected-file checks and
junctions. No user-profile ACL or source-directory ACL was changed. The new
handle test checks the kernel after assessment because a regular-file handle can
be transferred to a Python stream and closed without a direct validator call.

Linux fixtures exercise real no-follow, nonblocking and descriptor-relative opens,
private modes, extended default ACLs, FIFO/symlink refusal, concurrent path swaps,
renamed roots, failure cleanup, entry/depth limits and sanitized metadata errors.
The cross-filesystem regression injects only a consistent changed device ID into
native stat results and proves the child directory is not enumerated. It does
not mount a filesystem or certify real mount/bind-mount semantics. The deadline
regression advances a controlled clock after a real native metadata check; it is
not a measurement of an interruptible kernel timeout.

## Exact platform skips for integration

Each receipt contains `assessment_collected_ids` and `assessment_skips`, with
literal parametrized node IDs and the exact reason emitted by pytest. The latter
contains only the two new assessment modules, which are the proposed additions
for the parent's explicit platform allowlist. No wildcard or global skip-policy
change is proposed.

- Windows: seven original Linux-only assessment cases plus six review cases
  (five descriptor/race cases and one filesystem-boundary case), **13 total**.
- Linux: five original Windows-only assessment cases plus four review cases
  (inherited-mask, SID/revocation and two drive-path cases), **9 total**.
- The Linux full run additionally skipped **63 existing** cases in the two native
  Windows file-trust modules. Their existing platform policy is unchanged.

Raw full-run receipts, logs and the complete source manifest are retained in the
review checkout's ignored `.build/node-hardening-review/` directory. The committed
receipts provide the exact new skip IDs without relying on grouped `-ra` output.

## Remaining acceptance limits

This is a bounded metadata observation, not an atomic snapshot, continuing
enforcement or hardening approval. A blocked filesystem call can still block the
command. Same-device bind mounts, network filesystems, encrypted volumes,
service-account rollout, container confinement, consistent backup/restore and
the organization's node review remain separate acceptance work. The command reads
no file contents or database rows and outputs no arbitrary paths, filenames,
SIDs or native exception text. It never repairs permissions or starts a service.
