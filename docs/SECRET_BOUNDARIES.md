# Lifecycle secret boundary regression (ZT-22)

This is a regression test and defect handoff, not a secret-isolation acceptance
claim. The implementation base is `24489ca`. Production files are unchanged.

## Confirmed defect and required owner change

The real discovery sweep passes the synthetic SSH credential to both local nmap
child processes through their inherited environment. The regression remains a
normal failing test, without an expected-failure marker or an output exclusion.

The owning path is `cyberthunder/transport/local.py`: `LocalTransport.__init__`
defaults `env` to `None` (lines 18-21), and `run` passes that value to
`subprocess.run` (lines 35-36). Python consequently inherits the entire server
environment, including `CT_CRED_LIFECYCLE_CANARY`. Discovery constructs this
default transport in `cyberthunder/discovery/service.py:375-377`; its ping and
port scans at lines 398 and 404-406 both reach the affected boundary.

The smallest concrete production fix belongs to the local transport owner:
replace unrestricted default environment inheritance with an explicit, reviewed
non-secret child environment. Preserve the platform variables required to find
and launch tools. Local nmap requires no target credential. Tools needing
credentials must receive only their explicitly authorized account material;
changing account bindings or removing the canary from the test environment
would not fix this defect. Other direct subprocess call sites need separate
review before making a project-wide isolation claim.

## What traverses real code

`tests/security/test_secret_canary.py` uses the normal JSON and SQLite state
fixtures. Each lifecycle run performs these operations before its final canary
assertion:

1. Create an explicit principal/resource credential grant, then call the actual
   authenticated target discovery API. The real SSH transport resolves the named
   environment credential, checks a pinned host key, and reaches the fixture
   authentication sink with agent and ambient key lookup disabled.
2. Run the scanner and persist a real finding using the existing stateful Linux
   fixture adapter. Generate and validate an explanation through the real
   explanation service, capturing the prompt sent to its fixture backend.
3. Propose a fix, approve it through the authenticated API, and execute it through
   the remediation engine. The fixture re-check reports failure after a genuine
   in-memory file change. The real engine records applied/failed transitions,
   checks the rollback baseline, restores the saved file through SSH/SFTP, and
   records `rolled_back`.
4. Inject a credential-bearing authentication exception at the Paramiko boundary.
   Capture the real sanitized API response and public transport exception.
5. Read identity, targets, findings, proposals/diff, status, audit and audit
   verification APIs. Render commander and POA&M reports, read report history,
   queue a commander report, inspect pending state, and run the real outbox sync
   service. Verify that one report moved and the outbox API reports no pending
   entries. Sync here is the existing local file move, not a remote transfer.
6. Save an explicit single-address discovery scope and execute the real quick
   sweep. Capture both child argument vectors and effective environments at
   `Popen`, including inheritance for `env=None`. No child is launched. The
   inventory retains its original target; no discovery observation is accepted.
7. Consume the actual finite audit SSE response and verify the audit chain.
   Search all collected outputs together after the lifecycle completes.

Only remote I/O, process creation, token validation, model generation, and the
fixture adapter's host-specific checks are substituted. Account authorization,
credential selection, SSH transport methods, scope/kill guards, services,
persistence, report renderers, route handlers, and SSE serialization remain real.
The token validator supplies controlled claims; this does not test signature
validation or browser sessions. Network connection functions are denied during
application work. TestClient's internal Windows event-loop socket pair is created
before that guard. Remote files live only in memory; all application writes stay
inside pytest temporary state directories.

## Detection and explicit input exceptions

`tests/security/canary_helpers.py` searches plaintext UTF-8 and UTF-16LE, standard
and URL-safe base64 envelopes, percent encodings with either hex case, and up to
two nested decoding layers. It decodes enclosing documents because the encoding
of a secret inside JSON need not contain the standalone encoding of that secret.
Calibration tests deliberately plant leaks in files and SQLite, including a
large SQLite value, and require detection. A public-reference control must pass.
Failure messages identify only boundaries and encodings, never secret excerpts.

The search includes every state file and filename, SQLite/WAL/SHM bytes when
present, logical SQLite table values, snapshots, raw scan artifacts, report
history, pending/synced outbox artifacts, DEBUG logs, model prompts, captured API
response bodies and headers, public exceptions, audit SSE, remote command text,
and child argv/environment. The protected access policy is included: it contains
references, not the credential. No application-output path is excluded.

The synthetic canary constant and deliberately planted calibration fixtures are
test inputs, not application outputs. The server's source credential environment,
incoming fixture Authorization header, validator input, and Paramiko password
argument are intentional authentication inputs. These are not treated as leaks;
the test explicitly checks that the SSH password reaches its designated sink.
Copies forwarded to a scanner child are application outputs and are checked.
There is no secret-bearing configuration-file exemption.

## Reproduction and limits

From the scope-recipes checkout in PowerShell:

```powershell
$env:PYTHONPATH='C:/Users/joshu/.codex/worktrees/scope-recipes/cyber-thunder'
& 'C:/Users/joshu/.codex/worktrees/coverage-report/cyber-thunder/.venv/Scripts/python.exe' -m pytest tests/security/test_secret_canary.py -v --tb=short --show-capture=no --disable-warnings
```

Measured on Windows with Python 3.12.10: **8 passed, 2 failed** in 19.88 seconds.
Both failures are the lifecycle case, once for JSON and once for SQLite; all
calibration tests pass. Nine existing framework deprecation warnings were emitted.

The lifecycle failure identifies `child 1 environment (plaintext)` and
`child 2 environment (plaintext)`. The other captured boundaries contain no
detected canary in this scenario. Keep these regressions failing until the owning
production fix is integrated; rerun both state backends after that change.

This bounded scenario does not validate WinRM, Kubernetes credentials, real
remote authentication, model HTTP authentication or response reflection,
cryptographic token validation, browser-session/CSRF flows, every adapter and
failure branch, or actual network outbox delivery. It does not prove the absence
of arbitrary encodings, compression, fragmented log messages, or timing/memory
side channels. OS process launch is captured rather than performed. Platform
compatibility of a production environment fix needs Windows and Linux/container
validation. Further expansion stopped on the confirmed production leak.
