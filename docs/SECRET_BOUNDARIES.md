# Lifecycle secret boundary regression (ZT-22)

This regression exercises a credential through the application lifecycle and
checks its output boundaries. It is not a universal secret-isolation claim.

## Confirmed defect and correction

The original discovery sweep passed the synthetic SSH credential to both local
nmap child processes through their inherited environment. The regression caught
the leak on both JSON and SQLite without an output exclusion.

`LocalTransport` now supplies an explicit environment containing only executable
search paths, Windows platform paths, temporary paths, locale and timezone.
Application credentials, proxy credentials, shell startup hooks, loader variables
and credential-agent references are excluded. Explicit environment overrides use
the same allow-list and reject unsupported or ambiguous entries. Dependency reads
also use this filtered environment. Bash no longer starts as a login shell, CMD
disables AutoRun, and PowerShell retains `-NoProfile`.

Local nmap requires no target credential. Tools needing credentials must receive
only their explicitly authorized account material. The canary remains present in
the server environment and reaches the intended SSH authentication sink. Other
direct subprocess call sites and tools' own configuration lookup need separate
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

From the repository with its test dependencies installed:

```sh
python -m pytest tests/security/test_secret_canary.py tests/security/test_local_environment.py -v --tb=short --show-capture=no --disable-warnings
```

Before the correction, Windows Python 3.12.10 recorded **8 passed, 2 failed**;
both failures were the lifecycle case, once per backend. After the correction,
**22 passed** in 19.41 seconds, with existing framework deprecation warnings.
The additional tests launch a real Python child to verify environment exclusion,
exercise the dependency-collector boundary, and check explicit override refusal.
The same committed correction (`9557257`) passed **22 tests** on native Linux
under WSL with Python 3.12.16 in 10.73 seconds. No test was skipped on either
platform. Both runs used isolated fixture state and no remote targets.

The original failure identified `child 1 environment (plaintext)` and
`child 2 environment (plaintext)`. The corrected lifecycle contains no detected
canary at those or the other captured output boundaries.

This bounded scenario does not validate WinRM, Kubernetes credentials, real
remote authentication, model HTTP authentication or response reflection,
cryptographic token validation, browser-session/CSRF flows, every adapter and
failure branch, or actual network outbox delivery. It does not prove the absence
of arbitrary encodings, compression, fragmented log messages, or timing/memory
side channels. The lifecycle captures process creation; the separate local
environment test launches an actual Python child. The deployed container and
the remaining credential paths still need their own validation.
