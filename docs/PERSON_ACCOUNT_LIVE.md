# Local person and account acceptance

On 2026-11-06 UTC, explicit v2 person associations passed **104 checks on JSON
and 104 on SQLite** against unchanged application source
`799aac915a321d78cbb28f5adb6e38fcba756a88`.
The tested Git tree is `1698d667c457923e42e7215bbdef0c4b9b53f43d`.
This is bounded local acceptance of [person associations](PERSON_ASSOCIATION.md)
and [separate account access](ACCOUNT_ACCESS.md), with no application source fix.

| Per backend | Passed |
| --- | ---: |
| Browser authentication and HTTP decisions | 86 |
| Real bearer identity, account grants and credential selection | 13 |
| Persisted decisions, findings and audit verification | 5 |

Each run retained 63 HTTP request/response records, including 22 refused
requests and seven vote refusals with unchanged before/after approval counters
and history. Each final audit chain contains 35 events, including 26 rejections;
both copied chains and their head checkpoints verify. Original findings remain
unchanged. SQLite's actual document database and the common proposal/inventory
files have separate storage hashes in the receipt bundle.

## What passed

- A proposer with the signed approver role and an explicit approval grant could
  not vote. Its separately authenticated privileged login, explicitly mapped to
  the same person, also could not vote. A spoofed actor label changed neither result.
- One other mapped person supplied the first CAT I vote, leaving `proposed`,
  one approval and no final decision actor. Repeating that account's vote or
  using its privileged second login could not supply another independent vote.
  A second distinct other mapped person completed the two-vote quorum. A low
  severity proposal required one independent vote.
- Normal and privileged logins retained different target visibility and action
  grants. The normal login could not acquire the privileged login's administrative
  or apply access; the privileged login did not inherit scan/proposal access.
  A pure application-admin account had no implicit approval role.
- Real signed bearer principals selected only their own SSH bindings: scan-only
  `fixture_scan` without sudo versus `fixture_change` with sudo for the separately
  granted apply target. Cross-account, wrong-action and wrong-environment selections
  failed. **No credential was resolved and no SSH connection was opened.**
- An unmapped authenticated account could neither propose nor vote. A conflicting
  duplicate subject mapping invalidated the policy, refused a vote and exposed no
  target grants. Revoking a recorded voter's mapping and advancing policy revision
  refused the next vote and native `start_apply`, preserving the existing decisions.
  Original historical quorum evidence remained verifiable; a new proposal pinned
  the new policy. The original policy bytes were not restored.
- Every browser login used the actual authorization-code/S256 flow, signed account
  claims and protected session cookies. Each logout invalidated API access.

## Fixture and limits

The existing local Keycloak **26.7.4** image was reused without pulling:
`sha256:3d911baa186f352563854039b95f21a7e2c01c76b527fdc64f24a0885b927bdf`.
A unique disposable container/realm held seven random-password synthetic accounts.
Windows Python 3.12.10 and installed Edge drove the unmodified application and real
token endpoints. Docker used WSL Ubuntu with explicit `unix:///var/run/docker.sock`;
only HTTPS loopback ports 1464 and 1465 were published/listening on the host.
Certificate trust was confined to child processes and the browser's exact public-key
pin. The fixture explicitly accepted password `acr=1` for 900 seconds; production
assurance defaults were unchanged.

The initial fixture token lacked `sub` because its client omitted the standard
Keycloak scopes. Authentication correctly refused it. That failed attempt is
retained under `initial-claim-fixture`; correcting the disposable client's scopes
to `profile`, `email`, `basic` and `acr` enabled the final runs.

Targets and findings were synthetic. An allowed admin request changed only fixture
inventory notes. Target transport remained explicitly simulated; no target apply,
rollback, remote privilege verification or external enclave operation occurred.
This does not establish CAC/PIV assurance, correct assignment of real people to
accounts, production PKI or operational enclave acceptance. Browser session and
decision APIs were exercised; the bundled application UI was not rebuilt or accepted.
No full suite, push or merge was performed, and frozen release gates were untouched.

## Evidence and cleanup

Sanitized local receipts are in `.build/person-account-acceptance/`, including
browser decisions, binding provenance, original/final findings, complete proposals,
policy variants, raw audit chains/checkpoints, storage hashes, source-file hashes,
the retained initial refusal and cleanup status. Receipts omit passwords, tokens,
keys, cookie/CSRF values and request headers; the artifact scan passed.

| Artifact | SHA-256 |
| --- | --- |
| `manifest.json` (64 files) | `837ad53e9fd216a3c4958d6a8c5acd983f5ec2c41d33e0375a180663139724b1` |
| `summary.json` | `519d425d92a789d0764dcdb6267477f620d3833f939daf8df44839ee706e87e8` |
| `json-browser.json` | `f621f6456f3797da7ceea02950c1e45c9e3d0d31a68938f9f6d0b33b3e59b722` |
| `sqlite-browser.json` | `f1bbf9c8318d8e815f69bda07d42d40a955ed3fc67e3eebbd60510a4b71a54e8` |

The owned container `ct-person-account-46b022f51d01` was stopped and removed,
destroying its disposable realm. Browser contexts closed, both application processes
stopped and both loopback listeners closed. No anonymous volume was created; other
containers, realms and preexisting ignored evidence were untouched.

**Private fixture cleanup is incomplete.** Windows policy trust required a new
protected state directory outside the checkout's unsuitable ancestor permissions:
`C:\ct-person-account-46b022f51d01`. Tool-execution policy rejected both recursive
removal and deletion of its three explicit credential files with only the reason
`blocked by policy`. The tool supplied no further rationale; this was not a
Windows file-permission error. The protected directory still contains temporary fixture
passwords, its TLS private key and application state; the corresponding IdP realm
no longer exists. These private files are excluded from the sanitized evidence.
`cleanup.json` records this unresolved deletion separately from the passing checks.
