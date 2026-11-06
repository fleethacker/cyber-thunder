# SSH key boundary review

Reviewed candidate `1338f164589434d7c58b5f11efc4351f9e14fbfc` against base
`c0bec2996ac99c4cbf03a051b3c5e5f446e88ef8`. Review was limited to the six SSH-key
candidate paths and this report. Shared file-trust code, account policy, UI,
global documentation and CI skip policy were not changed.

## Confirmed findings and repairs

| Priority | Finding | Repair and regression evidence |
|---|---|---|
| P2 | Provider parsing accepted ambiguous input: appended keys/text, mismatched END labels, OpenSSH binary trailers and some leading text. Some OpenSSH header fields were also not enforced by the selected parser. | Require one matching envelope, canonical base64, exactly one unencrypted OpenSSH key with empty KDF options, and complete binary/public-private agreement validation. Tests mutate all five supported RSA/ECDSA/Ed25519 encodings and OpenSSH headers. |
| P2 | A fixed error message did not remove private material from traceback locals. Failed parsing retained raw bytes/text in the loader frame; a host-pin exception retained the parsed key in provider frames. | Isolate secret-bearing reader/parser frames below the public error boundary. Reconstruct host-trust errors outside the provider handler. Tests inspect loader traceback locals and use weak references to prove release after real host-pin failure. |
| P2 | Partial public-key authentication entered the provider's keyboard-interactive fallback, despite disabled agents and key discovery. A loopback server completed authentication using this additional method. | Use the provider's explicit authentication-strategy interface for one public-key attempt and require `is_authenticated()`. Real loopback tests reject partial success without invoking keyboard-interactive or returning an unauthenticated client. |

These are bounded credential-selection and secret-lifetime findings. The tests
do not establish an independent remote-memory disclosure. Python/provider
allocation erasure remains outside the guarantee.

## Validation boundary

The native mounted reader remains responsible for ownership, permissions,
ancestor checks, links, identity rechecks and the 32 KiB cap. Existing targeted
Windows DACL/handle/junction and POSIX mode/owner/descriptor-race cases are kept.
Exact-limit and overflow tests verify the SSH caller's size contract. No shared
native-file-trust gap requiring an out-of-scope repair was found in this review.

Supported RSA PEM/OpenSSH, ECDSA PEM/OpenSSH and Ed25519 OpenSSH keys authenticate
to a real loopback peer with the expected username and public key. Tests retain
host-pin denial, no pathname reopen or adjacent-certificate lookup, no ambient
agent/key discovery, fresh reconnect reads, distinct account/action keys and
sudo restrictions. Current-principal checks, revocation and missing-selected-key
denial run with both JSON and SQLite. Password-lease integration is included in
the focused regression selection.

Rejection, partial authentication, authentication timeout, authorization
revocation during loading and deadline expiry must close the client and release
handler/strategy key references. Parser/provider diagnostics exclude private
material. Production protections were not relaxed for fixtures.

## Reproducible evidence and integration

Evidence for this review is preserved in the local ignored directory
`.build/ssh-key-review-20261106-58d4bbd4/`. Its final `receipt.md` identifies the
repair commit, exact commands, native runtimes, source hashes, test counts and
cleanup results. Per-platform JSON receipts bind each run to every file in its
exported source snapshot. `committed-manifest.json` binds the final changed
files to the commit; documentation can be finalized after the executable tests.

Candidate regressions run with the original production sources plus review
tests. Final focused validation includes:

```text
python -m pytest -p tests.ssh_key_support tests/security/test_ssh_key_credentials.py tests/security/test_credential_binding.py tests/security/test_account_transports.py tests/transport/test_bound_accounts.py tests/transport/test_ssh_trust.py tests/transport/test_factory.py tests/transport/test_trust_guards.py tests/security/test_secret_transport_integration.py -ra --tb=short
```

Both native platforms use `CT_STATE_BACKENDS=json,sqlite`. Private test files
are generated in private temporary directories outside Git. Socket connections
and DNS are limited to loopback by the test support plugin; no operator secrets
or external targets are used. Disposable sources, private files, peers and
clients are cleaned up; prior ignored evidence is retained.

The review adds no platform-specific tests or skips beyond the candidate's
13 POSIX cases (skipped on Windows) and 14 Windows cases (skipped on Linux).
`platform-skips.md` and `platform-skips.json` list their exact pytest node IDs,
reason strings and opposite-platform pass evidence. They are new relative to
the integration parent's pre-key skip allowlist. The parent owns the exact
allowlist/cap update in `scripts/ci_pytest.py`; this review supplies evidence
without changing CI policy or claiming that the full gate has passed.

## Remaining limits

Static unencrypted provisioned keys only; no passphrase, SSH certificate,
broker issuance or short-lived key guarantee. OS service identity and native
administrators remain trusted. Local file ownership does not establish human
identity or remote account privileges. File deletion alone does not end an
existing authenticated session; existing authorization/kill-switch guards still
apply, and reconnects reread the protected file. No full gate, push or merge is
part of this review.
