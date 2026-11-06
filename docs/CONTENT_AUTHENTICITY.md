# Offline content authenticity

A SHA-256 digest establishes that bytes match a manifest. It does not identify who supplied that
manifest. Offline bundles can now carry an **operator attestation**: a signature by a key explicitly
trusted on this node. This is never described as a DISA signature or proof that DISA authored the files.
The existing download host allow-list, TLS checks and XML/archive checks remain separate controls.

## Trust and configuration

Set `CT_CONTENT_TRUST_CONFIG` to the absolute path of a protected JSON file. Application startup
loads it into `ctx.content_signature_config` before constructing services or creating state. The safe
configuration loader is `signatures.load_config(path)`; API requests cannot select the trust file:

```python
from cyberthunder.ingest.content import signatures

# settings.content_trust_config comes from CT_CONTENT_TRUST_CONFIG at startup.
ctx.content_signature_config = signatures.load_config(settings.content_trust_config)
```

With no configured path, the application trusts no offline signers. A configured but invalid file
fails startup without creating state; there is no silent fallback. JSON schema:

```json
{
  "version": 1,
  "scope": "enclave-a",
  "trusted_keys": {"courier-2026": "/protected/keys/courier-public.pem"},
  "signing_key": "/protected/keys/request-private.pem",
  "signing_key_id": "request-2026",
  "signing_password_ref": "CONTENT_SIGNING"
}
```

Omit all three signing fields on an import-only node. The loader rejects duplicate/unknown fields,
relative paths, inline passwords, oversized files, unsafe permissions and non-Ed25519 trusted keys.
It reads at most 64 KiB. It does not read a signing password until signing. Embedded applications may
also supply the typed object directly from their protected startup configuration:

```python
from pathlib import Path
from cyberthunder.ingest.content.signatures import ContentSignatureConfig

ctx.content_signature_config = ContentSignatureConfig(
    trusted_keys={
        "request-2026": Path("/protected/keys/request-public.pem"),
        "courier-2026": Path("/protected/keys/courier-public.pem"),
    },
    scope="enclave-a",
    signing_key=Path("/protected/keys/request-private.pem"),  # omit on an import-only node
    signing_key_id="request-2026",
    signing_password_ref="CONTENT_SIGNING",  # optional encrypted-key password reference
)
```

Use native absolute paths on Windows. Public keys are PEM SubjectPublicKeyInfo Ed25519 keys; private
keys are PEM Ed25519 keys, preferably encrypted PKCS#8. A password reference reads only
`CT_CRED_<reference>` on the signing machine. Never pass a password in a CLI argument, manifest,
request body or configuration object. Signing does not automatically trust that key on another node.

The key file and its ancestors must be real, stable paths with protected ownership and permissions.
Links, reparse points and hardlinked keys are refused. POSIX private-key files must exclude all
group/other permissions; public keys and parent directories cannot be writable by untrusted accounts.
Windows checks owners and DACL allow entries conservatively: only the current account, SYSTEM,
Administrators and TrustedInstaller may modify trusted paths or read a private key. OWNER RIGHTS is
accepted only after checking the owner. Unsupported ACE types and null DACLs fail closed. Existing
ACLs are never changed automatically. An otherwise private key beneath an untrusted writable ancestor
is refused; provision a protected location with the host administrator.

There is no automatic trust discovery, embedded-key trust, URL key lookup or new dependency. The
review used the installed `cryptography==50.0.2` Ed25519 implementation, already required transitively
by `PyJWT[crypto]` and `paramiko`; this patch adds no package requirement. Runtime environment
settings for this configuration are read at startup. Never read trusted-key paths or
signing credentials from an import request. Key-file changes are checked again on each verification;
changes to the configured signer map require replacing the context configuration or restarting.
Accepted attestations record the exact public-key SHA-256 fingerprint (DER SubjectPublicKeyInfo)
as `key_sha256`, so replacing a key while retaining its ID does not make historical signer evidence
ambiguous. Retained in-process attestations reverify their original signed bytes against current keys.

## Courier workflow

1. On the receiving node, export the requested content manifest. With a configured signing key,
   `write_manifest()` writes a signed request. Verified/fleet mode requires that key. The manifest is
   a portable file with both JSON and SQLite state backends.
2. On a connected operator workstation, verify the request, fetch its listed files, perform integrity
   checks and sign the resulting lock. Use a fresh, empty output directory for signed fetches:

   ```bash
   python -m cyberthunder ingest fetch-manifest request.json --out courier-bundle \
     --require-signed --content-scope enclave-a \
     --trusted-key request-2026=/protected/keys/request-public.pem \
     --signing-key /protected/keys/courier-private.pem --signing-key-id courier-2026 \
     --signing-password-ref CONTENT_SIGNING
   ```

   This standalone fetch utility uses the local development CLI profile; it does not establish an
   authenticated application session. Signing requires possession of the protected operator key.
   A request signature is checked before any network request. Failed downloads cannot produce an
   importable signed lock. Signed fetches require a fresh directory and a complete response on each
   attempt; existing partial bytes cannot become operator-attested merely by matching an ETag. The
   complete response hash must match the stable file used by the parser. Request trust is checked
   again before signing the lock. Unsigned development fetches retain resumable downloads.
3. Transfer the complete folder: `manifest.json`, `manifest.lock.json` and exactly the files listed in
   the lock. Import through `POST /api/v1/ingest/import-dir` with `{"path":"<folder on this node>"}`.
   Configure the request and courier public keys and the same scope on the receiver.

The lock binds the request digest, all file hashes/sizes, exact paths, and content metadata. The
receiver checks both attestations and the request/lock agreement, stages bounded stable copies, and
checks every listed file before parsing any archive. Missing, extra, duplicate or ambiguous paths,
modified metadata, digest mismatches and invalid signatures refuse the bundle. A standalone operator
lock may use `manifest: null`; it still binds every listed file and the configured scope.

## Development imports and explicit exceptions

Unsigned imports remain available in `dev`/`range` with `authenticity.status: "unsigned_dev"`,
`operator_attested: false` and `disa_signature: false`. Existing records without provenance are
reported as `legacy_unverified`. Integrity checks continue to apply; a development lock can still
detect a changed file without establishing authenticity.

In verified authentication modes or the fleet profile, unsigned content and unknown signers are
refused unless the **current authenticated human** explicitly overrides with a reason. Both the
`import` and `admin` role permissions and node-policy grants are required. A typed actor name,
workload token or caller-supplied permission flag cannot authorize an exception.

For folder imports, send an additional `override_reason` string (1–512 characters). Raw
`/ingest/content/upload` accepts one `file` part and an optional text `override_reason` part; the
legacy `/ingest/stig` JSON path body accepts the same reason. Signed packages use the folder route.
No UI override control is provided here. CLI `--override-reason` does not establish identity or bypass
the existing verified-mode CLI restriction.

An exception records `human_override`, the verified actor and reason in `content.authenticity` audit
events and held-content provenance. It is never relabelled as a verified signature. Invalid signatures
from known keys, malformed envelopes, wrong scope and file-integrity failures cannot be overridden.
Trust, current principal/session validity and authorization are checked again before publication.
Provide a nonsensitive reason; private key bytes, passwords, bearer tokens and raw signatures are
never part of diagnostics or authenticity audit fields.

## Authorized live updates

Verified nodes retain normal authorized live pulls through the existing fixed-host, certificate- and
hostname-verifying HTTPS `ContentClient`. These records carry `trusted_https_source`: **transport
provenance**, with the approved final URL, exact response SHA-256 and byte count. Neither
`operator_attested` nor `disa_signature` is true. The existing admin role/node permission, kill switch,
link state, session/account validity and transfer accounting remain enforced.

Only the downloader can mint this in-process receipt. It requires the narrow production transport,
checks redirected URLs, hashes the response as received and parses a private snapshot matching those
bytes. Verified live downloads start fresh instead of trusting an earlier partial file. Publication
checks the hash and authorization again. Caller-supplied metadata, serialized download results,
injected transports or an unsigned folder cannot assert HTTPS provenance. Copying a previously
downloaded file onto offline media still requires a trusted signed lock or the authorized human
exception. Evidence dictionaries, including ones placed into the internal receipt context, cannot
claim either HTTPS provenance or a verified operator signature. Receipts bind their authorized
hash/size pairs, context and actor. The trusted runtime is not a Python sandbox: arbitrary code
execution or mutation of internal modules is outside this boundary.

Raw upload and legacy STIG routes authorize their exception before parsing content. Final acceptance
copies the source into a private bounded snapshot. Parsing, catalog updates and publication use those
same bytes; changing the caller's source after its hash check cannot replace them. Session, policy,
signer trust and kill state are rechecked after validation/audit and before publication. SCAP extraction
is staged privately until that final check. Live job staging is removed when the job finishes.

## Wire format and bounds

The envelope is flattened [JWS](https://www.rfc-editor.org/rfc/rfc7515.html) with exactly `protected`,
`payload` and `signature`. The protected header contains only `alg: "EdDSA"`, a configured `kid`, and
`typ: "application/vnd.cyberthunder.content+jws"`. Only Ed25519 keys and 64-byte signatures are
accepted, using [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html) and
[cryptography's Ed25519 implementation](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).
No alternate algorithm, unsigned header, embedded key or critical extension is accepted.

The payload is `{version: 1, kind: "request"|"lock", scope, document}`. Header and payload use sorted
ASCII field names, compact JSON separators and ASCII JSON string escapes; floats and negative or
unsafe-sized integers are forbidden. This is a documented restricted JSON profile, not a general
RFC 8785 implementation. Base64url is unpadded and canonical. Signatures cover the standard JWS
`protected.payload` ASCII bytes. Receivers reject noncanonical signed JSON and duplicate object keys.

Limits: 1 MiB envelope, 512 KiB decoded document, 512 files, 512 MiB per file (or a lower configured
content cap), 2 GiB per bundle, 32 trusted keys, 64-character key IDs/scopes, and bounded metadata
and nesting. File names are single portable basenames; case aliases, traversal, device names and
archive duplicate/link paths are rejected. Lock publication uses an atomic temporary-file replacement.

## Integration and acceptance boundary

Public content routes and CLI imports call `ContentService.import_dir`, `import_upload` or
`import_stig`. `_accept` refuses publication without matching verified bytes or an authorized exception.
Every direct `IngestService.ingest_stig()` call now invokes
`signatures.acceptance(ctx, actor, sha256, size)` **before** parsing its bounded stable snapshot and
again before catalog publication. Its delta and audit record include authenticity, hash and size.
Direct `uploads.import_content()` calls also check acceptance before parsing and again before the
duplicate shortcut or publication. The content entry points carry the matching receipt in a ContextVar;
typed source labels do not confer authority. Without a receipt, a direct verified-mode import refuses
unsigned bytes. Verified live pulls still use the existing admin permission, without an offline import
override or a claim of publisher signature.

Content publication holds a process/file writer lock shared by service instances; the STIG catalog
also retains its shared writer lock. Each file replacement is atomic. Competing successful publishers
leave matching held bytes, index hash and extracted datastream. This is **not** one crash transaction
covering the held file, catalog, delta, audit and index: disk/process failure between replacements can
leave an incomplete import requiring operator retry/reconciliation. State directories and the running
application remain trusted. A bundle's signatures, listing and hashes are checked before any member
is parsed, but successful earlier members are not rolled back if a later member fails parsing or loses
authorization. No failed member is silently recorded as accepted.

Tests use real Ed25519 signatures, an independent JWS decoder, isolated local media, loopback HTTPS
with real certificate verification, real Windows fixture ACLs and both state backends. They cover
tampering, wrong scope/algorithm/key ID, missing/duplicate paths, unauthorized overrides,
role-versus-policy checks, revoked sessions/trust, forged transport metadata, unapproved redirects,
untrusted TLS, stale partial bytes and changes before parsing/publication.
The focused review also reproduces direct-entry bypasses, forged receipt dictionaries, injected
courier partial bytes, revocation during parsing/extraction, same-ID key rotation and competing service
publishers on JSON and SQLite. Windows ACL tests provision only disposable fixture directories;
POSIX permission branches require a separate platform run. The TLS fixtures substitute only an exact
loopback host and its temporary CA; production retains the fixed DoD host allow-list.
These fixtures do not validate operational key custody, fleet Windows DACL rollout, organizational
key distribution, key revocation procedures, FIPS suitability or a live DISA signing service. Signed
content is not automatically fresh: this profile has no release monotonicity or anti-rollback ledger.

Review validation on Windows, with the shared interpreter and this checkout on `PYTHONPATH`:

- Ingest/content/CLI and related API regression selection: **481 passed in 173.21s**, zero skips.
- Final `test_content_authenticity_review.py`, `test_content_signatures.py` and
  `test_content_live_authenticity.py`: **133 passed in 59.64s**, zero skips.
- Final fetch, service and ingest/CLI regression selection: **79 passed in 76.39s**, zero skips.

Stateful cases exercised JSON and SQLite. The only warnings were existing framework deprecations.
No external source, production key, live identity provider or host configuration was changed. Startup
settings/context wiring is covered by startup regressions. Operational key distribution remains open;
the selections above are focused evidence rather than a full gate.
