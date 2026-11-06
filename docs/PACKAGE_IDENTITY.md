# Packaged identity and startup

## Guarded container command

Both `Dockerfile` and `Containerfile` run `cyberthunder serve`, with `CT_HOST=0.0.0.0`,
`CT_PORT=8000` and `WEB_CONCURRENCY=1`. The CLI validates the actual bind address,
then `api.app.serve` validates it again before constructing the application and
starting Uvicorn. No Uvicorn CLI flag can silently choose a different address
from the settings inspected by application authentication. Retain one worker
and one replica: browser sessions are local to that process.
The shared serve implementation also passes `workers=1` explicitly. An external
`WEB_CONCURRENCY` override therefore cannot enable multiple workers; the startup
regressions set it to `8` and verify that one worker is retained.

This is a breaking startup correction. An image with no identity configuration
now exits with `development authentication may bind only to loopback` instead
of exposing development identity on the container network. Setting
`CT_AUTH_MODE=oidc` alone is insufficient: network OIDC requires TLS certificate
and key paths plus a valid issuer, API audience and JWKS URL. Only an actually
authenticated mesh deployment may use `CT_AUTH_MODE=mesh` without application
TLS; that mode still validates signed tokens and requires OIDC configuration.
It does not trust a caller-supplied actor name or arbitrary proxy headers.

The identity ConfigMaps deliberately start with `CT_STEP_UP_ACR_VALUES="[]"`.
Set it to a JSON array of exact assurance values enforced by the intended realm,
and retain `CT_STEP_UP_MAX_AGE_SECONDS=300` unless the enclave policy specifies a
different supported limit. Sign-in alone does not enable risky actions while
this list is empty. The realm must supply a signed authentication time and the
configured assurance claim; token refresh is not reauthentication. No example
value certifies CAC use. See [STEP_UP](STEP_UP.md) for policy and validation limits.

Native CLI behavior is unchanged. Native development defaults to loopback.
An explicit container `CT_HOST=127.0.0.1` is also loopback-only inside that
container; publishing a Docker port does not make that listener reachable on
the container interface. Do not use development mode for shared access.

Both build definitions now pin Trivy 0.71.1 at digest
`sha256:53570e6911c2361ebe7995228088cf83a6b9b73e7f3cdca44bd8f8f425e80fa7`.
The default `docker build .` uses `Dockerfile`; its former Trivy 0.56.2 did not
meet the managed engine's minimum version. Scanner and guarded-command parity
are covered by a regression over both definitions.

Other build differences remain deliberate or require separate acceptance:
`Dockerfile` builds the UI and runs as UID/GID 10001; `Containerfile` retains
UID/GID 1000, its additional system scanners and its existing source/UI staging
requirements. The default `.dockerignore` excludes some of its COPY inputs
(README, STIG and built UI); it is not a validated alternative Docker build
using that default context. No image or package was rebuilt in this change.
The entrypoint accepts native CLI arguments (`image serve`, `image --help`);
custom diagnostic executables require an explicit `--entrypoint` override.

The existing checked-in image/package archives have not been rebuilt. A future
release must rebuild the image from the corrected source before publishing it.
Invoking Uvicorn directly as a custom container command bypasses the guarded
serve entrypoint and is unsupported. Do not override the worker count.

## First-stage validation

`tests/test_package_identity.py` reads both actual build commands and defaults,
drives the native CLI, and verifies missing configuration and nonloopback dev/TLS
refusals before any listener. Configured startup constructs the real application
and Uvicorn configuration, loads fixture TLS material, and rejects an anonymous
API request. Only the final blocking server runner is replaced; no real image,
cluster, realm or external identity endpoint is used. Stateful cases run with
both JSON and SQLite.

First-stage focused result: **26 passed, 49 existing framework deprecation
warnings in 11.66 seconds** with the shared Python interpreter and the worker
checkout on `PYTHONPATH`.

## Deployment profiles and required inputs

The source manifests now require a `cyberthunder-identity` ConfigMap and a
`cyberthunder-oidc-client` Secret with key `client-secret`. Neither has a shared
account/password default. The Secret becomes `CT_CRED_BROWSER_LOGIN`, selected
by `CT_OIDC_CLIENT_SECRET_REF=BROWSER_LOGIN`; its value is not stored in settings
or policy. Missing resources stop Kubernetes container creation. An init
container validates non-secret settings and the existing policy with a read-only
state mount. It does not create directories, copy files, change permissions,
contact an issuer or read the client Secret.

| Profile | Configuration | Transport |
| --- | --- | --- |
| Native Kubernetes | Fill every empty field in `deploy/kubernetes/identity-config.example.yaml` | `CT_AUTH_MODE=oidc`, application TLS required |
| UDS package | `packages/cyberthunder/identity.yaml`, rendered with the reviewed `DOMAIN` | `CT_AUTH_MODE=mesh`, UDS HTTPS ingress and authenticated mesh transport required |

Both set `CT_SECURITY_MODE=fleet`, bind `0.0.0.0:8000` and retain one process and
replica. `packages/cyberthunder/app.yaml` is the alternate UID 1000 manifest;
it uses the same ConfigMap/Secret and preflight, but is not the manifest selected
by `zarf.yaml`. The canonical Docker deployment uses UID/GID 10001. Replace both
the application and init image references with the reviewed rebuilt image;
old `0.2.0`/`0.2.6` image tags are not proof of these source changes.

Native OIDC additionally needs the `cyberthunder-tls` Secret, keys `tls.crt` and
`tls.key`, mounted at `/etc/cyberthunder-tls`. The TLS Secret volume is optional
only so the UDS mesh profile can omit it. Native settings name the files and
Uvicorn refuses startup if they are missing or invalid. The canonical Service
retains port 80 for UDS compatibility; with the native OIDC profile that backend
port carries **TLS**, not plaintext HTTP. Configure ingress passthrough or
verified TLS re-encryption accordingly. Direct diagnostic forwarding must use
HTTPS and the correct certificate name. Never turn off certificate validation.

Startup/readiness/liveness probes use TCP. `/api/v1/status` remains authenticated;
it is unsuitable for anonymous kubelet probes. The existing public `/auth/status`
reports login availability/session state without application artifacts. A Ready
pod establishes process availability, not issuer reachability or account access.

## Exact issuer/client/claim contract

The UDS source profile uses these exact values after `DOMAIN` substitution:

| Input | Value |
| --- | --- |
| `CT_OIDC_ISSUER`, signed `iss` | `https://sso.<DOMAIN>/realms/uds` |
| `CT_OIDC_JWKS_URL` | Issuer + `/protocol/openid-connect/certs` |
| `CT_OIDC_AUTHORIZATION_ENDPOINT` | Issuer + `/protocol/openid-connect/auth` |
| `CT_OIDC_TOKEN_ENDPOINT` | Issuer + `/protocol/openid-connect/token` |
| `CT_OIDC_AUDIENCE`, access-token `aud` | `cyber-thunder-api` |
| `CT_OIDC_CLIENT_ID`, `CT_OIDC_AUTHORIZED_PARTY`, access-token `azp` | `cyber-thunder-app` |
| ID-token `aud` | `cyber-thunder-app`; must not include the API audience |
| `CT_OIDC_REDIRECT_URI` | `https://cyberthunder.<DOMAIN>/auth/callback` |
| `CT_OIDC_ROLES_CLAIM` | `ct_roles`, a JSON string array |
| `sub` | Stable issuer subject, matched exactly by server policy; not a display name |
| `ct_kind` | Admin-controlled account attribute, `human` for explicitly approved people; absence means `workload` |

The UDS client is confidential, uses authorization code with PKCE S256, and
does not enable client-credentials service accounts. Its audience mapper adds
only the API audience to access tokens. A client-role mapper emits only roles
from `cyber-thunder-app` into `ct_roles`; it does not translate membership of
`/UDS Core/Admin` into application administration. `fullScopeAllowed=false`
requires the realm administrator to configure the client's permitted role scope
mappings. The account-kind mapper reads `ct_kind`; it never hardcodes every
authenticated subject as human.

Realm administrators must create only the needed application client roles
(`viewer`, `analyst`, `approver`, `admin`, `auditor`), assign them to reviewed
named accounts, and configure permitted role scope mappings. Restrict `ct_kind`
to administrator-managed profile data; users, self-service registration and
unreviewed federation mappings must not set it. Disable implicit/password grant
flows, require suitable login assurance, and enable refresh-token rotation with
reuse rejected. The application rejects nonrotating refresh tokens. These realm
controls are operator acceptance steps, not changes applied by this package.
Provider signatures, expiry, audience and client validation remain mandatory.

The manifest follows UDS's documented [native SSO registration and Secret templates](https://docs.defenseunicorns.com/core/v1-14/how-to-guides/identity--authorization/register-and-customize-sso-clients/)
and [Package CR fields](https://docs.defenseunicorns.com/core/v1-14/reference/operator--crds/packages-v1alpha1-cr/).
The [client-role mapper implementation](https://github.com/keycloak/keycloak/blob/26.4.0/services/src/main/java/org/keycloak/protocol/oidc/mappers/UserClientRoleMappingMapper.java)
describes the selected client's multivalued role claim. UDS mapper allow-list
policy may require a realm administrator's review; do not broaden it globally
without that review. The repository bundle pins UDS Core 1.14.3; admission and
real token shape still need validation on the installed realm/version.

## Provision the account policy on the PVC

Before starting the app, a storage/cluster administrator must provision a
regular, singly linked `auth/access.json` on the state PVC. All path components
must be real directories, with trusted ownership and no group/other write bits.
Kubernetes projected Secret/ConfigMap files use symlinks and are refused here.
The init container intentionally does not turn such inputs into trusted files.

Provision the PVC while the application is stopped. On an administrator-controlled
mount, set the volume root and `auth` directory to the actual image UID/GID and
mode `0700`, and create the reviewed policy as that owner with mode `0600`.
The `auth` directory must belong to the application UID because it also holds
the verifier's writable public-key caches. For the canonical image, an example
administrative procedure is:

```sh
# STATE_MOUNT is the verified provisioning mount of this deployment's PVC.
chown 10001:10001 "$STATE_MOUNT"
chmod 0700 "$STATE_MOUNT"
install -d -o 10001 -g 10001 -m 0700 "$STATE_MOUNT/auth"
# Create /root/reviewed-access.json as administrator-controlled, reviewed data.
install -o 10001 -g 10001 -m 0600 /root/reviewed-access.json "$STATE_MOUNT/auth/access.json"
stat -c '%u:%g %a %n' "$STATE_MOUNT" "$STATE_MOUNT/auth" "$STATE_MOUNT/auth/access.json"
```

Use UID/GID 1000 only for the alternate Containerfile/app manifest. Verify source
ownership and content before the explicit administrative install; do not use a
downloaded file, shared writable staging directory or projected Secret as a
trust shortcut. Storage with `WaitForFirstConsumer` needs an administrator's
provisioning pod/mount in the intended topology. The package does not create a
privileged provisioning job. Windows native deployments require equivalent
DACL protection; POSIX mode checks cannot establish Windows ACL safety.

`fsGroup` is deliberately absent: kubelet ownership handling can make policy
ancestors group-writable and invalidate the policy. Existing PVCs need an
approved ownership/mode migration before upgrade. Preserve all application
state during that migration. Other mounted Secrets use read-only `0444` files
so the nonroot app can read them without `fsGroup`; access to mounting Secrets
is governed by cluster RBAC. This does not make projected SSH keys acceptable
to transport-specific file-trust checks; those bindings and protected credential
files still need their own supported provisioning.

Minimal policy example (replace issuer, subject and environment with reviewed
values; this example grants reads, not node administration):

```json
{
  "version": 1,
  "entries": [{
    "issuer": "https://sso.example.test/realms/uds",
    "subject": "REPLACE_WITH_THE_NAMED_ACCOUNT_SUBJECT",
    "node_actions": [],
    "grants": [{"environments": ["training"], "actions": ["read"]}]
  }]
}
```

That account also needs the `viewer` role from the issuer. A signed role alone
grants no access to another environment. Give inventory/node administrators
separate named-account entries with the precise node/resource actions their
work requires; there is no seeded shared administrator. `read.all` is a separate
node grant and is not used in this example. Resource grants and credential
bindings remain separate: a read/scan grant alone does not provide transport
credentials. Global CLI actor strings cannot replace verified API identity.

## Breaking UDS gateway migration

The older package used Authservice's `/login` callback and a gateway-wide
`/UDS Core/Admin` group restriction. The new source registration uses the
application's `/auth/callback` and native browser session. It intentionally
omits `enableAuthserviceSelector`; mesh ingress and the application enforce
their respective transport and identity boundaries. Remove/reconcile obsolete
Authservice configuration during upgrade and verify that it no longer injects
an Authorization header alongside the application's session cookie. Mixed
credentials are rejected, not silently preferred.

The public UI/login endpoints can now load before authentication; API artifacts
remain protected. The former gateway group is no longer the authorization rule.
Only named subjects/groups explicitly provisioned in `access.json`, together
with their role permissions, receive application access. Existing gateway SSO
cookies do not establish an application session. The application performs its
own code/PKCE exchange and issues its secure session cookie. Logout is local to
that session; it does not prove realm-wide logout or token revocation.

UDS egress allows HTTPS only to `sso.<DOMAIN>:443` for token exchange/JWKS, in
addition to existing cluster/approved-target rules. Provide a trusted CA chain
inside the image/runtime when the issuer uses private PKI. A developer gateway
certificate trusted only by a workstation is insufficient. No HTTP internal
Keycloak URL, insecure TLS fallback or ambient credential fallback is added.

## Acceptance and limits

Focused tests render the YAML/Zarf substitutions, check both manifests, execute
the exact read-only preflight, load the configured application, and validate
freshly signed fixture tokens against a protected local JWKS cache. They check
anonymous status versus protected API status, named-account/environment denial,
audience substitution, missing policy/settings and projected policy rejection.
They make no identity-provider calls. The scanner RBAC regression remains part
of the focused selection.

Second-stage focused result on the worker checkout: **97 passed, 73 warnings,
no skips in 27.66 seconds**, using the shared Python interpreter with this
checkout on `PYTHONPATH`:

```text
python -m pytest tests/test_package_identity.py tests/kubernetes/test_packaged_rbac.py --tb=short --disable-warnings
```

The configured native, alternate-native and UDS application cases run on both
JSON and SQLite. Rendering checks use local YAML parsing and fixture variable
substitution; they do not establish Zarf lint or Kubernetes admission success.

No image build, package rebuild, cluster admission, CSI mount, real browser/realm
login, account creation or registry publication is established by these tests.
Validate provider CA trust, role/attribute management, actual token claims,
refresh rotation, gateway/mesh policy and an unauthorized second account before
release. Existing cluster/SSH delegated credential and scheduler limitations
remain: neither this package nor a gateway login grants a background job or
another user access to a transport. This work does not close external ZT
acceptance requirements.
