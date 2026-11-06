# Package identity review

This review covers the source profiles at `83696ea` and the corrections below.
It does not certify the previously built archives or a running cluster. The
canonical Zarf deployment is `deploy/kubernetes/cyberthunder.yaml`; `app.yaml`
is an alternate deployment, not an additional Zarf workload.

## Findings corrected

| Severity | Finding | Correction |
| --- | --- | --- |
| High | The alternate `cyberthunder-readonly` role granted `get nodes/proxy`. A compromised workload could use privileged kubelet APIs, despite the role's name. | Remove `nodes/proxy` and unused `replicasets` access. Both source roles now cover the same survey resources and `/version`. |
| Medium | UDS ingress/egress selectors matched the alternate pod only; Zarf installs the canonical pod, which lacked that label. | Add `app.kubernetes.io/name: cyberthunder` to the canonical pod. Keep its existing Deployment/Service selectors for upgrade compatibility. |
| Medium | The alternate Service exposed port 8000 while the shared UDS route selected Service port 80. | Use Service port 80, targeting container port 8000. Alternate direct-Service consumers must update their port. |
| Medium | The alternate workload used automatic service-account token mounts, including the preflight container. | Disable automatic mounts on both Pod and ServiceAccount; explicitly project the one-hour token and cluster CA into the application container only. |

Kubernetes documents that even `get nodes/proxy` can execute commands in pods
through the kubelet and bypass API admission/audit controls. `get` alone does
not establish read-only access. See the official
[RBAC guidance](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#access-to-proxy-subresource-of-nodes).
No wildcard, Secret, exec/attach, impersonation, token issuance or mutation
permission is included in either packaged role.

The owning collector, `cyberthunder/adapters/kubernetes/adapter.py`, requests
`/api/v1/nodes/<node>/proxy/configz` opportunistically. Its failure does not
prevent collection of the required configuration artifacts. The recorded
cluster regression exercises that refusal and the remaining scan inputs.
Kubelet configuration is unavailable through this role; missing configuration
is not evidence of a passing kubelet check. Do not restore `nodes/proxy` to make
that optional request succeed. A separately approved node/configuration source
needs its own credential and authorization review.

Kubernetes permissions are additive. Updating the canonical role does not
remove an old alternate role or any external binding for the same service
account. On upgrade, the cluster administrator must review the effective
bindings, update any retained `cyberthunder-readonly` role from `app.yaml`, and
retire obsolete bindings explicitly. Offline tests cannot prove the live
account has no additional grants. Check effective denial of `nodes/proxy`,
Secrets, exec/attach and mutation, as well as the required survey reads.
The survey role reads workload and RBAC metadata cluster-wide; use a dedicated
cluster/credential boundary when that visibility is inappropriate.

## Identity, TLS and sessions

The required identity ConfigMap feeds both containers; explicit environment
entries fix fleet mode, the bind address, state path and client-secret reference.
Only the application receives `CT_CRED_BROWSER_LOGIN` from the required
`cyberthunder-oidc-client/client-secret` key. Preflight has read-only state and
script mounts and no secret or service-account token mount. Its successful
result validates local configuration/policy structure; it does not establish
provider reachability, valid client-secret contents, or certificate deployment.
Restrict administrator writes to these ConfigMaps, Secrets, workloads and PVCs.

Native Kubernetes uses application TLS on port 8000 through Service port 80.
Ingress must use verified TLS re-encryption or passthrough to that backend.
Both certificate and key must load successfully before the server listens.
The TLS Secret is optional in the shared workload only because UDS terminates
TLS at its gateway; omission does not permit plaintext native OIDC operation.
TCP probes deliberately avoid protected API routes and do not prove SSO works.

The UDS profile uses the public HTTPS origin and issuer with `CT_AUTH_MODE=mesh`.
It requires UDS gateway TLS, injected mesh transport and enforced STRICT mTLS
and network/authorization policy. The setting does not attest those controls
at runtime. Sidecar presence alone is insufficient: verify the actual policies
and rejection of unmeshed plaintext traffic before acceptance. The official
[UDS security baseline](https://docs.defenseunicorns.com/core/v1-13/concepts/platform/security/)
describes the platform controls on which this profile depends.

The application validates tokens itself; forwarded-user headers, gateway SSO
cookies and the old gateway admin group do not grant application rights.
Remove obsolete Authservice injection rather than combining its bearer header
with an application session. Callback/origin checks use the configured HTTPS
URI; the CLI disables proxy-header trust. Login and session cookies use the
`__Host-` prefix, Secure, HttpOnly, SameSite=Lax, Path=/ and no Domain. A login
transaction cookie alone does not authorize an API request. Unsafe cookie
requests additionally require the application's origin/CSRF checks.

One replica, Recreate deployment strategy and one server worker preserve the
process-local session boundary. Pod replacement invalidates application
sessions and pending logins. A changed Secret does not update an existing
process environment: coordinate a controlled pod replacement with client-secret
rotation and verify new login/refresh. Do not scale replicas or workers without
a separate shared-session design. Local logout does not prove realm-wide
revocation of already issued bearer tokens.

The UDS registration uses a confidential client, PKCE S256, an exact HTTPS
callback, a distinct API audience, restricted role scope and a single-key
client-secret template. These fields follow the official
[UDS SSO configuration](https://docs.defenseunicorns.com/core/v1-16/how-to-guides/identity--authorization/register-and-customize-sso-clients/).
The realm administrator must still provision permitted application roles and
scope mappings, protect `ct_kind` from user editing, configure refresh rotation
and reject reuse. Configure genuine assurance values in `CT_STEP_UP_ACR_VALUES`
and the matching realm flow; its empty default refuses assurance-gated actions.
Never hardcode all accounts as human or treat a refreshed token as fresh login.
Private issuer CA trust must be installed in the application runtime, not merely
in an operator's browser. No TLS verification bypass is supported.

## Account Kubernetes credentials: required provisioning seam

The bootstrap inventory record and the mounted local-cluster kubeconfig do not
grant a user transport credentials. Verified requests require that subject's
policy grant and credential binding. The bootstrap ConfigMap is a Kubernetes
projection and contains `tokenFile`; both are incompatible with the protected
account kubeconfig validator. Even copying its contents into a regular file
does not make `tokenFile` acceptable. The application must not fall back to the
pod token, an ambient `KUBECONFIG`, a login plugin or cluster-admin credentials.

Before a verified cluster scan, an administrator must provision an owned,
protected regular per-account kubeconfig in a trusted directory (for example
under the state PVC's `auth` directory), then bind its absolute path and exact
context in that account's access-policy grant. The supported configuration has
one HTTPS cluster/context/user, trusted CA material, and an explicit static token
or client certificate/key. Follow the existing kubeconfig validator's ownership,
mode, link and credential rules. Use the canonical UID/GID 10001, or UID/GID 1000
for the alternate image; private files are mode 0600 and their private directories
0700 on Linux. Provision and rotate through an approved administrative process;
there is no trust-copying init container. Credential changes stop captured
operations; a subsequent authorized operation must select the reviewed binding.

Supporting rotating projected service-account credentials as account bindings
would require a separately designed credential-validator seam. It is not added
by this package change. The current tests prove a missing binding and a regular
copy retaining `tokenFile` are refused before subprocess execution; a fixture
regular static credential works only through the explicit account binding.

## Offline evidence and remaining live acceptance

The focused suite resolves the files named by `zarf.yaml`, substitutes package
variables, checks selectors through Service/backend ports, and checks both
roles and token mounts. It executes the actual preflight and application with
fixture keys/policies on both JSON and SQLite storage. Negative cases include
HTTP callback/token endpoints, OIDC without TLS, mismatched authorized party,
projected policy, wrong issuer/audience, missing grants, header spoofing and
ambient Kubernetes credentials. No real credentials or cluster endpoints are
read by these tests.

Receipt: Windows Python 3.12.10, JSON and SQLite enabled, **135 passed, zero
failed, zero skipped** in 33.54 seconds. The 73 warnings are existing
FastAPI/Starlette deprecations; no thread warning occurred. Four focused
regressions first failed against the original manifests, reproducing the
selector, Service port, automatic token mount and RBAC defects above.
This is not a Linux/container execution or a live UDS schema/admission result.

Run from the repository root with the selected Python environment:

```sh
CT_STATE_BACKENDS=json,sqlite PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest \
  tests/test_package_identity.py tests/kubernetes/test_packaged_rbac.py \
  -o addopts= -q --tb=short -p no:cacheprovider
```

Before release, an operator still needs a rebuilt image/package and live
acceptance against the intended Kubernetes/UDS version: admission and actual
selectors/ports, protected PVC provisioning, effective RBAC including stale
bindings, mesh plaintext refusal, gateway/backend/issuer certificate trust,
SSO claim/assurance mappings, client-secret rotation, refresh reuse rejection,
CSRF/logout/restart behavior, and two independently scoped accounts using their
own delegated cluster credentials. No infrastructure, image build, package
publication or live realm acceptance was performed in this review.
