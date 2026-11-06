# Cyber Thunder Zarf package

Built using the installed Zarf v0.85.0. The package includes the local
`cyberthunder:0.2.6` image, its SBOM, and the Deployment, Service, Namespace,
read-only cluster survey RBAC, kubeconfig and 10 GiB PVC from `deploy/kubernetes/cyberthunder.yaml`. The UDS Package in
`uds.yaml` configures Istio ingress and Keycloak SSO at
`https://cyberthunder.uds.dev` (or `cyberthunder.<DOMAIN>`).

**Source identity migration:** a rebuilt image/package now requires a protected
PVC account policy and uses native application OIDC sessions. Read
[PACKAGE_IDENTITY.md](../../docs/PACKAGE_IDENTITY.md) before deploying. The
checked-in `0.2.6` archives below remain historical artifacts with the earlier
gateway/typed-actor behavior; they have not been rebuilt by these source changes.
The two source build definitions now share the guarded CLI entrypoint and
digest-pinned Trivy 0.71.1.

## Rebuilt-source identity configuration

See the [package identity review](docs/IDENTITY_REVIEW.md) for corrected traffic
selectors, the alternate Service port change, removal of `nodes/proxy`, and
the required per-account kubeconfig provisioning and live acceptance boundary.

`zarf.yaml` includes `identity.yaml`, the read-only identity preflight, and the
canonical UID/GID 10001 deployment. `DOMAIN` supplies the explicit UDS issuer,
JWKS/auth/token endpoints and `/auth/callback` origin. `uds.yaml` registers the
confidential `cyber-thunder-app` client with PKCE and a separate
`cyber-thunder-api` access-token audience; its generated
`cyberthunder-oidc-client` Secret supplies the app's client secret. The manifest
also permits HTTPS egress to that issuer host. Private issuer PKI must be trusted
inside the application runtime.

The realm administrator must configure permitted application client roles and
their scope mappings, an administrator-controlled `ct_kind` attribute for named
human accounts, and refresh rotation. The storage administrator must provision
the PVC root/auth directory and regular `auth/access.json` before deployment;
see the exact ownership, policy example and migration steps in the linked
document. There is no shared-admin seed or trust-copying init container.
`fsGroup` is no longer used because it conflicts with protected policy paths.

This source profile replaces the former Authservice `/login` flow with the
application's native `/auth/callback`. The UI/login endpoints load before
authentication; artifact APIs remain protected. Reconcile away the old
Authservice injection and verify native login with two separately scoped
accounts. Gateway SSO cookies alone do not establish an application session,
and `/UDS Core/Admin` membership alone grants no application permissions.
Keep UDS TLS ingress and authenticated mesh transport; `mesh` is not a setting
for an ordinary plaintext deployment.

The alternate `app.yaml` remains a UID 1000/5 GiB deployment for the teammate's
Containerfile workflow and now consumes the same identity/preflight inputs.
Its Service now uses port 80, matching the shared UDS route; the container still
listens on port 8000. It is not selected by `zarf.yaml`; apply the shared preflight ConfigMap separately
when using it. Its image source/context and delegated cluster/transport setup
still require validation. Do not treat the old image tag as an identity update.

## Report history

Version `0.2.6` adds searchable saved reports. Open **Reports → Report history**
to search contents, asset names/IDs, scan IDs and operators, or filter by type
and UTC date range. Saved versions can be reopened and downloaded without
regenerating them from current findings. The Reports page includes commander
reports, POA&Ms, checklists and target reports.

Rendered exports and Mission target reports are retained under
`/var/lib/cyberthunder/reports/history/` on the state PVC, for both state backends.
Existing target reports and pending/synced report payloads are imported once.
Include this directory in state backups. See [Reports](../../docs/UI.md#reports-reports).

## Cluster scanning release

Version `0.2.6` includes the app updates from `cluster-scan` commit
`2d309095f0a1aa39104f4e0dd09f4ef0828bbca9`, including the cluster survey,
Trivy image baseline, namespace risk profiles, and optional OpenAI descriptions.
The Docker build compiles the UI from that source. The release also enforces
the existing operator-name requirement on baseline requests and records that
operator in the audit log. The image includes kubectl v1.36.4 and Trivy v0.56.2.

The package grants its dedicated service account `get` and `list` access to
namespaces, nodes, pods, service accounts, services, deployments, statefulsets,
daemonsets, cronjobs, jobs, role bindings, cluster role bindings and network
policies, plus `get /version` for cluster identification. These cover the
configuration scan, cluster survey and image baseline collectors.
It mounts a rotating projected token and a kubeconfig that points at the local
cluster, and allows Kubernetes API egress through UDS. It cannot mutate cluster
resources or read Secrets. Deployment does not start a baseline automatically.

### Upgrade existing scan permissions

The package includes the correction introduced in `0.2.5` for configuration scan `Forbidden` errors for
`serviceaccounts`, `services`, `clusterrolebindings`, `rolebindings` and
`networkpolicies`. The previous role covered cluster discovery and workload
baselines but omitted these configuration-check inputs. Deploy the `0.2.6`
package to persist the corrected read permissions.

To apply just the RBAC correction to an existing deployment, use cluster admin
credentials for the intended cluster and run this from the updated checkout:

```sh
zarf tools yq 'select(.kind == "ClusterRole" and .metadata.name == "cyberthunder-survey")' \
  deploy/kubernetes/cyberthunder.yaml | kubectl apply -f -
```

The existing `cyberthunder-survey` ClusterRoleBinding continues to bind this role
to the app's service account. Permissions take effect immediately; rerun the
scan without restarting the pod. Kubelet `/configz` collection remains optional
and is not enabled by these RBAC changes.

### Discover the host cluster

An image and package rebuilt from this source add **Local Kubernetes cluster**
(`local-cluster`) to **Assets** at startup, using the mounted
`/etc/cyberthunder/kubeconfig` and its `in-cluster` context. The asset is visible
but **out of scope**. No manual registration is needed for this inventory record.
Use a verified named account with the appropriate roles, server policy and
delegated credential binding to enable scope and discover it. Typed actor names
and the mounted service account alone do not authorize access in verified mode.

The already-built `0.2.4`, `0.2.5` and `0.2.6` archives retain the earlier behavior:
newly registered host-cluster assets start in scope. Those archives have not
been rebuilt with these guardrails. Rebuild both the image and package from
this source to get out-of-scope registration; existing operator scope choices
remain unchanged on restart or upgrade.

Registration is audited once as `inventory.bootstrap`. Restarting the pod
preserves an existing asset, including its name, options and operator-selected
scope. External clusters continue to use **Assets → Add asset** with their own
mounted kubeconfigs. Set `CT_BOOTSTRAP_CLUSTER_TARGET=false` in the deployment
to disable startup registration; `CT_BOOTSTRAP_CLUSTER_TARGET_ID` and
`CT_BOOTSTRAP_CLUSTER_NAME` control the local asset's ID and display name.
Automatic registration is enabled by this Kubernetes deployment; ordinary CLI
and standalone server runs retain their existing explicit inventory setup.

For verified account operations, the projected bootstrap kubeconfig and its
`tokenFile` are not a supported credential binding. Provision a protected regular
per-account kubeconfig and explicit policy binding before scanning; see the
[credential provisioning seam](docs/IDENTITY_REVIEW.md#account-kubernetes-credentials-required-provisioning-seam).
The pod's survey role and inventory registration do not grant account rights.

### Cluster baseline API

With an authenticated browser session, the cluster API provides:

- `GET /api/v1/cluster/survey`: namespaces and workload images.
- `POST /api/v1/cluster/baseline` with `{"use_openai": false}`: scan images and save risk profiles for the authorized account (application session and CSRF headers required).
- `GET /api/v1/cluster/risk`: the latest saved profiles.

Trivy's vulnerability database and target images are not included in this app
archive. Newly built images use Trivy 0.71.1 and the managed **Vulnerability data**
page. Update there when connected, or import an exported database ZIP from a
connected node. The main database, optional Java index, versions, freshness and
update errors are visible separately from the STIG Library. Schedules are opt-in.
See [VULNERABILITY_DATA.md](../../docs/VULNERABILITY_DATA.md) for CLI commands and
transfer controls. Existing published 0.2.6 package archives are not rebuilt by
editing source; rebuild the package to deploy these changes.

Managed files live under `/var/lib/cyberthunder/vulnerabilities/` on the writable
state PVC. Copying a bare legacy `trivy-cache/db` directory does not activate a
managed generation. Cluster baselines pin a validated generation and never
refresh databases during a scan. Normalized image CVEs appear in Findings;
per-image errors preserve earlier findings and never establish a clean baseline.

Disconnected scans also need the actual image content. Allow only the intended
image and official database registry access in `uds.yaml`, then rebuild for your
environment. Private image registries still need their own credentials and CA
configuration. A database bundle does not include those credentials or images.

OpenAI summaries remain opt-in, with template text available offline. Enabling
them requires a key provided through a Kubernetes Secret and explicit egress to
`api.openai.com:443`; the default package configures neither. The request sends
the namespace risk profile to that external service.

## Historical archive deployment

These steps describe the existing split archives, not a rebuilt identity-aware
source release. Do not publish them as containing the current startup guard or
account isolation. Rebuilt deployments require the provisioning steps above.

Copy these artifacts from `packages/` to the deployment machine:

- `zarf-package-cyberthunder-amd64-0.2.6.tar.zst.part000`
- `zarf-package-cyberthunder-amd64-0.2.6.tar.zst.part001`
- `zarf-package-cyberthunder-amd64-0.2.6.tar.zst.part002`
- `zarf-package-cyberthunder-amd64-0.2.6.tar.zst.sha256`

The package uses Zarf split archives to keep each file below GitHub's 100 MiB
limit. Keep all three parts in the same directory; `.part000` contains the
reassembly metadata.

Use Zarf v0.85.0 and credentials for the intended remote cluster:

```sh
export KUBECONFIG=/path/to/remote-kubeconfig
kubectl config current-context
sha256sum -c zarf-package-cyberthunder-amd64-0.2.6.tar.zst.sha256
```

The package requires UDS Core with Keycloak and Authservice, an initialized Zarf
cluster, Linux amd64 nodes, and a default storage class supporting ReadWriteOnce
and fsGroup. Configure DNS for `cyberthunder.<domain>` to reach the UDS tenant
gateway; the local demo resolves `cyberthunder.uds.dev` to its loopback gateway.
Use the domain configured in UDS Core (default `uds.dev`):

```sh
zarf package deploy ./zarf-package-cyberthunder-amd64-0.2.6.tar.zst.part000 --confirm --set DOMAIN=uds.dev
kubectl -n cyberthunder rollout status deployment/cyberthunder
```

Open **https://cyberthunder.uds.dev** and sign in with a Keycloak user in
`/UDS Core/Admin` (the development `hacker` user has this group). The Kubernetes
ClusterIP Service is `cyberthunder.cyberthunder.svc.cluster.local:80`, targeting
container port 8000. UDS creates the `cyber-thunder-app` OIDC client and protects
the UI and API with Authservice. The package waits for UDS configuration before
starting the app; upgrades recreate the pod with its Istio sidecar and preserve
the existing PVC. Direct port-forwarding is for administrator diagnostics and
bypasses the gateway's browser login flow.

The application image and SBOM are carried in the archive, so no public image
registry is needed during deployment. The package is unsigned; the checksum
verifies transfer integrity, not publisher identity.

The app uses one replica and one API worker because verified browser sessions
are process-local. Documents use `CT_STATE_BACKEND=json` (default) or `sqlite`;
audit, inventory, proposals and other artifacts remain files on the PVC under
both backends. Back up the whole state directory; see [State](../../docs/STATE.md).
Template explanations are the default. See
[runtime configuration and scanning limitations](../../deploy/kubernetes/README.md).
Target and model-server egress must be explicitly allowed in the UDS Package for
your environment. A non-default storage class requires updating the PVC manifest
and rebuilding. In rebuilt source, verified account identity, application roles
and server policy control access and attribution; a configured actor name does
not authorize an operation.

## SSH access to an external VM

The source package supports `SCAN_TARGET_CIDR` and `SCAN_SSH_PORT` deployment
variables. The default CIDR is the documentation-only address `192.0.2.1/32`,
so a real target requires explicit configuration. For the local QEMU range,
set `SCAN_TARGET_CIDR=172.18.0.1/32` and `SCAN_SSH_PORT=2222` when deploying a
package rebuilt from this source:

```sh
zarf package deploy <rebuilt-package> --confirm --set DOMAIN=uds.dev \
  --set SCAN_TARGET_CIDR=172.18.0.1/32 --set SCAN_SSH_PORT=2222
```

Supply these values on subsequent upgrades too. UDS permits TCP egress only
from the scanner to that CIDR and SSH port, alongside existing Kubernetes API
access. This rule does not enable external Kubernetes API or WinRM access.

The optional `cyberthunder-target-credentials` Secret remains mounted read-only
at `/etc/cyberthunder/targets` with mode `0444`. **Do not select its projected
`id_ed25519` as an SSH private key.** The protected key reader rejects symlinks
and group/world permission bits. Changing only the mount mode does not provide
a protected regular file or an account binding.

Provision a protected regular key through the storage administrator, then bind
its absolute runtime path and remote username to the exact named account,
target, environment and action in `auth/access.json`. Use a read-only target
account with `sudo: false` for scans and a separately authorized apply account
with only the remote privileges required by the reviewed fix. Retain verified
SSH host trust. Inventory key fields and egress rules cannot supply the account
grant. Fleet password references instead require an explicit protected
`CT_CREDENTIAL_SOURCES` registry; `CT_CRED_*` target-password fallback is refused.
The OIDC browser client secret remains a separate application credential.

See [Deployment credential provisioning](../../docs/DEPLOYMENT_CREDENTIAL_PROVISIONING.md)
for file-based configuration examples, native alternatives and exact protection
requirements. The package has no end-to-end target credential provisioner: it
does not install those files, populate the registry or create remote accounts.
The preflight validates application identity/policy, not target authentication.
The [local QEMU repair patches](../../range/README.md#qemu-ssh-from-a-uds-deployment)
describe legacy egress/Secret wiring and do not close this credential gap.
The existing archives are unchanged; rebuilding alone does not provision
credentials. Remaining provisioning/acceptance work is tracked in
[BACKLOG.md](../../docs/BACKLOG.md), ZT-19 and ZT-13.

## Verify

From the repository root after deployment:

```sh
# Local k3d demo, using its bundled TLS certificate:
./scripts/verify-cyberthunder.sh
# Other cluster/domain, using trusted TLS:
./scripts/verify-cyberthunder.sh CONTEXT DOMAIN
```

For the historical Authservice archives, the check requires a Ready UDS Package and Deployment, an injected Istio sidecar,
Keycloak redirects for the UI/API/assets, and rejection of invalid bearer tokens.
Also sign in with an authorized user and confirm that the UI and `/api/v1/status`
load. A user outside `/UDS Core/Admin` must be denied access.

The existing verification script assumes the old gateway flow and is not an
acceptance test for this native-session source profile. For a rebuilt release,
check `/auth/status` (public 200), anonymous `/api/v1/status` (401), native browser
login, CSRF, logout, and denial of a second account outside its assigned
environment. Do not change the API to satisfy the obsolete anonymous probe.

## Rebuild

From the repository root with a running Docker daemon. Rebuilt artifacts are written to `.build/`:

```sh
mkdir -p .build
docker build --platform linux/amd64 -t cyberthunder:0.2.6 .
zarf dev lint packages/cyberthunder
zarf package create packages/cyberthunder --confirm --architecture amd64 --max-package-size 95 --output .build
(cd .build && sha256sum zarf-package-cyberthunder-amd64-0.2.6.tar.zst.part* > zarf-package-cyberthunder-amd64-0.2.6.tar.zst.sha256)
```

Zarf falls back to the local Docker image when the tag cannot be found in a
registry. Lint warns that this local image uses a tag rather than a registry
and digest; the built archive carries the captured image and content checksums.
The default kubectl matches Kubernetes 1.36; set `--build-arg KUBECTL_VERSION=vX.Y.Z`
when rebuilding for a different cluster minor version. Bump the image tag and
package version together for subsequent releases, including the init-container
image. The commands above are operator release steps; no image/package build or
live realm acceptance was performed for this source integration.
