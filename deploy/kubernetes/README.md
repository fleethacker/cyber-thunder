# Run Cyber Thunder in Kubernetes

Run these commands from the repository root. The image builds the React UI and
serves it with the Python API on port 8000. It runs as UID/GID 10001.

## Build and publish

With a running Docker daemon, replace the example registry with yours:

```sh
docker build -t registry.example.com/team/cyberthunder:0.2.6 .
docker push registry.example.com/team/cyberthunder:0.2.6
```

Change both application and init-container `image` references in
`deploy/kubernetes/cyberthunder.yaml` to that published image.
For a private registry, configure an imagePullSecret in the namespace and
reference it in the pod specification. Build for the cluster node architecture
(use Docker buildx for a cluster with multiple architectures).

For a local k3d cluster, you can instead use:

```sh
docker build -t cyberthunder:0.2.6 .
k3d image import cyberthunder:0.2.6 -c cyber-thunder
```

## Deploy and open

Select the intended kubectl context first. The cluster needs a default storage
class that supports ReadWriteOnce volumes; otherwise set `storageClassName` on
the PVC. **This source deployment now requires verified identity configuration.**
Follow [PACKAGE_IDENTITY.md](../../docs/PACKAGE_IDENTITY.md) to configure the
issuer/client claims and provision a protected regular `auth/access.json` on
the PVC as UID/GID 10001. `fsGroup` is deliberately absent because group-writable
policy ancestors are rejected. Existing PVC ownership/modes must be reviewed
before upgrade; do not replace or erase application state.
Include the provisioner-created volume root in that review. Local acceptance
found a root-owned `0777` PVC root above a UID 10001 `0700` application directory;
the private child does not make that ancestor acceptable to protected readers.
See [PVC trust and bounded acceptance](../../docs/DEPLOYMENT_CREDENTIAL_PROVISIONING.md#pvc-root-and-namespace-acceptance-limits).

Create the Namespace/PVC first so an administrator can provision storage. For
example, with Zarf's bundled yq:

```sh
zarf tools yq 'select(.kind == "Namespace" or .kind == "PersistentVolumeClaim")' \
  deploy/kubernetes/cyberthunder.yaml | kubectl apply -f -
```

Copy `identity-config.example.yaml` to a reviewed local file and fill every
empty field. Register the confidential browser client and its distinct API
audience with the issuer. Provision its secret and an application TLS certificate
through your approved secret handling; the following commands reference files,
not secret values on the command line:

```sh
kubectl apply -f /protected/reviewed-identity.yaml
kubectl -n cyberthunder create secret generic cyberthunder-oidc-client \
  --from-file=client-secret=/protected/client-secret
kubectl -n cyberthunder create secret tls cyberthunder-tls \
  --cert=/protected/console-chain.pem --key=/protected/console-key.pem
kubectl apply -f deploy/kubernetes/identity-preflight.yaml
kubectl apply -f deploy/kubernetes/cyberthunder.yaml
kubectl -n cyberthunder rollout status deployment/cyberthunder
```

Open the configured HTTPS origin. The native profile runs TLS on backend port
8000, reached through Service port 80; configure verified ingress re-encryption
or TLS passthrough. Port-forwarding is only a diagnostic path and still needs
HTTPS/correct certificate validation. `/auth/status` is public session status;
`/api/v1/status` and API docs require authentication. Probes use TCP.
An absent ConfigMap/client Secret prevents container creation; the read-only
preflight rejects missing/invalid policy and incomplete identity settings.
It never copies a Secret into a trusted policy file.
For a UDS cluster, deploy the [Cyber Thunder Zarf package](../../packages/cyberthunder/README.md)
instead. Its native OIDC session profile uses UDS HTTPS ingress at
`https://cyberthunder.<domain>` and the application's named-account policy.

## State and configuration

The 10 GiB PVC holds inventory, audit records, findings, approvals and other
application state at `/var/lib/cyberthunder`. Back up the whole directory:
documents use `CT_STATE_BACKEND=json` (default) or `sqlite`, while audit,
inventory, proposals and other artifacts remain files under both backends.
See [State](../../docs/STATE.md). Keep one replica and one API worker because
verified browser sessions are local to the process. Recreate deployment strategy
stops the old pod before starting its replacement, with brief downtime.
Deleting the Deployment preserves the PVC; deleting the namespace deletes it.

The default `CT_LLM_BACKEND=template` works without a model server. To use an
existing Ollama service, set `CT_LLM_BACKEND=ollama` and `CT_LLM_URL` to its
reachable cluster URL (localhost refers to this container). Other `CT_*`
settings are documented in `cyberthunder/config.py`.

Target credentials require an exact named-account policy binding for the target,
environment and action. Fleet SSH/WinRM password references do not fall back to
`CT_CRED_<reference>`: configure a protected `CT_CREDENTIAL_SOURCES` registry
with explicit mounted-file or native Windows Credential Manager sources.
SSH keys require protected regular files selected by the account's binding.
The browser client's `CT_CRED_BROWSER_LOGIN` is a separate application login
secret; it grants no target access. Credentials and local state are excluded
from the Docker build context.

The optional `cyberthunder-target-credentials` Secret still projects files at
`/etc/cyberthunder/targets` with mode `0444`. Its `id_ed25519` path is **not a
supported SSH key input**: the key reader rejects projected symlinks and
group/world permissions. The package neither provisions protected target files
and their registry nor copies this Secret into trusted files. Follow
[Deployment credential provisioning](../../docs/DEPLOYMENT_CREDENTIAL_PROVISIONING.md)
for native/container requirements and the remaining package gap. See
[VM egress](../../packages/cyberthunder/README.md#ssh-access-to-an-external-vm)
for package network variables; network access alone supplies no credentials.
Network policy must allow access to the targets and any configured model server.

The image supports the Python SSH and WinRM transports and includes kubectl
v1.36.4 and digest-pinned Trivy v0.71.1. The deployment mounts a local-cluster kubeconfig and
rotating service account token. Its RBAC permits only `get` and `list` of
namespaces, nodes, workload resources, service accounts, services, RBAC bindings
and network policies, plus `get /version`, for discovery, configuration scans
and image baselines;
it cannot apply Kubernetes remediation or read Secrets. Use a kubectl version
compatible with the target cluster (`--build-arg KUBECTL_VERSION=vX.Y.Z`).

These cluster-wide permissions differ from a namespace-only Role. The current
standard collectors issue cluster-wide requests; successful reads of selected
types inside one namespace do not establish an end-to-end scan. The
[bounded local acceptance](../../docs/DEPLOYMENT_CREDENTIAL_PROVISIONING.md#pvc-root-and-namespace-acceptance-limits)
established limited namespace evidence and persistence, not full scanning or SSO.

Neither packaged role grants `nodes/proxy`; even `get` on that subresource can
authorize kubelet command execution. Optional kubelet `configz` evidence remains
unavailable through these roles. Review effective bindings on upgrade, including
an old alternate `cyberthunder-readonly` role. The
[package identity review](../../packages/cyberthunder/docs/IDENTITY_REVIEW.md)
records the RBAC evidence, traffic corrections and live acceptance requirements.

With an image rebuilt from this source, **Local Kubernetes cluster**
(`local-cluster`) appears automatically in **Assets**, with the mounted
in-cluster kubeconfig and **out of scope**. Sign in with a named account whose
roles and server policy permit the inventory/scope operation before using
**Discover**. A typed operator name cannot authorize verified operations;
discovery also requires the account's delegated target credential binding.
The projected bootstrap kubeconfig uses `tokenFile`, which the account validator
does not accept. Provision an owned protected regular kubeconfig with supported
explicit credentials and bind its path/context in that account's policy; neither
the pod token nor a copied `tokenFile` configuration is an account credential.
Existing names, options and scope
choices survive restarts. The deployment sets
`CT_BOOTSTRAP_CLUSTER_TARGET=true`; set it to `false` to disable registration.
Register external clusters manually with their separately mounted kubeconfigs.

The already-built `0.2.4`, `0.2.5` and `0.2.6` package archives predate these guardrails
and initially register new host-cluster assets in scope. Rebuild the image and
package from this source to get out-of-scope registration; the checked-in
archives have not been rebuilt by this change.

Before image baselines, stage a matching Trivy vulnerability database on the
state PVC and allow access to the image registries, including credentials for
private images. See the [package setup instructions](../../packages/cyberthunder/README.md#cluster-scanning-release).
Optional OpenAI summaries require a separately supplied API key and egress;
local template descriptions remain the default. Local commands run inside the
container and therefore describe the container, not its host.

## Troubleshooting

If a configuration scan reports `Forbidden` while listing service accounts,
services, RBAC bindings or network policies, upgrade to package `0.2.6` or apply
the [RBAC-only correction](../../packages/cyberthunder/README.md#upgrade-existing-scan-permissions)
from the updated checkout. The app keeps read-only access to scan inputs.

```sh
kubectl -n cyberthunder get pods,pvc
kubectl -n cyberthunder describe pod -l app=cyberthunder
kubectl -n cyberthunder logs deployment/cyberthunder
```

A pending PVC usually needs a storage class; ImagePullBackOff usually indicates
an unpublished image, incorrect tag, or missing registry credentials.
For `Init:Error`, inspect `kubectl -n cyberthunder logs deployment/cyberthunder -c identity-preflight`.
Missing settings, a projected policy symlink, wrong ownership or group-writable
ancestors require administrator correction, not a change to the guard.
