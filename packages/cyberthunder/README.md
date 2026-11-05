# Cyber Thunder Zarf package

Built using the installed Zarf v0.85.0. The package includes the local
`cyberthunder:0.2.5` image, its SBOM, and the Deployment, Service, Namespace,
read-only cluster survey RBAC, kubeconfig and 10 GiB PVC from `deploy/kubernetes/cyberthunder.yaml`. The UDS Package in
`uds.yaml` configures Istio ingress and Keycloak SSO at
`https://cyberthunder.uds.dev` (or `cyberthunder.<DOMAIN>`).

## Cluster scanning release

Version `0.2.5` includes the app updates from `cluster-scan` commit
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

Version `0.2.5` fixes the configuration scan's `Forbidden` errors for
`serviceaccounts`, `services`, `clusterrolebindings`, `rolebindings` and
`networkpolicies`. The previous role covered cluster discovery and workload
baselines but omitted these configuration-check inputs. Deploy the `0.2.5`
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
but **out of scope**. No manual registration or external kubeconfig is needed
for the host cluster. Enter your operator name in **Settings**, enable the
asset's scope, then use **Discover** to retrieve the Kubernetes version, node
names and readiness. Discover returns HTTP 403 before scope is authorized.

The already-built `0.2.4` and `0.2.5` archives retain the earlier behavior:
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

### Cluster baseline API

With an authenticated browser session, the cluster API provides:

- `GET /api/v1/cluster/survey`: namespaces and workload images.
- `POST /api/v1/cluster/baseline` with `{"use_openai": false}` and an `X-Actor` header naming the operator: scan images and save risk profiles.
- `GET /api/v1/cluster/risk`: the latest saved profiles.

Trivy's vulnerability database and target images are not included in this app
archive. Before running a baseline, provision the database at
`/var/lib/cyberthunder/trivy-cache/db/` on the state PVC using a connected machine
with the same Trivy version. For example, stage a database on that machine:

```sh
docker run --rm --entrypoint trivy -v "$PWD/trivy-cache:/cache" cyberthunder:0.2.5 \
  image --cache-dir /cache --download-db-only
kubectl -n cyberthunder exec deployment/cyberthunder -c cyberthunder -- \
  mkdir -p /var/lib/cyberthunder/trivy-cache/db
kubectl -n cyberthunder cp trivy-cache/db/. \
  cyberthunder/POD_NAME:/var/lib/cyberthunder/trivy-cache/db -c cyberthunder
```

Replace `POD_NAME` with the app pod's name. The deployment retains the branch's
`CT_TRIVY_SKIP_DB_UPDATE=true` default and stores caches on the writable PVC.
Keep the database current through the same transfer process. Allow network
access to the registries that host the surveyed images in `uds.yaml`, then
rebuild for your environment. Private registries also need credentials and any
private CA configured for Trivy. A baseline reports per-image scan errors;
missing image access or database content does not establish a clean baseline.
Java analysis may additionally need a staged Java database; configure Trivy's
offline settings for fully disconnected operation.

OpenAI summaries remain opt-in, with template text available offline. Enabling
them requires a key provided through a Kubernetes Secret and explicit egress to
`api.openai.com:443`; the default package configures neither. The request sends
the namespace risk profile to that external service.

## Deploy to a remote cluster

Copy these artifacts from `packages/` to the deployment machine:

- `zarf-package-cyberthunder-amd64-0.2.5.tar.zst.part000`
- `zarf-package-cyberthunder-amd64-0.2.5.tar.zst.part001`
- `zarf-package-cyberthunder-amd64-0.2.5.tar.zst.part002`
- `zarf-package-cyberthunder-amd64-0.2.5.tar.zst.sha256`

The package uses Zarf split archives to keep each file below GitHub's 100 MiB
limit. Keep all three parts in the same directory; `.part000` contains the
reassembly metadata.

Use Zarf v0.85.0 and credentials for the intended remote cluster:

```sh
export KUBECONFIG=/path/to/remote-kubeconfig
kubectl config current-context
sha256sum -c zarf-package-cyberthunder-amd64-0.2.5.tar.zst.sha256
```

The package requires UDS Core with Keycloak and Authservice, an initialized Zarf
cluster, Linux amd64 nodes, and a default storage class supporting ReadWriteOnce
and fsGroup. Configure DNS for `cyberthunder.<domain>` to reach the UDS tenant
gateway; the local demo resolves `cyberthunder.uds.dev` to its loopback gateway.
Use the domain configured in UDS Core (default `uds.dev`):

```sh
zarf package deploy ./zarf-package-cyberthunder-amd64-0.2.5.tar.zst.part000 --confirm --set DOMAIN=uds.dev
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

The app uses one replica, persistent file state, and template explanations by
default. See [runtime configuration and scanning limitations](../../deploy/kubernetes/README.md).
Target and model-server egress must be explicitly allowed in the UDS Package for
your environment. A non-default storage class requires updating the PVC manifest
and rebuilding. SSO controls access; audit actions still use the app's configured
actor name in Settings.

## Verify

From the repository root after deployment:

```sh
# Local k3d demo, using its bundled TLS certificate:
./scripts/verify-cyberthunder.sh
# Other cluster/domain, using trusted TLS:
./scripts/verify-cyberthunder.sh CONTEXT DOMAIN
```

The check requires a Ready UDS Package and Deployment, an injected Istio sidecar,
Keycloak redirects for the UI/API/assets, and rejection of invalid bearer tokens.
Also sign in with an authorized user and confirm that the UI and `/api/v1/status`
load. A user outside `/UDS Core/Admin` must be denied access.

## Rebuild

From the repository root with a running Docker daemon. Rebuilt artifacts are written to `.build/`:

```sh
mkdir -p .build
docker build --platform linux/amd64 -t cyberthunder:0.2.5 .
zarf dev lint packages/cyberthunder
zarf package create packages/cyberthunder --confirm --architecture amd64 --max-package-size 95 --output .build
(cd .build && sha256sum zarf-package-cyberthunder-amd64-0.2.5.tar.zst.part* > zarf-package-cyberthunder-amd64-0.2.5.tar.zst.sha256)
```

Zarf falls back to the local Docker image when the tag cannot be found in a
registry. Lint warns that this local image uses a tag rather than a registry
and digest; the built archive carries the captured image and content checksums.
The default kubectl matches Kubernetes 1.36; set `--build-arg KUBECTL_VERSION=vX.Y.Z`
when rebuilding for a different cluster minor version. Bump the image tag and
package version together for subsequent releases.
