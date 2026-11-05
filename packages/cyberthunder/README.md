# Cyber Thunder Zarf package

Built using the installed Zarf v0.85.0. The package includes the local
`cyberthunder:0.2.2` image, its SBOM, and the Deployment, Service, Namespace and
10 GiB PVC from `deploy/kubernetes/cyberthunder.yaml`. The UDS Package in
`uds.yaml` configures Istio ingress and Keycloak SSO at
`https://cyberthunder.uds.dev` (or `cyberthunder.<DOMAIN>`).

## Deploy to a remote cluster

Copy these artifacts from `packages/` to the deployment machine:

- `zarf-package-cyberthunder-amd64-0.2.2.tar.zst`
- `zarf-package-cyberthunder-amd64-0.2.2.tar.zst.sha256`

Use Zarf v0.85.0 and credentials for the intended remote cluster:

```sh
export KUBECONFIG=/path/to/remote-kubeconfig
kubectl config current-context
sha256sum -c zarf-package-cyberthunder-amd64-0.2.2.tar.zst.sha256
```

The package requires UDS Core with Keycloak and Authservice, an initialized Zarf
cluster, Linux amd64 nodes, and a default storage class supporting ReadWriteOnce
and fsGroup. Configure DNS for `cyberthunder.<domain>` to reach the UDS tenant
gateway; the local demo resolves `cyberthunder.uds.dev` to its loopback gateway.
Use the domain configured in UDS Core (default `uds.dev`):

```sh
zarf package deploy ./zarf-package-cyberthunder-amd64-0.2.2.tar.zst --confirm --set DOMAIN=uds.dev
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
docker build --platform linux/amd64 -t cyberthunder:0.2.2 .
zarf dev lint packages/cyberthunder
zarf package create packages/cyberthunder --confirm --architecture amd64 --output .build
(cd .build && sha256sum zarf-package-cyberthunder-amd64-0.2.2.tar.zst > zarf-package-cyberthunder-amd64-0.2.2.tar.zst.sha256)
```

Zarf falls back to the local Docker image when the tag cannot be found in a
registry. Lint warns that this local image uses a tag rather than a registry
and digest; the built archive carries the captured image and content checksums.
Bump the image tag and package version together for subsequent releases.
