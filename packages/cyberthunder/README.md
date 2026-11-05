# Cyber Thunder Zarf package

Built using the installed Zarf v0.85.0. The package includes the local
`cyberthunder:0.2.1` image, its SBOM, and the Deployment, Service, Namespace and
10 GiB PVC from `deploy/kubernetes/cyberthunder.yaml`.

## Deploy to a remote cluster

Copy these artifacts from `.build/` to the deployment machine:

- `zarf-package-cyberthunder-amd64-0.2.1.tar.zst`
- `zarf-package-cyberthunder-amd64-0.2.1.tar.zst.sha256`

Use Zarf v0.85.0 and credentials for the intended remote cluster:

```sh
export KUBECONFIG=/path/to/remote-kubeconfig
kubectl config current-context
sha256sum -c zarf-package-cyberthunder-amd64-0.2.1.tar.zst.sha256
```

The package requires Linux amd64 nodes, a default storage class that supports
ReadWriteOnce and fsGroup, and an initialized Zarf cluster. On a cluster that
has not been initialized, first transfer the matching Zarf v0.85.0 amd64 init
package and initialize it (this installs Zarf infrastructure):

```sh
zarf init /path/to/zarf-init-amd64-v0.85.0.tar.zst --confirm
```

Skip initialization on an already initialized cluster, including an existing
UDS cluster. Deploy the application:

```sh
zarf package deploy ./zarf-package-cyberthunder-amd64-0.2.1.tar.zst --confirm
kubectl -n cyberthunder rollout status deployment/cyberthunder
kubectl -n cyberthunder port-forward service/cyberthunder 8000:80
```

Open http://localhost:8000. The application image is carried in the archive;
no Docker load or public registry access is needed during application deployment.
Zarf pushes it into the cluster registry and rewrites pod image references.
The package is unsigned; the checksum verifies transfer integrity, not publisher
identity. No remote deployment has been performed as part of package creation.

The app uses one replica, persistent file state, and template explanations by
default. See [runtime configuration and access requirements](../../deploy/kubernetes/README.md)
for credentials, model services, authenticated ingress, and scanning limitations.
On UDS clusters, configure UDS ingress and network permissions separately.
A non-default storage class requires updating the PVC manifest and rebuilding.

## Rebuild

From the repository root with a running Docker daemon:

```sh
mkdir -p .build
docker build --platform linux/amd64 -t cyberthunder:0.2.1 .
zarf dev lint packages/cyberthunder
zarf package create packages/cyberthunder --confirm --architecture amd64 --output .build
(cd .build && sha256sum zarf-package-cyberthunder-amd64-0.2.1.tar.zst > zarf-package-cyberthunder-amd64-0.2.1.tar.zst.sha256)
```

Zarf falls back to the local Docker image when the tag cannot be found in a
registry. Lint warns that this local image uses a tag rather than a registry
and digest; the built archive carries the captured image and content checksums.
Bump the image tag and package version together for subsequent releases.
