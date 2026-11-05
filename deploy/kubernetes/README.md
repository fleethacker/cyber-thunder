# Run Cyber Thunder in Kubernetes

Run these commands from the repository root. The image builds the React UI and
serves it with the Python API on port 8000. It runs as UID/GID 10001.

## Build and publish

With a running Docker daemon, replace the example registry with yours:

```sh
docker build -t registry.example.com/team/cyberthunder:0.2.2 .
docker push registry.example.com/team/cyberthunder:0.2.2
```

Change `image` in `deploy/kubernetes/cyberthunder.yaml` to that published image.
For a private registry, configure an imagePullSecret in the namespace and
reference it in the pod specification. Build for the cluster node architecture
(use Docker buildx for a cluster with multiple architectures).

For a local k3d cluster, you can instead use:

```sh
docker build -t cyberthunder:0.2.2 .
k3d image import cyberthunder:0.2.2 -c cyber-thunder
```

## Deploy and open

Select the intended kubectl context first. The cluster needs a default storage
class that supports ReadWriteOnce volumes; otherwise set `storageClassName` on
the PVC. The storage driver must honor the pod's fsGroup so UID 10001 can write.

```sh
kubectl apply -f deploy/kubernetes/cyberthunder.yaml
kubectl -n cyberthunder rollout status deployment/cyberthunder
kubectl -n cyberthunder port-forward service/cyberthunder 8000:80
```

Open http://localhost:8000 (API status: `/api/v1/status`, docs: `/api/docs`).
The Service is internal. Add your cluster's authenticated TLS ingress before
exposing it to other users; these manifests do not configure authentication.
For a UDS cluster, deploy the [Cyber Thunder Zarf package](../../packages/cyberthunder/README.md)
instead. It includes authenticated ingress at `https://cyberthunder.<domain>`
with Keycloak SSO and access restricted to `/UDS Core/Admin`.

## State and configuration

The 10 GiB PVC holds inventory, audit records, findings, approvals and other
application state at `/var/lib/cyberthunder`. Back it up regularly. Keep one
replica and one API worker: state is file based. Recreate deployment strategy
stops the old pod before starting its replacement, with brief downtime.
Deleting the Deployment preserves the PVC; deleting the namespace deletes it.

The default `CT_LLM_BACKEND=template` works without a model server. To use an
existing Ollama service, set `CT_LLM_BACKEND=ollama` and `CT_LLM_URL` to its
reachable cluster URL (localhost refers to this container). Other `CT_*`
settings are documented in `cyberthunder/config.py`.

Inject target credentials using Kubernetes Secrets (the transports expect
`CT_CRED_<reference>` environment variables), or mount SSH keys read-only.
Credentials and local state are excluded from the Docker build context.
Network policy must allow access to the targets and any configured model server.

The base image supports the Python SSH and WinRM transports. Kubernetes target
scanning requires a compatible `kubectl` binary and an explicit mounted
kubeconfig; extend the image and add those mounts if needed. This deployment
neither grants cluster RBAC nor mounts a service account token. Local commands
run inside the container and therefore describe the container, not its host.
Do not mount a host container-engine socket merely to run the web application.

## Troubleshooting

```sh
kubectl -n cyberthunder get pods,pvc
kubectl -n cyberthunder describe pod -l app=cyberthunder
kubectl -n cyberthunder logs deployment/cyberthunder
```

A pending PVC usually needs a storage class; ImagePullBackOff usually indicates
an unpublished image, incorrect tag, or missing registry credentials.
