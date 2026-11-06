# UDS cluster deployment

The local demo combines
Defense Unicorns UDS Core with the Podinfo sample application in one UDS bundle.
UDS CLI packages and deploys the stack. Zarf packages contain its charts, images,
and manifests. See the [UDS bundle documentation](https://github.com/defenseunicorns/uds-core/blob/v1.14.3/docs/concepts/configuration-and-packaging/bundles.mdx).

## Prerequisites

- Install UDS CLI `v0.39.0`, k3d `v5.9.0`, Docker CLI, Python 3, and curl.
- On Linux, start Docker or a rootful Podman API service. The selected Docker
  context or `DOCKER_HOST` must reach that service. The Mac launcher starts its
  Podman VM.
- Allocate the resources listed in the [UDS Core v1.14.3 requirements](https://github.com/defenseunicorns/uds-core/blob/v1.14.3/docs/getting-started/local-demo/basic-requirements.mdx):
  4 CPU cores, 10 GiB RAM, and 40 GiB storage.
- Make host ports `80`, `443`, and `6550` available to the container engine.
- Allow access to GitHub Container Registry and Sigstore services while building
  and verifying upstream packages.

The scripts target macOS and Linux hosts using `arm64` or `amd64` Linux
container engines. Linux uses native Docker or rootful Podman. macOS uses a
rootful Podman machine. On November 4, 2026, `./deploy.sh dev` passed against
the existing `arm64` cluster on macOS with Podman. Verification covered the
development SSO login, workload readiness, Podinfo HTTPS redirect, and Prometheus
scraping. A WSL2 Ubuntu deployment and a scan of its k3d demo cluster from Windows
are also recorded below (5 Nov 2026). Native Linux, fresh macOS cluster creation,
and arbitrary existing Kubernetes cluster deployment remain unvalidated here.
These results do not establish that every Cyber Thunder container-to-target scan
and remediation path has been exercised; see [the validation matrix](VALIDATION.md).

## Deployment

1. Prepare the platform's container runtime.

   On macOS, install Podman and the Docker API client through Homebrew.

   ```sh
   brew install podman docker
   ```

   The launcher reuses `podman-machine-default` when available. Otherwise it
   creates that rootful machine with 6 CPUs, 16384 MiB RAM, and a 100 GiB disk.
   These are the configured allocations in `deploy-mac.sh`. An existing machine
   must be rootful and meet the upstream resource requirements. The launcher
   starts the machine without changing the default Podman connection.

   To initialize a new VM from a local Podman machine image, set
   `PODMAN_MACHINE_IMAGE` to that image's path. Otherwise Podman downloads its
   default machine image. See [Podman machine initialization](https://docs.podman.io/en/v6.1.3/markdown/podman-machine-init.1.html).

   On Linux with Docker, verify that the selected engine is reachable.

   ```sh
   docker context show
   docker info
   ```

   On Linux with Podman, start the rootful API service and run the deployment
   with permission to access `/run/podman/podman.sock`. On a systemd host:

   ```sh
   sudo systemctl start podman.socket
   ```

   On a host without systemd, run the API service in a separate terminal:

   ```sh
   sudo podman system service --time=0 unix:///run/podman/podman.sock
   ```

   Install the Docker API client for the Linux Podman path as well. See the
   [k3d Podman guide](https://k3d.io/stable/usage/advanced/podman/).

2. Build, deploy, and test the demo.

   On macOS or Linux with Docker:

   ```sh
   ./deploy.sh
   ```

   To enable the development SSO administrator and print its credentials:

   ```sh
   ./deploy.sh dev
   ```

   Dev mode creates or reconciles `hacker` in the `uds` realm and assigns
   `/UDS Core/Admin`. It disables conditional OTP and clears required login
   actions for this local development identity. The password is generated
   once, stored with mode `0600` in `.build/identity/admin-password`, and printed
   after deployment verification succeeds. Normal deployment excludes the
   identity bootstrap and credential output.

   Rerun `./deploy.sh dev` to re-enable a disabled development administrator
   and clear that account's failed-login lockout. The bootstrap verifies login
   and enabled status before succeeding. The realm's lockout policy remains
   enabled.

   If deployment ran without `dev`, configure the development administrator
   afterward without rebuilding the bundle or redeploying workloads:

   ```sh
   ./setup-dev-user.sh
   ```

   This command uses `.build/kubeconfig`, or the file specified by `KUBECONFIG`,
   and requires context `k3d-cyber-thunder`. Install UDS CLI, Python 3, and curl
   before running it. The cluster and Keycloak must already be running. It
   creates or reuses the same saved password as `./deploy.sh dev` and prints
   credentials after the identity bootstrap verifies login. It does not call
   k3d or the container runtime. The development identity changes described
   above also apply to this command.

   If `cyber-thunder` already exists, dev mode updates only identity bootstrap
   and Podinfo. It preserves the cluster and Core deployment. A missing
   Keycloak master administrator is created through the first-admin welcome
   flow; existing administrator credentials are verified and preserved.

   On Linux with rootful Podman:

   ```sh
   sudo env PATH="$PATH" CONTAINER_RUNTIME=podman ./deploy.sh
   ```

   Add `dev` to that command for the same development identity behavior.

   Use the same runtime and privileges for later verification and removal.
   The scripts build Podinfo and the combined UDS bundle, remove k3d clusters
   other than `cyber-thunder` from the selected engine, create `cyber-thunder`,
   deploy the stack, and run verification. Cluster removal deletes workloads
   and data. Clusters in other engines or machines are outside this command's
   scope.

   The build and deployment code is shared across both platforms. Podman uses
   a DNS-enabled `cyber-thunder` network and the rootful container socket. The
   scripts derive the bundle architecture from the container engine and write
   a separate kubeconfig to `.build/kubeconfig`.

   Normal deployment stops if `cyber-thunder` already exists. The upstream cluster
   package deletes a same-named cluster before creating one. Use `./deploy.sh`
   for initial deployment so the existing-cluster check runs. Rerun verification
   separately after a partial deployment.

3. Open the application and platform services.

   | Service | URL |
   | --- | --- |
   | Podinfo | <https://podinfo.uds.dev> |
   | Keycloak administration | <https://keycloak.admin.uds.dev> |
   | Grafana | <https://grafana.admin.uds.dev> |

   Podinfo redirects to UDS SSO. In dev mode, sign in with the printed `hacker`
   credentials. For normal deployment, create a user in the `uds` realm and
   assign it to `/UDS Core/Admin`. Retrieve the Keycloak master administrator
   password from its Secret when that credential has been provisioned.

   ```sh
   KUBECONFIG="$PWD/.build/kubeconfig" uds zarf tools kubectl \
     --context k3d-cyber-thunder -n keycloak get secret keycloak-admin-password \
     -o jsonpath='{.data.password}' | base64 --decode
   ```

   On macOS, use `base64 -D` instead of `base64 --decode`. Keep the generated
   credentials local. The demo domains must resolve to the machine exposing the
   cluster ports. A VM or remote engine also needs host port forwarding.

## Windows 11 host (WSL2)

The launcher runs on Linux, so on a Windows laptop it runs inside a WSL2 Ubuntu distribution that has Docker
Engine, k3d and the UDS CLI installed.

First run, 4 Nov 2026 (evening, Norfolk): Windows 11 Enterprise 22621, WSL 3.0.3 with Ubuntu 26.04.1 LTS, Docker
Engine 29.1.3, k3d v5.9.0, UDS CLI v0.39.0, 6 CPUs and 19 GiB given to WSL. `./deploy.sh dev` built the bundle,
created the cluster and deployed `uds-k3d-dev`, `init`, `core`, `identity-bootstrap` and `podinfo` in 24 minutes;
`scripts/verify.sh` passed (all pods ready, Podinfo HTTPS with the SSO redirect, Prometheus scraping Podinfo).
Cyber Thunder then scanned the cluster from Windows (see "Scanning the cluster from Windows" below).

1. Enable WSL2 once from an elevated PowerShell, then restart Windows:

   ```powershell
   wsl --install -d Ubuntu --no-launch
   ```

   VMware Workstation keeps working next to WSL2 (it switches to the Windows hypervisor platform; nested
   virtualization inside VMware guests is lost).

2. Give the WSL VM what UDS Core needs (4 CPUs and 10 GiB at least) in `%USERPROFILE%\.wslconfig`, then
   `wsl --shutdown` so it applies:

   ```ini
   [wsl2]
   memory=20GB
   processors=6
   swap=8GB
   ```

3. Open Ubuntu from the Start menu (the distribution name offered by the built-in WSL is plain `Ubuntu`, the current LTS), create the Linux user, and run the bootstrap. It installs Docker Engine,
   k3d v5.9.0 and UDS CLI v0.39.0, and clones this repository into the Linux file system:

   ```sh
   bash /mnt/c/dev/cyber-thunder/scripts/wsl-bootstrap.sh
   ```

   The first run switches systemd on and asks for one `wsl --shutdown`; rerun it afterwards.

4. In a new shell:

   ```sh
   cd ~/cyber-thunder && ./deploy.sh dev
   ```

Ports 80, 443 and 6550 must be free on Windows as well as inside WSL, because WSL forwards them to
`localhost`; the `uds.dev` names resolve to 127.0.0.1, so the printed addresses open from a Windows browser.
Keep the clone in the Linux file system (`~`), not under `/mnt/c`: Docker bind mounts and k3d are far slower
there.

**Keep the WSL test instance alive.** Closing the last active WSL session can let
the instance stop, taking Docker and the test cluster with it. The exact timing
depends on the installed WSL version and configuration. Use the optional
[per-user keep-alive helper](WSL_KEEPALIVE.md) from the stable Windows checkout:

```powershell
powershell.exe -NoProfile -File C:\dev\cyber-thunder\scripts\wsl-keepalive.ps1 -Action Plan
```

Review the plan, then use explicit Install and Start actions as documented there.
Installation does not start WSL. The helper leaves `.wslconfig` and current
sessions unchanged; it provides Status, Stop and Remove actions. Its task state
does not establish cluster health. Actual logon/reboot acceptance remains open.

### Scanning the cluster from Windows

The deploy writes `~/cyber-thunder/.build/kubeconfig` inside Ubuntu with the API server as `https://0.0.0.0:6550`.
From Windows the same port answers on 127.0.0.1 through the WSL port forward, so copy the file (its Windows path is
`\\wsl.localhost\Ubuntu\home\<user>\cyber-thunder\.build\kubeconfig`) and change the address. With a `kubectl.exe` on the laptop (the release binary from `dl.k8s.io`,
checksum verified), register the cluster as a Kubernetes target and scan it:

```bash
python -m cyberthunder --actor <your name> targets add --id k3d-cyber-thunder --type kubernetes --transport kubeconfig --option kubeconfig=C:\path\to\k3d.kubeconfig --option kubectl=C:\Tools\kubectl.exe --in-scope --reason "team demo cluster on this laptop"
```

```bash
python -m cyberthunder --actor <your name> scan --targets k3d-cyber-thunder --wait
```

First scan, 5 Nov 2026 02:21Z: 127 findings (119 Kubernetes STIG and CIS checks, 8 intrusion-hunt indicators) and no
adapter errors. The first attempt had exposed one bug, RBAC objects named like `system:controller:bootstrap-signer`
being rejected as object names, fixed before the second run. On k3s the API server runs inside the k3s process, so
the API-server flag rules report that nothing was collected unless a `node_target` with SSH access to the node is
set.

## Existing Kubernetes cluster

This mode deploys Zarf initialization, UDS Core, and Podinfo into the named
Kubernetes context. It uses a separate bundle that contains no k3d package.
It does not create or remove clusters and does not require a container engine
on the deployment host.

The cluster must use Linux nodes with one architecture, `amd64` or `arm64`.
Provide a default storage class, network policy enforcement, a load balancer,
DNS, gateway certificates, external S3-compatible storage, and a PostgreSQL
database for Keycloak. Follow the [UDS Core cluster prerequisites](https://github.com/defenseunicorns/uds-core/blob/v1.14.3/docs/getting-started/production/prerequisites.mdx)
and [external service setup](https://github.com/defenseunicorns/uds-core/blob/v1.14.3/docs/getting-started/production/provision-services.mdx).
Distribution-specific kernel and networking requirements still apply.

1. Copy the configuration template to a local file.

   ```sh
   umask 077
   mkdir -p .build
   cp bundles/existing-cluster/uds-config.example.yaml .build/existing-uds-config.yaml
   ```

2. Fill every configuration value in `.build/existing-uds-config.yaml`.

   Set `shared.domain` to the cluster's tenant domain. Supply the Keycloak
   database credentials, Loki bucket settings, Velero bucket settings and AWS
   credential file content, and base64-encoded gateway certificates and keys.
   Keep the configuration file local. See the [upstream configuration guide](https://github.com/defenseunicorns/uds-core/blob/v1.14.3/docs/getting-started/production/build-your-bundle.mdx).

3. Deploy to the named Kubernetes context.

   ```sh
   ./deploy.sh --existing-cluster your-context .build/existing-uds-config.yaml
   ```

   The script exports only that context to a private kubeconfig, checks nodes
   and the default storage class, and builds the bundle for the node
   architecture. It skips Zarf initialization when Zarf state already exists.
   Core and Podinfo use the pinned versions listed below.

   Verification uses the configured DNS domain and validates HTTPS
   certificates. Podinfo is available at `https://podinfo.<domain>`. Wildcard DNS
   must already route the tenant and admin domains to the appropriate gateways.

4. Rerun verification with the same context and domain when needed.

   ```sh
   KUBECONFIG="$PWD/.build/existing/kubeconfig" \
     ./scripts/verify.sh your-context your-domain.example
   ```

## Build and verification commands

1. Build without creating a cluster.

   ```sh
   uds run build
   ```

   This uses the host architecture by default. For a different target, set
   `UDS_ARCHITECTURE=arm64` or `UDS_ARCHITECTURE=amd64` before the command.
   Build outputs are stored in `.build/`.

   To build the existing-cluster bundle instead:

   ```sh
   uds run build-existing
   ```

2. Verify an existing deployment.

   ```sh
   uds run verify
   ```

   Verification checks node readiness, UDS Package readiness, deployment
   availability, pod readiness, Podinfo health, the HTTPS redirect to SSO, and
   a healthy Podinfo scrape target in Prometheus. The Prometheus check uses local port
   `19090`. The script closes its port-forward when it exits.

   The HTTPS check accepts the bundled development certificate for the local
   demo. Upstream package signature verification remains enabled. Interactive
   SSO login requires a configured user and is not part of the automated test.

3. Run the local deployment guard tests.

   ```sh
   python3 -m unittest discover -s tests -v
   bash -n deploy.sh deploy-mac.sh deploy-linux.sh setup-dev-user.sh scripts/*.sh packages/identity-bootstrap/scripts/*.sh
   shellcheck deploy.sh deploy-mac.sh deploy-linux.sh setup-dev-user.sh scripts/*.sh packages/identity-bootstrap/scripts/*.sh
   uds zarf dev lint packages/podinfo
   uds zarf dev lint packages/identity-bootstrap
   uds run build --dry-run
   uds run build-existing --dry-run
   ```

   The Python tests use command stubs to check failure handling and cluster
   preservation, platform selection, Podman setup, and existing-cluster
   deployment boundaries. They do not substitute for the live cluster test.

## Cluster removal

1. Select the same container engine used for deployment.
2. Delete the demo cluster when its data is no longer needed.

   ```sh
   k3d cluster delete cyber-thunder
   ```

## Package sources

| Package | Pinned version |
| --- | --- |
| UDS k3d environment | `0.21.0-airgap` |
| Zarf initialization | `v0.86.0` |
| UDS Core, upstream flavor | `1.14.3-upstream` |
| Local Podinfo Zarf package | `0.0.1` |
| Development identity bootstrap | `0.0.1` |
| Podinfo Helm chart and image | `6.10.1` |

The bundle derives from [`defenseunicorns/uds-core` tag `v1.14.3`](https://github.com/defenseunicorns/uds-core/tree/v1.14.3),
commit `ee479114762badb92eaf9b851779db55a76b0060`, file
`bundles/k3d-standard/uds-bundle.yaml`. The copied configuration retains its
copyright and license header. Its license is in
[licenses/uds-core-LICENSE.md](../licenses/uds-core-LICENSE.md).

The local bundle uses a published Core package, adds release signature
verification for Core, and appends Podinfo after Core. It retains upstream demo
overrides and disables the upstream organization-specific Google identity
provider and Fleet client. Other upstream package versions remain unchanged.

Podinfo follows the [UDS integration example](https://github.com/defenseunicorns/uds-core/blob/v1.14.3/docs/getting-started/local-demo/integrate-your-package.mdx).
Its UDS Package configures sidecar injection, tenant ingress, SSO, and a
PodMonitor for the chart's dedicated metrics port. Podinfo uses a version tag;
the image digest has not been pinned.

The identity scripts derive from `uds-proving-ground-local` commit
`d4468e3bf2dc7f0af5504337de4e5f9cd75eec71`, files
`packages/identity-bootstrap/scripts/ensure-user.sh` and
`scripts/ensure-keycloak-bootstrap-admin.sh`. The Cyber Thunder copy omits the
CAT audience mapper and requires dev mode and the local cluster context. The
existing-cluster bundle excludes these development identity changes.

## Cyber Thunder application container

To build and run the software in `cyberthunder/` inside Kubernetes, see
[the application container guide](../deploy/kubernetes/README.md). It includes
Docker build/push commands and standalone manifests with persistent state.

For a transferable archive containing both the application image and Kubernetes
resources, use the [Cyber Thunder Zarf package](../packages/cyberthunder/README.md).
