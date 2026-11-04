#!/usr/bin/env bash
# Seed the k3s cluster on the range VM with the misconfigurations and intrusion indicators listed in
# range/answer_key/kubernetes.json. Run as root on the k3s server node of the ISOLATED range only.
#
#   sudo ./seed.sh            seed everything (restarts k3s once for the control-plane flags)
#   sudo ./seed.sh --undo     remove the seeded objects and the control-plane flags
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KUBECTL="k3s kubectl"
CONFIG=/etc/rancher/k3s/config.yaml
MARK="# cyber-thunder seed"
BASE_IMAGE="${BASE_IMAGE:-docker.io/library/busybox:1.36}"
IMAGES=(
  registry.local/apps/web-frontend:2.4.1
  registry.local/apps/payments:1.8.0
  registry.local/apps/toolbox:1.2
  registry.local/monitoring/prometheus:v2.53.0
  ghcr.io/x0rcist/node-tools:latest
  198.51.100.23:5000/collector:1.0
)

[[ $EUID -eq 0 ]] || { echo "run as root on the k3s server node" >&2; exit 1; }
command -v k3s >/dev/null || { echo "k3s not installed; see README.md" >&2; exit 1; }

if [[ "${1:-}" == "--undo" ]]; then
  $KUBECTL delete -f "$HERE/manifests/10-seeded.yaml" --ignore-not-found
  $KUBECTL delete -f "$HERE/manifests/00-baseline.yaml" --ignore-not-found
  if grep -q "$MARK" "$CONFIG" 2>/dev/null; then
    sed -i "/$MARK/,/$MARK end/d" "$CONFIG"
    systemctl restart k3s
  fi
  echo "seed removed"
  exit 0
fi

# 1. Control-plane flags (M2 anonymous-auth, M3 kubelet read-only port; M5 = no audit-log-path, the k3s default).
if ! grep -q "$MARK" "$CONFIG" 2>/dev/null; then
  cp -a "$CONFIG" "$CONFIG.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
  cat >> "$CONFIG" <<EOF
$MARK
kube-apiserver-arg:
  - "anonymous-auth=true"
kubelet-arg:
  - "read-only-port=10255"
$MARK end
EOF
  systemctl restart k3s
  until $KUBECTL get nodes >/dev/null 2>&1; do sleep 2; done
fi

# 2. Images. The range is offline: every seeded image is a local tag of one small base image, so pods start
#    without any registry. Import BASE_IMAGE first if it is not present:  k3s ctr images import busybox.tar
k3s ctr images ls -q | grep -qx "$BASE_IMAGE" || k3s ctr images pull "$BASE_IMAGE"
for img in "${IMAGES[@]}"; do
  k3s ctr images ls -q | grep -qx "$img" || k3s ctr images tag "$BASE_IMAGE" "$img"
done

# 3. Workloads, RBAC and the seeded objects.
$KUBECTL apply -f "$HERE/manifests/00-baseline.yaml"
$KUBECTL apply -f "$HERE/manifests/10-seeded.yaml"
echo "seeded: $(grep -c '"id"' "$HERE/../answer_key/kubernetes.json") answer-key items"
