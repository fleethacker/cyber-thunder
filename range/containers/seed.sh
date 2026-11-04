#!/usr/bin/env bash
# Seed the container host on the range VM with the items in range/answer_key/containers.json.
# Works with podman (Rocky 9 default) or docker. ISOLATED range only.
#
#   sudo ./seed.sh           create the seeded containers
#   sudo ./seed.sh --undo    remove them
#
# Every image is a local tag of one small base image, so nothing is pulled from a registry and the
# "miner" is a sleep loop whose command line only looks like xmrig. Nothing here mines or beacons.
set -euo pipefail

ENGINE="${ENGINE:-$(command -v podman >/dev/null && echo podman || echo docker)}"
BASE_IMAGE="${BASE_IMAGE:-docker.io/library/busybox:1.36}"
NAMES=(web ops-agent ops-dashboard metrics-relay systemd-update backup-agent cache-sync)
SOCKET=/var/run/docker.sock
[[ "$ENGINE" == podman ]] && SOCKET=/run/podman/podman.sock

[[ $EUID -eq 0 ]] || { echo "run as root (rootful containers are what the checks look at)" >&2; exit 1; }

if [[ "${1:-}" == "--undo" ]]; then
  for n in "${NAMES[@]}"; do $ENGINE rm -f "$n" >/dev/null 2>&1 || true; done
  echo "seed removed"
  exit 0
fi

$ENGINE image exists "$BASE_IMAGE" 2>/dev/null || $ENGINE image inspect "$BASE_IMAGE" >/dev/null 2>&1 \
  || $ENGINE pull "$BASE_IMAGE"
tag() { $ENGINE tag "$BASE_IMAGE" "$1"; }
for img in docker.io/library/nginx:1.25.3 registry.local/ops/agent:3.2 registry.local/ops/dashboard:1.4 \
           registry.local/ops/relay:2.0 docker.io/xmrig/xmrig:6.21.0 registry.local/ops/backup:1.0 \
           203.0.113.50:5000/cache-sync:0.3; do
  tag "$img"
done
[[ "$ENGINE" == podman ]] && systemctl enable --now podman.socket >/dev/null 2>&1 || true

hard=(--user 1000 --read-only --memory 256m --cpus 0.5 --restart unless-stopped)
run() { $ENGINE run -d --pull never "$@" >/dev/null; }

# compliant baseline (port 443 is on the expected list)
run --name web --user 101 --read-only --memory 256m --cpus 0.5 --restart always -p 443:443 \
    docker.io/library/nginx:1.25.3 sleep 86400
# M1 privileged
run --name ops-agent "${hard[@]}" --privileged registry.local/ops/agent:3.2 sleep 86400
# M2 engine socket mounted
run --name ops-dashboard "${hard[@]}" -v "$SOCKET:/var/run/docker.sock" registry.local/ops/dashboard:1.4 sleep 86400
# M3 host network
run --name metrics-relay "${hard[@]}" --network host registry.local/ops/relay:2.0 sleep 86400
# I1 miner look-alike, root, no limits, restart always, unapproved image
run --name systemd-update --restart always docker.io/xmrig/xmrig:6.21.0 \
    sh -c 'while true; do sleep 60; done # xmrig -o stratum+tcp://10.10.10.10:3333 -u enclave --donate-level 0'
# I2 host root mounted read-write
run --name backup-agent "${hard[@]}" -v /:/host registry.local/ops/backup:1.0 sleep 86400
# I3 recent, unexpected container from an unknown registry (start it last so it is the newest)
run --name cache-sync "${hard[@]}" 203.0.113.50:5000/cache-sync:0.3 sleep 86400

echo "seeded ${#NAMES[@]} containers with $ENGINE"
