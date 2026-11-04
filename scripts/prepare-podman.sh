#!/usr/bin/env bash
set -euo pipefail

: "${DOCKER_HOST:?Set DOCKER_HOST to the Podman API socket.}"
rootless=$(podman --url "$DOCKER_HOST" info --format '{{.Host.Security.Rootless}}')
if [ "$rootless" != false ]; then
  echo "This deployment requires a rootful Podman service." >&2
  exit 1
fi

if podman --url "$DOCKER_HOST" network exists cyber-thunder; then
  :
else
  network_status=$?
  if [ "$network_status" -ne 1 ]; then
    echo "Unable to inspect the cyber-thunder Podman network." >&2
    exit "$network_status"
  fi
  podman --url "$DOCKER_HOST" network create cyber-thunder
fi
network_dns=$(podman --url "$DOCKER_HOST" network inspect cyber-thunder --format '{{.DNSEnabled}}')
if [ "$network_dns" != true ]; then
  echo "The cyber-thunder Podman network must have DNS enabled." >&2
  exit 1
fi
