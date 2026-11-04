#!/usr/bin/env bash
set -euo pipefail
umask 077

repository_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$repository_dir"

if [ "$(uname -s)" != Linux ]; then
  echo "Run ./deploy-linux.sh on Linux." >&2
  exit 1
fi

case "${CONTAINER_RUNTIME:-docker}" in
  docker) ;;
  podman)
    export DOCKER_HOST="${DOCKER_HOST:-unix:///run/podman/podman.sock}"
    export DOCKER_SOCK=/run/podman/podman.sock
    unset DOCKER_CONTEXT
    ./scripts/prepare-podman.sh
    export UDS_CONFIG="$repository_dir/bundles/k3d-demo/uds-podman-config.yaml"
    ;;
  *) echo "Set CONTAINER_RUNTIME to docker or podman." >&2; exit 1 ;;
esac

exec ./scripts/deploy-bundle.sh "$@"
