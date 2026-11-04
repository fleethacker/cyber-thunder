#!/usr/bin/env bash
set -euo pipefail
umask 077

repository_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$repository_dir"

if [ "$(uname -s)" != Darwin ]; then
  echo "Run ./deploy-mac.sh on macOS." >&2
  exit 1
fi

for command_name in brew k3d uds python3 curl podman; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Required command not found: $command_name" >&2
    exit 1
  fi
done

docker_cli_prefix=$(brew --prefix docker)
if [ ! -x "$docker_cli_prefix/bin/docker" ]; then
  echo "Install the Docker API client with: brew install docker" >&2
  exit 1
fi
export PATH="$docker_cli_prefix/bin:$PATH"

mkdir -p .build
machine_name=podman-machine-default
podman machine list --format json > .build/podman-machines.json
machine_exists=$(python3 -c '
import json

with open(".build/podman-machines.json") as machine_file:
    machines = json.load(machine_file)
print("true" if any(machine["Name"] == "podman-machine-default" for machine in machines) else "false")
')

if [ "$machine_exists" = false ]; then
  init_options=(--provider applehv --rootful --cpus 6 --memory 16384 --disk-size 100)
  # Share Zarf temporary files and the repository with containers inside the VM.
  init_options+=(--volume /Users:/Users --volume /private:/private --volume /var/folders:/var/folders)
  case "$repository_dir" in
    /Users/*|/private/*) ;;
    *) init_options+=(--volume "$repository_dir:$repository_dir") ;;
  esac
  if [ -n "${PODMAN_MACHINE_IMAGE:-}" ]; then
    init_options+=(--image "$PODMAN_MACHINE_IMAGE")
  fi
  podman machine init "${init_options[@]}" "$machine_name"
fi

podman machine inspect "$machine_name" > .build/podman-machine.json
python3 -c '
import json
import sys

with open(".build/podman-machine.json") as machine_file:
    machine = json.load(machine_file)[0]
resources = machine["Resources"]
if not machine["Rootful"]:
    sys.exit("The podman-machine-default Podman machine must use rootful containers.")
if resources["CPUs"] < 4 or resources["Memory"] < 10240 or resources["DiskSize"] < 40:
    sys.exit("The podman-machine-default Podman machine needs at least 4 CPUs, 10240 MiB RAM, and 40 GiB disk.")
'

machine_state=$(podman machine inspect "$machine_name" --format '{{.State}}')
if [ "$machine_state" != running ]; then
  podman machine start --update-connection=false "$machine_name"
fi

podman_socket=$(podman machine inspect "$machine_name" --format '{{.ConnectionInfo.PodmanSocket.Path}}')
export DOCKER_HOST="unix://$podman_socket"
export DOCKER_SOCK=/run/podman/podman.sock
unset DOCKER_CONTEXT
docker info >/dev/null

./scripts/prepare-podman.sh

export UDS_CONFIG="$repository_dir/bundles/k3d-demo/uds-podman-config.yaml"
exec ./scripts/deploy-bundle.sh "$@"
