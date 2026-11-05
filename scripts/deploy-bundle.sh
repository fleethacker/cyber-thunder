#!/usr/bin/env bash
set -euo pipefail
umask 077

repository_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_dir"

development_mode=false
if [ "$#" -eq 1 ] && [ "$1" = dev ]; then
  development_mode=true
elif [ "$#" -ne 0 ]; then
  echo "Usage: ./deploy.sh [dev]" >&2
  exit 1
fi

for command_name in uds k3d docker curl python3; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Required command not found: $command_name" >&2
    exit 1
  fi
done

# k3d reads DOCKER_HOST rather than the Docker CLI's selected context.
if [ -z "${DOCKER_HOST:-}" ]; then
  container_context=${DOCKER_CONTEXT:-$(docker context show)}
  DOCKER_HOST=$(docker context inspect "$container_context" --format '{{.Endpoints.docker.Host}}')
  export DOCKER_HOST
fi
unset DOCKER_CONTEXT
echo "Container endpoint: $DOCKER_HOST"

if ! engine_platform=$(docker info --format '{{.OSType}}/{{.Architecture}}'); then
  echo "Start the selected container engine, then rerun ./deploy.sh." >&2
  exit 1
fi
engine_memory_bytes=$(docker info --format '{{.MemTotal}}')
if [ "${engine_memory_bytes:-0}" -lt 10737418240 ]; then
  python3 - "$engine_memory_bytes" <<'PY'
import sys

memory_bytes = int(sys.argv[1] or 0)
gib = memory_bytes / 1024 / 1024 / 1024
sys.exit(
    f"The selected container engine exposes only {gib:.1f} GiB RAM. "
    "UDS Core needs at least 10 GiB for the local k3d demo; otherwise istiod cannot schedule "
    "and ztunnel stays unready. Increase Docker/Podman/WSL memory, restart the engine, delete the "
    "partial cyber-thunder cluster, and rerun ./deploy.sh."
)
PY
fi

case "$engine_platform" in
  linux/aarch64|linux/arm64) architecture=arm64 ;;
  linux/x86_64|linux/amd64) architecture=amd64 ;;
  *) echo "Unsupported container engine platform: $engine_platform" >&2; exit 1 ;;
esac

assert_new_cluster() {
  # The upstream k3d package deletes a same-named cluster before deployment.
  k3d cluster list --output json | python3 -c '
import json
import sys

clusters = json.load(sys.stdin)
if any(cluster["name"] == "cyber-thunder" for cluster in clusters):
    sys.exit("Cluster cyber-thunder already exists. Deployment stopped without deleting it.")
'
}

reuse_cluster=false
if [ "$development_mode" = true ]; then
  reuse_cluster=$(k3d cluster list --output json | python3 -c '
import json
import sys

print("true" if any(cluster["name"] == "cyber-thunder" for cluster in json.load(sys.stdin)) else "false")
')
fi
if [ "$reuse_cluster" = false ]; then
  assert_new_cluster
fi
echo "Architecture: $architecture"
uds version
k3d version

export CLI_FEATURES=NextMode=false
export UDS_ARCHITECTURE="$architecture"
export UDS_CONFIG="${UDS_CONFIG:-$repository_dir/bundles/k3d-demo/uds-config.yaml}"
export KUBECONFIG="$repository_dir/.build/kubeconfig"
mkdir -p .build
if [ "$reuse_cluster" = true ]; then
  k3d kubeconfig get cyber-thunder > "$KUBECONFIG"
  uds zarf tools kubectl --context k3d-cyber-thunder wait -n keycloak \
    --for=condition=Ready pod/keycloak-0 --timeout=120s
fi

uds run build
if [ "$reuse_cluster" = false ]; then
  assert_new_cluster
fi

bundle_version=$(uds zarf tools yq -r '.metadata.version' bundles/k3d-demo/uds-bundle.yaml)
bundle_file=".build/uds-bundle-cyber-thunder-${architecture}-${bundle_version}.tar.zst"
if [ ! -s "$bundle_file" ]; then
  echo "Built bundle not found: $bundle_file" >&2
  exit 1
fi

deploy_packages=uds-k3d-dev,init,core,podinfo,nginx-bad
if [ "$development_mode" = true ]; then
  mkdir -p .build/identity
  python3 - <<'PY'
from pathlib import Path
import secrets

password_file = Path('.build/identity/admin-password')
if not password_file.exists():
    password_file.write_text(secrets.token_urlsafe(32) + 'Aa1!@')
password_file.chmod(0o600)
if not password_file.read_text().strip():
    raise SystemExit('The development administrator password file is empty.')
PY
  generated_config=$(mktemp .build/identity/uds-config.XXXXXX)
  CYBER_THUNDER_PASSWORD="$(cat .build/identity/admin-password)" uds zarf tools yq \
    '.variables."identity-bootstrap".ADMIN_PASSWORD = strenv(CYBER_THUNDER_PASSWORD) | .variables."identity-bootstrap".DEV_MODE = "true" | .variables.core.INSECURE_ADMIN_PASSWORD_GENERATION = true' \
    "$UDS_CONFIG" > "$generated_config"
  mv "$generated_config" .build/identity/uds-config.yaml
  export UDS_CONFIG="$repository_dir/.build/identity/uds-config.yaml"
  deploy_packages=uds-k3d-dev,init,core,identity-bootstrap,podinfo,nginx-bad
  if [ "$reuse_cluster" = true ]; then
    deploy_packages=identity-bootstrap,podinfo,nginx-bad
  fi
fi

./scripts/cleanup-clusters.sh

uds deploy "$bundle_file" --architecture "$architecture" --packages "$deploy_packages" --confirm \
  --set CLUSTER_NAME=cyber-thunder

./scripts/verify.sh

echo "Podinfo: https://podinfo.uds.dev"
echo "Keycloak: https://keycloak.admin.uds.dev"
echo "Grafana: https://grafana.admin.uds.dev"
echo "Kubeconfig: $KUBECONFIG"
if [ "$development_mode" = true ]; then
  echo "UDS username: hacker"
  printf 'UDS password: %s\n' "$(cat .build/identity/admin-password)"
  echo "Password file: $repository_dir/.build/identity/admin-password"
fi
