#!/usr/bin/env bash
set -euo pipefail
umask 077

repository_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [ "$#" -ne 2 ] || [ -z "$1" ]; then
  echo "Usage: ./deploy.sh --existing-cluster CONTEXT CONFIG_FILE" >&2
  exit 1
fi
cluster_context=$1
if [ ! -f "$2" ]; then
  echo "UDS configuration file not found: $2" >&2
  exit 1
fi
config_file=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
cd "$repository_dir"

export CLI_FEATURES=NextMode=false
export UDS_CONFIG="$config_file"
mkdir -p .build/existing
uds zarf tools yq -o=json '.variables.core' "$config_file" | python3 -c '
import json
import sys

values = {key.upper(): value for key, value in (json.load(sys.stdin) or {}).items()}
required = (
    "KEYCLOAK_DB_HOST", "KEYCLOAK_DB_USERNAME", "KEYCLOAK_DB_DATABASE", "KEYCLOAK_DB_PASSWORD",
    "LOKI_CHUNKS_BUCKET", "LOKI_ADMIN_BUCKET", "LOKI_S3_ENDPOINT", "LOKI_S3_REGION",
    "LOKI_ACCESS_KEY_ID", "LOKI_SECRET_ACCESS_KEY", "VELERO_BUCKET", "VELERO_REGION",
    "VELERO_S3_ENDPOINT", "VELERO_CLOUD_CREDENTIALS", "ADMIN_TLS_CERT", "ADMIN_TLS_KEY",
    "TENANT_TLS_CERT", "TENANT_TLS_KEY",
)
missing = [name for name in required if not isinstance(values.get(name), str) or not values[name].strip()]
if missing:
    sys.exit("Missing configuration values: " + ", ".join(missing))
'
cluster_domain=$(uds zarf tools yq -r '.shared.domain' "$config_file")
python3 -c '
import re
import sys

domain = sys.argv[1]
if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", domain) or "." not in domain or domain.endswith(".invalid"):
    sys.exit("Set shared.domain to the configured cluster DNS domain.")
' "$cluster_domain"

# Export only the named context so package actions cannot use another context.
uds zarf tools kubectl --context "$cluster_context" config view --raw --minify --flatten \
  > .build/existing/kubeconfig
export KUBECONFIG="$repository_dir/.build/existing/kubeconfig"
uds zarf tools kubectl config use-context "$cluster_context" >/dev/null

kubectl() {
  uds zarf tools kubectl --context "$cluster_context" "$@"
}

kubectl wait nodes --all --for=condition=Ready --timeout=300s
architecture=$(kubectl get nodes -o json | python3 -c '
import json
import sys

nodes = json.load(sys.stdin)["items"]
platforms = {(node["status"]["nodeInfo"]["operatingSystem"], node["status"]["nodeInfo"]["architecture"]) for node in nodes}
if len(platforms) != 1 or next(iter(platforms)) not in {("linux", "amd64"), ("linux", "arm64")}:
    sys.exit("Cluster nodes must use one supported Linux architecture: amd64 or arm64.")
print(next(iter(platforms))[1])
')
kubectl get storageclasses -o json | python3 -c '
import json
import sys

classes = json.load(sys.stdin)["items"]
if not any(item["metadata"].get("annotations", {}).get("storageclass.kubernetes.io/is-default-class") == "true" for item in classes):
    sys.exit("The cluster needs a default storage class.")
'

echo "Kubernetes context: $cluster_context"
echo "Architecture: $architecture"
export UDS_ARCHITECTURE="$architecture"
uds run build-existing
bundle_version=$(uds zarf tools yq -r '.metadata.version' bundles/existing-cluster/uds-bundle.yaml)
bundle_file=".build/uds-bundle-cyber-thunder-existing-${architecture}-${bundle_version}.tar.zst"
if [ ! -s "$bundle_file" ]; then
  echo "Built bundle not found: $bundle_file" >&2
  exit 1
fi

deploy_packages=init,core,podinfo
zarf_namespace=$(kubectl get namespace zarf --ignore-not-found -o name)
if [ -n "$zarf_namespace" ]; then
  zarf_state=$(kubectl get secret zarf-state -n zarf --ignore-not-found -o name)
  if [ -n "$zarf_state" ]; then
    deploy_packages=core,podinfo
  fi
fi

uds deploy "$bundle_file" --architecture "$architecture" --packages "$deploy_packages" --confirm
./scripts/verify.sh "$cluster_context" "$cluster_domain"
echo "Podinfo: https://podinfo.$cluster_domain"
