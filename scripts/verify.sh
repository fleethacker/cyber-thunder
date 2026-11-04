#!/usr/bin/env bash
set -euo pipefail
umask 077

repository_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_dir"
export CLI_FEATURES=NextMode=false
export KUBECONFIG="${KUBECONFIG:-$repository_dir/.build/kubeconfig}"

cluster_context=k3d-cyber-thunder
cluster_domain=uds.dev
curl_options=(--silent --show-error --max-time 30)
if [ "$#" -eq 2 ]; then
  cluster_context=$1
  cluster_domain=$2
elif [ "$#" -eq 0 ]; then
  # The local demo uses its bundled certificate and loopback port mapping.
  curl_options+=(--insecure --resolve podinfo.uds.dev:443:127.0.0.1)
else
  echo "Usage: ./scripts/verify.sh [CONTEXT DOMAIN]" >&2
  exit 1
fi

if [ ! -s "$KUBECONFIG" ]; then
  echo "Deployment kubeconfig not found: $KUBECONFIG" >&2
  exit 1
fi

kubectl() {
  uds zarf tools kubectl --context "$cluster_context" "$@"
}

kubectl wait node --all --for=condition=Ready --timeout=300s
kubectl wait packages.uds.dev --all --all-namespaces --for=jsonpath='{.status.phase}'=Ready --timeout=300s
kubectl wait deployment --all --all-namespaces --for=condition=Available --timeout=300s
kubectl wait pods --all --all-namespaces --field-selector=status.phase!=Succeeded --for=condition=Ready --timeout=300s
kubectl rollout status deployment/podinfo -n podinfo --timeout=300s
kubectl exec -n podinfo deployment/podinfo -c podinfo -- podcli check http localhost:9898/readyz
kubectl get podmonitors.monitoring.coreos.com -n podinfo

curl "${curl_options[@]}" \
  --dump-header .build/podinfo-headers --output /dev/null "https://podinfo.$cluster_domain/"
python3 -c '
import pathlib
import sys

headers = pathlib.Path(".build/podinfo-headers").read_text().lower()
expected_location = "location: https://sso." + sys.argv[1].lower() + "/realms/uds/"
if " 302 " not in headers or expected_location not in headers:
    sys.exit("Podinfo did not redirect to UDS SSO. See .build/podinfo-headers.")
print("Podinfo HTTPS and SSO redirect passed.")
' "$cluster_domain"

kubectl port-forward --address 127.0.0.1 -n monitoring \
  service/kube-prometheus-stack-prometheus 19090:9090 >.build/prometheus-forward.log 2>&1 &
forward_pid=$!
trap 'kill "$forward_pid" 2>/dev/null || true; wait "$forward_pid" 2>/dev/null || true' EXIT

for ((attempt = 1; attempt <= 60; attempt++)); do
  if ! kill -0 "$forward_pid" 2>/dev/null; then
    cat .build/prometheus-forward.log >&2
    exit 1
  fi
  if curl --silent --max-time 5 --fail --get \
    --data-urlencode 'query=up{namespace="podinfo"}' \
    --output .build/podinfo-metrics.json http://127.0.0.1:19090/api/v1/query; then
    if python3 -c '
import json
import sys

with open(".build/podinfo-metrics.json") as metrics_file:
    response = json.load(metrics_file)
results = response.get("data", {}).get("result", [])
sys.exit(0 if response.get("status") == "success" and results and
         all(float(result["value"][1]) == 1 for result in results) else 1)
'; then
      echo "Prometheus is scraping Podinfo."
      exit 0
    fi
  fi
  sleep 3
done

echo "Prometheus did not report a healthy Podinfo target. See .build/podinfo-metrics.json." >&2
exit 1
