#!/usr/bin/env bash
# Verify the installed Cyber Thunder UDS package and its authentication boundary.
set -euo pipefail

context=${1:-k3d-cyber-thunder}
domain=${2:-uds.dev}
base_url="https://cyberthunder.$domain"
curl_options=(--silent --show-error --max-time 30)
if [ "$#" -eq 0 ]; then
  curl_options+=(--insecure --resolve cyberthunder.uds.dev:443:127.0.0.1)
fi
kubectl() { uds zarf tools kubectl --context "$context" "$@"; }

kubectl wait -n cyberthunder package/cyberthunder --for=jsonpath='{.status.phase}'=Ready --timeout=300s
kubectl rollout status -n cyberthunder deployment/cyberthunder --timeout=300s
kubectl wait -n cyberthunder pod -l app=cyberthunder --for=condition=Ready --timeout=300s
containers=$(kubectl get pods -n cyberthunder -l app=cyberthunder -o jsonpath='{.items[0].spec.containers[*].name} {.items[0].spec.initContainers[?(@.restartPolicy=="Always")].name}')
if [[ " $containers " != *' istio-proxy '* ]]; then
  echo 'Cyber Thunder is missing its Istio authentication proxy.' >&2
  exit 1
fi

# Both browser and API requests must go through SSO. An invalid bearer token
# must be rejected rather than bypassing the browser authentication policy.
for path in / /api/v1/status /assets/unauthenticated.js; do
  headers=$(curl "${curl_options[@]}" --dump-header - --output /dev/null "$base_url$path")
  if ! printf '%s\n' "$headers" | tr -d '\r' | grep -Eq '^HTTP/[^ ]+ 302'; then
    echo "Expected an SSO redirect for $path" >&2
    exit 1
  fi
  location=$(printf '%s\n' "$headers" | tr -d '\r' | sed -n 's/^[Ll]ocation: //p')
  if [[ "$location" != "https://sso.$domain/realms/uds/"* || "$location" != *'client_id=cyber-thunder-app'* ]]; then
    echo "Unexpected SSO client or issuer for $path" >&2
    exit 1
  fi
  echo "PASS: $path requires Cyber Thunder Keycloak login"
done
status=$(curl "${curl_options[@]}" --header 'Authorization: Bearer invalid' --output /dev/null --write-out '%{http_code}' "$base_url/api/v1/status")
if [[ "$status" != 401 && "$status" != 403 ]]; then
  echo "Invalid bearer token was not rejected (HTTP $status)." >&2
  exit 1
fi
echo 'PASS: invalid bearer token rejected'
echo "Cyber Thunder is ready at $base_url (Keycloak group /UDS Core/Admin)."
