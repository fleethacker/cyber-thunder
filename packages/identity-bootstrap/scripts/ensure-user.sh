#!/usr/bin/env bash

set -euo pipefail
set +x

username="admin"
email=admin@uds.dev
domain="${DOMAIN:-uds.dev}"

if [[ -x ./zarf ]]; then
  zarf=(./zarf)
else
  zarf=(uds zarf)
fi

render_user_payload() {
  KC_USERNAME="$username" KC_EMAIL="$email" KC_PASSWORD="$ADMIN_PASSWORD" \
    "${zarf[@]}" tools yq -n -o=json \
    '{"username": strenv(KC_USERNAME), "email": strenv(KC_EMAIL), "enabled": true, "emailVerified": true, "requiredActions": [], "credentials": [{"type": "password", "value": strenv(KC_PASSWORD), "temporary": false}]}'
}

render_password_payload() {
  KC_PASSWORD="$ADMIN_PASSWORD" "${zarf[@]}" tools yq -n -o=json \
    '{"type": "password", "value": strenv(KC_PASSWORD), "temporary": false}'
}

if [[ "${DEV_MODE:-false}" != true ]]; then
  echo "Development identity setup requires ./deploy.sh dev." >&2
  exit 1
fi
: "${ADMIN_PASSWORD:?ADMIN_PASSWORD is required}"
if [[ "${BOOTSTRAP_DRY_RUN:-false}" == true ]]; then
  render_user_payload >/dev/null
  render_password_payload >/dev/null
  echo "reconcile Keycloak user admin with email admin@uds.dev"
  echo "user payload valid"
  exit 0
fi

kubectl=("${zarf[@]}" tools kubectl)
keycloak_admin_url="https://keycloak.admin.${domain}"
context=$("${kubectl[@]}" config current-context)
if [[ "$context" != k3d-cyber-thunder ]]; then
  echo "Development identity setup requires context k3d-cyber-thunder." >&2
  exit 1
fi

umask 077
mkdir -p .build/deploy/identity-bootstrap
request_dir=$(mktemp -d .build/deploy/identity-bootstrap/request.XXXXXX)
trap 'rm -rf "$request_dir"' EXIT
printf '%s' "$ADMIN_PASSWORD" > "$request_dir/user-password"

"${kubectl[@]}" wait -n keycloak --for=condition=Ready pod/keycloak-0 --timeout=120s >/dev/null
curl -fsS -o /dev/null --retry 20 --retry-delay 2 --retry-all-errors \
  --connect-timeout 5 --max-time 120 "${keycloak_admin_url}/realms/master"
bash "$(dirname "${BASH_SOURCE[0]}")/ensure-admin.sh"
keycloak_password=$("${kubectl[@]}" get secret -n keycloak keycloak-admin-password -o jsonpath='{.data.password}' \
  | "${zarf[@]}" tools yq -r '@base64d')
printf '%s' "$keycloak_password" > "$request_dir/keycloak-password"
unset keycloak_password
admin_token="$(curl -fsS "${keycloak_admin_url}/realms/master/protocol/openid-connect/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode username=admin \
  --data-urlencode "password@$request_dir/keycloak-password" \
  --data-urlencode client_id=admin-cli \
  --data-urlencode grant_type=password | "${zarf[@]}" tools yq -r .access_token)"
[[ -n "$admin_token" && "$admin_token" != null ]] || { echo "Keycloak returned no admin token." >&2; exit 1; }
printf 'Authorization: Bearer %s\n' "$admin_token" > "$request_dir/admin-headers"
unset admin_token

# This is a local development environment. Disable the realm's conditional OTP
# execution so the generated administrator can sign in without enrolling MFA.
conditional_otp_id="$(curl -fsS \
  "${keycloak_admin_url}/admin/realms/uds/authentication/flows/Authentication/executions" \
  -H "@$request_dir/admin-headers" \
  | "${zarf[@]}" tools yq -r '.[] | select(.displayName == "Conditional OTP") | .id' \
  | head -n 1)"
if [[ -n "$conditional_otp_id" ]]; then
  OTP_EXECUTION_ID="$conditional_otp_id" "${zarf[@]}" tools yq -n -o=json \
    '{"id": strenv(OTP_EXECUTION_ID), "requirement": "DISABLED"}' \
    | curl -fsS -o /dev/null -X PUT \
      "${keycloak_admin_url}/admin/realms/uds/authentication/flows/Authentication/executions" \
      -H "@$request_dir/admin-headers" -H 'Content-Type: application/json' --data-binary @-
fi

user_id="$(curl -fsS "${keycloak_admin_url}/admin/realms/uds/users?username=${username}&exact=true" \
  -H "@$request_dir/admin-headers" | "${zarf[@]}" tools yq -r '.[0].id // ""')"
if [[ -z "$user_id" ]]; then
  render_user_payload \
    | curl -fsS -o /dev/null -X POST "${keycloak_admin_url}/admin/realms/uds/users" \
      -H "@$request_dir/admin-headers" -H 'Content-Type: application/json' --data-binary @-
  user_id="$(curl -fsS "${keycloak_admin_url}/admin/realms/uds/users?username=${username}&exact=true" \
    -H "@$request_dir/admin-headers" | "${zarf[@]}" tools yq -r '.[0].id')"
else
  curl -fsS -o /dev/null -X PUT "${keycloak_admin_url}/admin/realms/uds/users/${user_id}" \
    -H "@$request_dir/admin-headers" -H 'Content-Type: application/json' \
    --data-raw '{"username":"admin","email":"admin@uds.dev","enabled":true,"emailVerified":true,"requiredActions":[]}'
fi

password_status="$(curl -sS -o /dev/null -w '%{http_code}' \
  "https://sso.${domain}/realms/uds/protocol/openid-connect/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "username=${username}" \
  --data-urlencode "password@$request_dir/user-password" \
  --data-urlencode client_id=admin-cli \
  --data-urlencode grant_type=password)"
if [[ "$password_status" != 200 ]]; then
  render_password_payload \
    | curl -fsS -o /dev/null -X PUT \
      "${keycloak_admin_url}/admin/realms/uds/users/${user_id}/reset-password" \
      -H "@$request_dir/admin-headers" -H 'Content-Type: application/json' --data-binary @-
fi

parent_group_id="$(curl -fsS --get "${keycloak_admin_url}/admin/realms/uds/groups" \
  -H "@$request_dir/admin-headers" --data-urlencode 'search=UDS Core' --data-urlencode exact=true \
  | "${zarf[@]}" tools yq -r '.[0].id // ""')"
[[ -n "$parent_group_id" ]] || { echo "UDS Core group not found" >&2; exit 1; }
group_id="$(curl -fsS "${keycloak_admin_url}/admin/realms/uds/groups/${parent_group_id}/children" \
  -H "@$request_dir/admin-headers" \
  | "${zarf[@]}" tools yq -r '.[] | select(.name == "Admin") | .id' | head -n 1)"
[[ -n "$group_id" ]] || { echo "UDS Core/Admin group not found" >&2; exit 1; }
curl -fsS -o /dev/null -X PUT \
  "${keycloak_admin_url}/admin/realms/uds/users/${user_id}/groups/${group_id}" \
  -H "@$request_dir/admin-headers"

# UDS Terms and Conditions can add TERMS_AND_CONDITIONS when Admin group
# membership changes. Reconcile required actions after group assignment, then
# prove that the direct-grant login used by local automation actually works.
user_token=""
for ((attempt = 1; attempt <= 10; attempt++)); do
  curl -fsS -o /dev/null -X PUT "${keycloak_admin_url}/admin/realms/uds/users/${user_id}" \
    -H "@$request_dir/admin-headers" -H 'Content-Type: application/json' \
    --data-raw '{"username":"admin","email":"admin@uds.dev","enabled":true,"emailVerified":true,"requiredActions":[]}'
  token_response="$(curl -sS "https://sso.${domain}/realms/uds/protocol/openid-connect/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "username=${username}" \
    --data-urlencode "password@$request_dir/user-password" \
    --data-urlencode client_id=admin-cli \
    --data-urlencode grant_type=password)"
  user_token="$(printf '%s' "$token_response" | "${zarf[@]}" tools yq -r '.access_token // ""')"
  [[ -n "$user_token" ]] && break
  sleep 1
done
if [[ -z "$user_token" ]]; then
  printf 'local development identity login failed: %s\n' \
    "$(printf '%s' "$token_response" | "${zarf[@]}" tools yq -r '.error_description // .error // "unknown error"')" >&2
  exit 1
fi

echo "local development identity reconciled"
