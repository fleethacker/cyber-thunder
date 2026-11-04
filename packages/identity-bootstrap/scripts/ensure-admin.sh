#!/usr/bin/env bash
set -euo pipefail
set +x

if [[ "${DEV_MODE:-false}" != true ]]; then
  echo "Keycloak bootstrap requires ./deploy.sh dev." >&2
  exit 1
fi
if [[ -x ./zarf ]]; then
  zarf=(./zarf)
else
  zarf=(uds zarf)
fi
context=$("${zarf[@]}" tools kubectl config current-context)
[[ "$context" == k3d-cyber-thunder ]] || { echo "Expected context k3d-cyber-thunder." >&2; exit 1; }
PROJECT_ROOT=$PWD
BUILD_DIR="$PROJECT_ROOT/.build"
log() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }

umask 077
stage_dir="$BUILD_DIR/deploy/keycloak-bootstrap"
state_dir="$BUILD_DIR/identity/keycloak-bootstrap"
mkdir -p "$stage_dir" "$state_dir"
request_dir="$(mktemp -d "$stage_dir/request.XXXXXX")"
forward_pid=""
cleanup() {
  if [[ -n "$forward_pid" ]]; then
    kill "$forward_pid" 2>/dev/null || true
    wait "$forward_pid" 2>/dev/null || true
  fi
  rm -rf "$request_dir"
}
trap cleanup EXIT
base_url="https://keycloak.admin.${DOMAIN:-uds.dev}"
password_file="$state_dir/admin-password"

# --ignore-not-found distinguishes absence from API/RBAC/connectivity errors.
"${zarf[@]}" tools kubectl get secret keycloak-admin-password -n keycloak --ignore-not-found -o json > "$request_dir/secret.json" || die 'cannot inspect the Keycloak admin credential; refusing bootstrap'
credential_present=false
if [[ -s "$request_dir/secret.json" ]]; then
  credential_present=true
  python3 - "$request_dir/secret.json" > "$request_dir/password" <<'PY_SECRET'
import base64
import json
import sys

with open(sys.argv[1]) as secret_file:
    data = json.load(secret_file).get("data", {})
username = base64.b64decode(data.get("username", "YWRtaW4="), validate=True).decode()
password = base64.b64decode(data.get("password", ""), validate=True)
if username != "admin" or not password:
    sys.exit("Expected an admin username and password in keycloak-admin-password; existing Secret was preserved.")
sys.stdout.buffer.write(password)
PY_SECRET
  password_input="$request_dir/password"
else
  if [[ ! -s "$password_file" ]]; then
    python3 -c 'import secrets, sys; sys.stdout.write(secrets.token_hex(32))' > "$password_file"
    chmod 600 "$password_file"
  fi
  password_input="$password_file"
fi

# Keep passwords/tokens out of command arguments, logs and deployment archives.
check_admin() {
  local status
  status="$(curl -sS --connect-timeout 5 --max-time 30 -o "$request_dir/token.json" -w '%{http_code}' \
    "$base_url/realms/master/protocol/openid-connect/token" \
    --data-urlencode username=admin --data-urlencode "password@$password_input" \
    --data-urlencode client_id=admin-cli --data-urlencode grant_type=password)" || die 'Keycloak token endpoint is unreachable; refusing bootstrap'
  case "$status" in
    200) ;;
    400 | 401)
      # OAuth invalid_grant is HTTP 400 on the pinned Keycloak server. Other
      # errors (invalid_client, disabled grant, etc.) are not account absence.
      "${zarf[@]}" tools yq -e '.error == "invalid_grant" and .error_description == "Invalid user credentials"' "$request_dir/token.json" >/dev/null || die "Keycloak rejected the token request (HTTP $status); refusing bootstrap"
      return 1 ;;
    *) die "Keycloak token endpoint returned HTTP $status; refusing bootstrap" ;;
  esac
  local access_token
  access_token=$("${zarf[@]}" tools yq -r '.access_token // ""' "$request_dir/token.json")
  [[ -n "$access_token" ]] || die 'Keycloak returned no admin access token'
  printf 'Authorization: Bearer %s\n' "$access_token" > "$request_dir/headers"
  status="$(curl -sS --connect-timeout 5 --max-time 30 -o "$request_dir/realm.json" -w '%{http_code}' \
    -H "@$request_dir/headers" "$base_url/admin/realms/master")" || die 'Keycloak admin API is unreachable; refusing bootstrap'
  [[ "$status" == 200 ]] || die "stored credential lacks master admin access (HTTP $status); existing account was preserved"
}

if check_admin; then
  log 'existing Keycloak bootstrap admin credential verified'
elif [[ "$credential_present" == true ]]; then
  die 'stored Keycloak admin credential is invalid; existing account and Secret were preserved'
else
  # An absent Secret is not proof of an absent account. The supported welcome
  # form is available only before the first admin exists. Refuse if it is gone.
  # This localhost tunnel is solely for Keycloak's local-only bootstrap form;
  # authentication and all later admin API calls use the trusted public HTTPS.
  log 'checking for the first-admin welcome form via a temporary localhost tunnel'
  "${zarf[@]}" tools kubectl port-forward -n keycloak svc/keycloak-http --address 127.0.0.1 0:8080 > "$stage_dir/port-forward.log" 2>&1 &
  forward_pid=$!
  local_port=""
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    local_port="$(awk '/^Forwarding from 127.0.0.1:/ {split($3,p,":"); print p[2]; exit}' "$stage_dir/port-forward.log")"
    [[ -z "$local_port" ]] || break
    kill -0 "$forward_pid" 2>/dev/null || die 'Keycloak bootstrap tunnel exited before becoming ready'
    sleep 1
  done
  [[ "$local_port" =~ ^[0-9]+$ ]] || die 'Keycloak bootstrap tunnel did not become ready'
  local_url="http://127.0.0.1:$local_port/"
  curl -fsS --connect-timeout 5 --max-time 30 --cookie-jar "$request_dir/cookies" "$local_url" -o "$request_dir/welcome.html" || die 'cannot inspect the first-admin welcome form'
  if ! grep -q 'name="username"' "$request_dir/welcome.html" || ! grep -q 'name="stateChecker"' "$request_dir/welcome.html"; then
    die 'first-admin welcome form is unavailable; an admin exists or existed. Supply a working admin credential; existing accounts were preserved'
  fi
  state_checker="$(awk '$6 == "WELCOME_STATE_CHECKER" {print $7}' "$request_dir/cookies")"
  [[ -n "$state_checker" ]] || die 'Keycloak welcome form supplied no state-check cookie'
  log 'creating the missing Keycloak bootstrap admin through the supported welcome form'
  curl -fsS --connect-timeout 5 --max-time 30 --cookie "$request_dir/cookies" "$local_url"     --data-urlencode username=admin --data-urlencode "password@$password_input"     --data-urlencode "passwordConfirmation@$password_input" --data-urlencode "stateChecker=$state_checker"     --data-urlencode email=admin@uds.dev --data-urlencode firstName=Local --data-urlencode lastName=Admin     -o "$request_dir/create-response.html" || die 'Keycloak rejected first-admin creation; no existing account was reset'
  kill "$forward_pid" 2>/dev/null || true
  wait "$forward_pid" 2>/dev/null || true
  forward_pid=""
  # Verify creation independently; a successful form POST alone is insufficient.
  verified=false
  for ((attempt = 1; attempt <= 6; attempt++)); do
    if check_admin; then verified=true; break; fi
    sleep 2
  done
  [[ "$verified" == true ]] || die "created admin did not authenticate; password retained privately in $state_dir for recovery"
fi

if [[ "$credential_present" != true ]]; then
  # create, never apply: a concurrent or preexisting Secret is not overwritten.
  "${zarf[@]}" tools kubectl create secret generic keycloak-admin-password -n keycloak \
    --from-literal=username=admin --from-file="password=$password_file" > "$stage_dir/secret-create.log" || die 'could not publish the verified bootstrap credential; local password retained for retry'
  log 'verified Keycloak bootstrap admin credential created for development helpers'
fi
# Kubernetes now holds the credential. Remove the retry copy; it is not an
# additional long-lived host credential provider.
rm -f "$password_file"
