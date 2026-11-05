#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

repository_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$repository_dir"

if [ "$#" -ne 0 ]; then
  echo "Usage: ./setup-dev-user.sh" >&2
  exit 1
fi
for command_name in uds python3 curl; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Required command not found: $command_name" >&2
    exit 1
  fi
done

export KUBECONFIG="${KUBECONFIG:-$repository_dir/.build/kubeconfig}"
if [ ! -s "$KUBECONFIG" ]; then
  echo "Deployment kubeconfig not found: $KUBECONFIG" >&2
  exit 1
fi
context=$(uds zarf tools kubectl config current-context)
if [ "$context" != k3d-cyber-thunder ]; then
  echo "Development identity setup requires context k3d-cyber-thunder." >&2
  exit 1
fi

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

DEV_MODE=true DOMAIN=uds.dev BOOTSTRAP_DRY_RUN=false \
  ADMIN_PASSWORD="$(cat .build/identity/admin-password)" \
  bash packages/identity-bootstrap/scripts/ensure-user.sh

echo "SSO: https://sso.uds.dev"
echo "UDS username: hacker"
printf 'UDS password: %s\n' "$(cat .build/identity/admin-password)"
echo "Password file: $repository_dir/.build/identity/admin-password"
