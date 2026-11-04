#!/usr/bin/env bash
set -euo pipefail

repository_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [ "$#" -eq 3 ] && [ "$1" = --existing-cluster ]; then
  exec "$repository_dir/scripts/deploy-existing.sh" "$2" "$3"
fi
if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != dev ]; }; then
  echo "Usage: ./deploy.sh [dev | --existing-cluster CONTEXT CONFIG_FILE]" >&2
  exit 1
fi
case "$(uname -s)" in
  Darwin) exec "$repository_dir/deploy-mac.sh" "$@" ;;
  Linux) exec "$repository_dir/deploy-linux.sh" "$@" ;;
  *) echo "Supported hosts: macOS and Linux." >&2; exit 1 ;;
esac
