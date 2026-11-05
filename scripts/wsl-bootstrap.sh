#!/usr/bin/env bash
# Prepare an Ubuntu WSL2 distribution to run ./deploy.sh (the UDS Core + Podinfo demo cluster) on a Windows
# laptop, then clone the repository into the Linux file system where k3d and UDS expect it.
#
# Run once inside the WSL distribution, as your normal user:
#   bash /mnt/c/dev/cyber-thunder/scripts/wsl-bootstrap.sh
# Then, in a NEW shell (so the docker group applies):
#   cd ~/cyber-thunder && ./deploy.sh dev
#
# Versions follow docs/DEPLOYMENT.md. Everything installs under /usr/local/bin or through apt.
set -euo pipefail

UDS_VERSION="${UDS_VERSION:-v0.39.0}"
K3D_VERSION="${K3D_VERSION:-v5.9.0}"
SOURCE_REPO="${SOURCE_REPO:-/mnt/c/dev/cyber-thunder}"
CLONE_DIR="${CLONE_DIR:-$HOME/cyber-thunder}"

if ! grep -qi microsoft /proc/version 2>/dev/null; then
  echo "This script is for a WSL2 distribution. On a plain Linux host follow docs/DEPLOYMENT.md directly." >&2
  exit 1
fi
if [ "$(uname -m)" != x86_64 ]; then
  echo "Expected an x86_64 distribution, found $(uname -m)." >&2
  exit 1
fi

step() { printf '\n== %s\n' "$*"; }

step "systemd inside WSL (Docker's service needs it)"
if ! grep -qs '^systemd=true' /etc/wsl.conf; then
  sudo mkdir -p /etc
  printf '[boot]\nsystemd=true\n' | sudo tee /etc/wsl.conf >/dev/null
  echo "systemd was switched on. Run 'wsl --shutdown' from Windows, reopen the distribution, and rerun this script."
  exit 0
fi
if [ "$(ps -p 1 -o comm= 2>/dev/null)" != systemd ]; then
  echo "systemd is configured but not running. Run 'wsl --shutdown' from Windows, reopen the distribution, and rerun." >&2
  exit 1
fi

step "packages: docker engine, python3, curl, git"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io python3 curl git ca-certificates >/dev/null
sudo systemctl enable --now docker
if ! id -nG "$USER" | tr ' ' '\n' | grep -qx docker; then
  sudo usermod -aG docker "$USER"
  echo "Added $USER to the docker group; it applies to new shells."
fi

step "k3d $K3D_VERSION"
if ! command -v k3d >/dev/null 2>&1 || ! k3d version 2>/dev/null | grep -q "k3d version $K3D_VERSION"; then
  curl -fsSL -o /tmp/k3d "https://github.com/k3d-io/k3d/releases/download/${K3D_VERSION}/k3d-linux-amd64"
  sudo install -m 0755 /tmp/k3d /usr/local/bin/k3d && rm -f /tmp/k3d
fi
k3d version | head -1

step "UDS CLI $UDS_VERSION"
if ! command -v uds >/dev/null 2>&1 || ! uds version 2>/dev/null | grep -q "${UDS_VERSION#v}"; then
  curl -fsSL -o /tmp/uds "https://github.com/defenseunicorns/uds-cli/releases/download/${UDS_VERSION}/uds-cli_${UDS_VERSION}_Linux_amd64"
  sudo install -m 0755 /tmp/uds /usr/local/bin/uds && rm -f /tmp/uds
fi
uds version

step "repository clone in the Linux file system ($CLONE_DIR)"
if [ ! -d "$CLONE_DIR/.git" ]; then
  if [ -d "$SOURCE_REPO/.git" ]; then
    git clone -q "$SOURCE_REPO" "$CLONE_DIR"
    git -C "$CLONE_DIR" remote set-url origin https://github.com/fleethacker/cyber-thunder.git
  else
    git clone -q https://github.com/fleethacker/cyber-thunder.git "$CLONE_DIR"
  fi
fi
git -C "$CLONE_DIR" log --oneline -1

step "checks"
for p in 80 443 6550; do
  if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}$"; then
    echo "port $p is already in use inside WSL; k3d needs it free" >&2
  fi
done
mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
cpus=$(nproc)
echo "WSL sees ${cpus} CPUs and $((mem_kb / 1024 / 1024)) GiB; UDS Core wants at least 4 CPUs and 10 GiB (see .wslconfig in docs/DEPLOYMENT.md)."
if ! sg docker -c 'docker info --format "{{.OSType}}/{{.Architecture}}"' 2>/dev/null; then
  echo "docker is not reachable yet; open a new shell and run: docker info" >&2
fi

cat <<EOF

Ready. In a new shell:
  cd $CLONE_DIR && ./deploy.sh dev
The first deployment downloads the UDS Core packages (several GB). When it finishes, verify.sh runs and the
script prints the Podinfo, Keycloak and Grafana addresses, which also open from a Windows browser.
Keep one wsl.exe session open while the cluster is in use (WSL stops the instance a minute after the last
session closes); docs/DEPLOYMENT.md shows a hidden keep-alive session and the .wslconfig idle timeout.
EOF
