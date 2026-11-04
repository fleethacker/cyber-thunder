# Container host range target (podman on the Rocky 9 VM)

Seeds rootful containers that match `range/answer_key/containers.json` (three misconfigurations, three
intrusion indicators). The simulated target `sim-docker-01` carries the same seed. Isolated range only.

## 1. Engine

Rocky 9 ships podman:

```
sudo dnf -y install podman
```

Docker CE also works; the adapter tries `docker` first and falls back to `podman` (set `options.engine` to
choose). Offline, load the one base image the seed needs: `sudo podman load -i busybox-1.36.tar`.

## 2. Seed

```
sudo ./range/containers/seed.sh
```

`sudo ./range/containers/seed.sh --undo` removes the seeded containers. Every image is a local tag of
busybox; the "miner" is a sleep loop whose command line contains the xmrig arguments, so it only looks like
one. It does not mine or connect anywhere.

The I3 item (container started in the last 24 hours that is not on the expected list) is time-based: re-run
the seed (or `podman restart cache-sync`) on the day of the demo.

## 3. Point a target at it

```yaml
- id: rocky-01-containers
  name: rocky-01 containers
  asset_type: containers
  transport: ssh
  address: 10.20.0.10
  username: ctscan
  credential_ref: rocky01
  sudo: true
  options:
    engine: podman
    allowed_registries: [registry.local, docker.io/library]
    expected_containers: [web, ops-agent, ops-dashboard, metrics-relay]
    expected_ports: [443]
    critical_containers: [web]
```

`sudo: true` runs the engine commands through `sudo -n`; give the scan account a sudoers entry limited to
`/usr/bin/podman` (or `/usr/bin/docker`). If `trivy` is installed on the host with an offline DB, the adapter
also runs `trivy image --skip-db-update` for each running image and reports CVEs.

## What the fixes do here

- `containers:fix:stop-and-disable` (hunt items): `update --restart=no` then `stop`. The container and its
  filesystem are kept for forensics. Rollback restores the saved restart policy and starts it again.
  Podman: `podman update --restart` needs podman 4.6 or later.
- `containers:runbook:recreate-*` (configuration items): nothing is run. Applying the runbook prints the exact
  corrected `run` command built from `inspect`, plus the compose change, for the operator.
