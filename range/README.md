# Local range

A disposable, deliberately misconfigured enclave on the laptop. Use it until the event range is reachable and
keep it as the demo fallback. Never point Cyber Thunder at a live network.

| Asset | Type in inventory | Built as |
|---|---|---|
| `acd-target-01` | linux | Rocky Linux 9 VM with OpenSCAP and the STIG content |
| `acd-k3s` | kubernetes | k3s single node on the same VM |
| `acd-containers` | containers | podman containers on the same VM |
| `acd-sw-01` | cisco | an IOS-style running-config file (no device needed) |
| `acd-win-01` | windows | optional Windows VM |

Seed scripts: `range/seed_misconfig.sh` (Linux), `range/k8s/seed.sh`, `range/containers/seed.sh`,
`range/cisco/*.cfg`, `range/windows/seed_misconfig.ps1`. Answer keys:
`range/answer_key/{linux,cisco_ios,kubernetes,containers,windows,discovery}.json`. The answer key lists every
seeded item (misconfiguration or intrusion indicator), what should detect it, and the fix it maps to; it is
used for the detection score on the Reports page and must never be shown to the model.

## Rocky 9 VM (one time, about 25 minutes)

> **Automated path (VMware Workstation):** [`range/vmware/new-range-vm.ps1`](vmware/README.md) does
> steps 1–6 below hands-off: it writes the vmx, bakes an `OEMDRV` kickstart ISO, drives the unattended
> install, checks SSH and passwordless sudo, and snapshots `clean`. The manual steps below still apply
> to any other hypervisor. See [the first real-host run](#first-real-host-run-from-the-laptop) for the
> scan results this produced.

1. Download `Rocky-9-latest-x86_64-minimal.iso` from the Rocky Linux site.
2. In the hypervisor: new VM, Linux / RHEL 9 64-bit, name `acd-target-01`, 2 vCPU, 4 GB RAM (8 GB if k3s
   and podman run on it), 40 GB disk, **NAT** network.
3. Install: Minimal, hostname `acd-target-01`, root password set, user `acd` with administrator (sudo).
4. First boot, as `acd`:

```bash
sudo dnf install -y openscap-scanner scap-security-guide openssh-server python3 tar
sudo systemctl enable --now sshd
ip -4 addr show | grep inet
```

5. From the laptop, copy your SSH key and confirm sudo works without a terminal:

```bash
ssh-copy-id acd@<vm-ip>
ssh acd@<vm-ip> 'sudo -n true && echo SUDO_OK'
```

6. Take a snapshot named **`clean`**.

## k3s and podman on the same VM

Install what the Kubernetes and container areas need (needs a one-time internet connection, so do it before
the event and snapshot afterwards):

```bash
sudo dnf install -y podman
curl -sfL https://get.k3s.io | sudo sh -
```

Then run the seed scripts for those areas from `range/k8s/` and `range/containers/` (see the comments at
the top of each script for the exact invocation).

## Cisco config target

No device is needed. Put the seeded running-config file from `range/cisco/` into the inventory as a `cisco`
target with the `file` transport. A real switch or lab device can be added later with the `ssh` transport.

## Windows VM (optional)

Build a Windows VM only if a teammate owns the Windows adapter. Enable WinRM for the lab, create a local
test account, and keep the credentials in an environment variable named in the target's `credential_ref`
(`CT_CRED_<ref>`); never commit them. Snapshot as `clean`, run the seed from `range/windows/`, snapshot as
`seeded`.

## Seed and snapshot

Linux (the script refuses to run unless the hostname starts with `acd-target-`):

```bash
scp range/seed_misconfig.sh acd@<vm-ip>:/tmp/ && ssh -t acd@<vm-ip> 'sudo bash /tmp/seed_misconfig.sh'
```

Then snapshot **`seeded`**. Revert to `seeded` before every rehearsal.

## Low-bandwidth link emulation

`range/link_emulate.sh` shapes a network interface on the Linux VM with `tc` and `netem`, so the STIG delta
transfer is felt, not just computed. Run it on the VM as root:

```bash
sudo bash range/link_emulate.sh on 56 500
```

```bash
sudo bash range/link_emulate.sh status
```

```bash
sudo bash range/link_emulate.sh off
```

Arguments to `on` are rate in kbps and added latency in ms; defaults are 56 and 500. Set the same numbers in
Cyber Thunder (`python -m cyberthunder link set --kbps 56 --latency-ms 500`, or Scans, Link controls) so the sizes and transfer times it reports match
what the wire does. For the simulated mode there is no wire; the numbers in Cyber Thunder are the emulation.

## Scan by hand (what `cyberthunder scan` automates)

```bash
oscap info /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml | grep -A1 -i 'profile'
```

```bash
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig \
  --results /tmp/acd-results.xml --report /tmp/acd-report.html \
  /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml ; echo "exit $?"
```

`oscap` exits 2 when any rule fails; that is normal. If the `stig` profile is missing from the distribution's
content, use the CIS profile for the first day and drop upstream content into
`/usr/share/xml/scap/ssg/content/` later.

## Fix library source

Every rule in the benchmark carries a shell fix; the parser lifts it into the finding and the fix library
holds the vetted subset. Rollback restores the before-state the apply step captured, then rescans.

## First real-host run (from the laptop)

Register the three range assets in a scratch state directory and scan them from the laptop. The scan
account `acd` reaches the VM over SSH with the key `new-range-vm.ps1` installed; no password is on the
wire and none is in the inventory.

```bash
# PowerShell: $env:CT_STATE_DIR="C:\ct\range-state"; $env:CT_ACTOR="IT1 Ott"
export CT_STATE_DIR=/c/ct/range-state
export CT_ACTOR="IT1 Ott"
KEY="C:\Users\joshu\.ssh\ct_range_ed25519"
```

`CT_STATE_DIR` must be an environment variable (not only `--state-dir`): the Kubernetes `node_target`
feature re-reads it from the environment when it opens the server node's SSH transport.

Linux host, SSH with a key file and no password:

```bash
python -m cyberthunder targets add --id acd-target-01 --name acd-target-01 --type linux --transport ssh --address <ip> --username acd --option key_file=$KEY --in-scope --reason "range build"
```

Container host, podman over the same SSH host:

```bash
python -m cyberthunder targets add --id acd-containers --name acd-containers --type containers --transport ssh --address <ip> --username acd --option key_file=$KEY --option engine=podman --option 'allowed_registries=["registry.local","docker.io/library"]' --option 'expected_containers=["web","ops-agent","ops-dashboard","metrics-relay"]' --option 'expected_ports=[443]' --option 'critical_containers=["web"]' --in-scope --reason "range build"
```

k3s cluster, kubeconfig transport; `node_target` reads the control-plane flags over the Linux target's SSH:

```bash
python -m cyberthunder targets add --id acd-k3s --name acd-k3s --type kubernetes --transport kubeconfig --option kubeconfig=C:\ct\kubeconfig-acd-k3s.yaml --option kubectl=C:\Tools\kubectl\kubectl.exe --option node_target=acd-target-01 --option node_name=acd-target-01 --option 'allowed_registries=["registry.local","docker.io/library"]' --in-scope --reason "range build"
```

Copy the kubeconfig off the VM first and point it at the VM address (it is cluster-admin; keep it private):

```bash
scp -i %USERPROFILE%\.ssh\ct_range_ed25519 acd@<ip>:/etc/rancher/k3s/k3s.yaml C:\ct\kubeconfig-acd-k3s.yaml
# then replace 127.0.0.1 with <ip> in that file
```

Scan, score against the answer keys, and take one fix end to end:

`report score` prints seeded vs found per answer key. `apply` captures the before-state, applies and
verifies; `rollback` restores the before-state and rescans; `audit verify` checks the hash chain.

```bash
python -m cyberthunder --actor "IT1 Ott" scan
python -m cyberthunder report score
python -m cyberthunder proposals list
python -m cyberthunder proposals approve <proposal-id>
python -m cyberthunder apply <proposal-id>
python -m cyberthunder diff <proposal-id>
python -m cyberthunder rollback <proposal-id>
python -m cyberthunder audit verify
```

### Results (first real-host run, 2026-11-04)

First scan of a real host, not the in-process simulator: the automated Rocky 9 VM above, seeded with all
three Linux/Kubernetes/container seed scripts, scanned from the laptop over SSH and a kubeconfig.

**Detection.** Every one of the 28 seeded items on the three scanned targets was detected, and the
scoreboard (`report score`) credits all 28. The first run credited only 23; the five-item gap was a
scoring-identifier mismatch, since fixed (detail below), not a detection miss.

| Target | Seeded | Detected | Scoreboard credits |
|---|---|---|---|
| `acd-target-01` (linux) | 12 | 12 | 12 |
| `acd-containers` (podman) | 6 | 6 | 6 |
| `acd-k3s` (kubernetes) | 10 | 10 | 10 |
| **Total** | **28** | **28** | **28 (100%)** |

The full `report score` also lists the cisco, windows and discovery keys as `not_scanned` (33 + 10 + 3
items): those targets were out of scope for this run, so the raw overall figure understates the result.
Scope the score to what was built and it is 28 of 28.

**One fix, end to end on the real host.** Proposal `ssg:file_permissions_etc_shadow` (STIG RHEL-09-232270,
Linux M3): approved as `IT1 Ott`, applied (`/etc/shadow` 0644 -> 0000, before-state captured), verified by
re-check, then rolled back (restored to 0644) and confirmed on the host. `audit verify` reported the chain
intact (hash-linked, checkpoint matches).

**What the adapters got wrong (and what this run fixed).**

- **Kubernetes RBAC check crashed on a real cluster (fixed in this PR).** `check_rbac` and
  `hunt_admin_bindings` raised `invalid object name 'system:controller:bootstrap-signer'` and aborted,
  because `ObjRef` validated namespaced RoleBinding names with the DNS-1123 pattern, which forbids the `:`
  that every real cluster's built-in `system:` bindings carry (the simulator has none, so this never
  surfaced before). The crash hid the seeded `system-monitor-binding` (k8s I1). Fixed by letting namespaced
  `roles`/`rolebindings` use the colon-tolerant RBAC name pattern; k8s I1 is now detected.
- **Answer keys were scoped to simulated targets only (fixed in this PR).** `kubernetes.json` and
  `containers.json` named only `sim-k8s-01` / `sim-docker-01`, so real-range findings scored as
  `not_scanned`. They now carry `target: acd-k3s` / `acd-containers` with the simulated id moved to
  `sim_target`, mirroring `linux.json`. The simulated demo still scores through `sim_target`.
- **Five real detections were not credited by the scoreboard (fixed in this PR).** k8s M2/M3/M5 (apiserver
  `anonymous-auth`, kubelet `read-only-port`, missing audit log) are detected on the node as
  `CNTR-K8-000360/000330/000610` against `-/node/acd-target-01`, but the key's `object` named the simulated
  apiserver/kubelet pod; on k3s the control plane runs in-process, not as a pod (see
  [k8s/README.md](k8s/README.md)). These rules fire once, so the redundant `object` was dropped and the
  `rule` id now credits both the real node finding and the simulated pod. Linux M5/M6 (ctrl-alt-del,
  world-writable dir) are detected by OpenSCAP as `xccdf_org.ssgproject.content_rule_*`, while the simulator
  emits the native `linux:` id; both carry the same `fix_ref` (`ssg:disable_ctrlaltdel_reboot`,
  `ssg:dir_perms_world_writable_system_owned`), so those two items are now matched by `fix_ref` (the key's
  existing detector/fix_ref fallback) instead of a simulator-only `check_id`. The simulated range still
  scores 100% (`tests/report`), so the scoreboard now reads 28/28 on both ranges.

Reproduce: build with `range/vmware/new-range-vm.ps1`, seed per [vmware/README.md](vmware/README.md), then
run the commands above with `CT_STATE_DIR` pointed at a scratch directory.
