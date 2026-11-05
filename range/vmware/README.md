# Automated Rocky 9 range VM (VMware Workstation)

`new-range-vm.ps1` builds the disposable range host **acd-target-01** end to end without the VMware
GUI: it fills a kickstart, bakes it onto an `OEMDRV` ISO that Anaconda loads automatically, creates the
disk and `.vmx`, drives the unattended install, boots the clean system, checks SSH and passwordless sudo,
and takes the `clean` snapshot. This is the automated version of the by-hand steps in
[../README.md](../README.md). Isolated range only: the NIC is NAT on VMnet8, never bridged.

## Files

| File | What it is |
|---|---|
| `new-range-vm.ps1` | Orchestrator. Writes the vmx, builds the OEMDRV ISO, drives `vmrun`. |
| `ks.cfg` | Kickstart **template**. `@@ACD_PWHASH@@` and `@@SSH_PUBKEY@@` are filled at build time. |
| `build_oemdrv.py` | Builds the `OEMDRV`-labelled ISO holding `ks.cfg` (needs `pip install pycdlib`). |
| `range/.local/range.env` | **Untracked** secrets: the generated `acd` password, its SHA-512 hash, and the SSH key paths. Git-ignored; never committed. |

No ISO, disk, vmx, password or key is committed. Only the three scripts above and this README are.

## Prerequisites

- VMware Workstation (provides `vmrun.exe` and `vmware-vdiskmanager.exe`). Default location
  `C:\Program Files (x86)\VMware\VMware Workstation`; override with `-VmwareDir`.
- A NAT network on **VMnet8** (the Workstation default). The host reaches the guest directly on that
  subnet, which is how the scan, SSH and the k3s API (6443) are reached from the laptop.
- Python 3.11+ on PATH with `pycdlib` (`pip install pycdlib`).
- The Rocky 9 minimal ISO. Default `C:\VM\ISO\rocky9\Rocky-9-latest-x86_64-minimal.iso`; override
  with `-Iso`. Verify its SHA-256 against the mirror's `CHECKSUM` before first use.
- Windows OpenSSH client (`ssh.exe`, built into Windows) for the post-install sudo check.

## Build

```
powershell -ExecutionPolicy Bypass -File range\vmware\new-range-vm.ps1
```

On first run, if `range/.local/range.env` is absent the script generates a 20-character password, hashes
it with `openssl passwd -6`, ensures an `ed25519` key at `%USERPROFILE%\.ssh\ct_range_ed25519`, and writes
`range.env`. It prints the guest IP and leaves the VM on snapshot `clean`.

The VM it creates: guest `rhel9-64`, **EFI** firmware, 2 vCPU, 8 GB RAM, a 40 GB growable NVMe disk, two
SATA optical drives (Rocky ISO + OEMDRV), one `e1000e` NIC on NAT. EFI + NVMe is used because Rocky 9
dropped the legacy LSI-parallel SCSI driver. The kickstart does a minimal install plus
`openscap-scanner scap-security-guide openssh-server python3 tar podman open-vm-tools`, locks root, makes
`acd` a wheel admin with the scan key in `authorized_keys`, and drops in passwordless, terminal-less sudo
for `acd` so `sudo -n` works over SSH.

Useful switches: `-Force` (recreate an existing VM), `-SkipSnapshot`, `-MemoryMB`, `-Cpus`, `-DiskGB`,
`-InstallTimeoutSec`. If the unattended install ever stalls, watch the headless console with
`vmrun -T ws captureScreen <vmx> out.png`.

## After the build: k3s, podman seed, and the `seeded` snapshot

k3s and podman need one online moment (NAT gives it); do this before the event, then snapshot.

```
scp -i %USERPROFILE%\.ssh\ct_range_ed25519 -r range\k8s range\containers range\seed_misconfig.sh acd@<ip>:/tmp/
```

```
ssh -i %USERPROFILE%\.ssh\ct_range_ed25519 acd@<ip> "curl -sfL https://get.k3s.io | sudo INSTALL_K3S_VERSION=v1.30.6+k3s1 sh -s - --write-kubeconfig-mode 0600 && sudo dnf -y install podman"
```

```
ssh -i %USERPROFILE%\.ssh\ct_range_ed25519 acd@<ip> "sudo bash /tmp/seed_misconfig.sh && sudo /tmp/k8s/seed.sh && sudo /tmp/containers/seed.sh"
```

Then snapshot `seeded` and revert to it before every rehearsal:

```
vmrun -T ws snapshot <vmx> seeded
vmrun -T ws revertToSnapshot <vmx> seeded
```

## Registering the targets (scratch state dir)

See [../README.md](../README.md#first-real-host-run-from-the-laptop) for the exact `targets add`,
`scan`, `report score`, `apply`/`rollback` and `audit verify` commands used for the first real-host run.
