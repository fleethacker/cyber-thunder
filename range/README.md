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
