# Local range: `acd-target-01` (Rocky Linux 9, VMware Workstation)

Use this until the event range is reachable; keep it as the fallback for the demo.

## Build (one time, ~25 min)

1. Download `Rocky-9-latest-x86_64-minimal.iso` from https://rockylinux.org/download
2. VMware Workstation → New VM → Typical → ISO → Linux / RHEL 9 64-bit
   - Name `acd-target-01`, 2 vCPU, 4 GB RAM, 40 GB disk, **NAT** network
3. Install: Minimal, hostname `acd-target-01`, root password set, user `acd` (administrator = sudo), enable network.
4. First boot, as `acd`:

```bash
sudo dnf install -y openscap-scanner scap-security-guide openssh-server python3 tar
sudo systemctl enable --now sshd
ip -4 addr show | grep inet
```

5. From the laptop, copy your SSH key and confirm sudo works without a TTY:

```bash
ssh-copy-id acd@<vm-ip>
ssh acd@<vm-ip> 'sudo -n true && echo SUDO_OK'
```

6. VMware → Snapshot → **`clean`**.

## Seed misconfigurations and the hidden intrusion

```bash
scp range/seed_misconfig.sh acd@<vm-ip>:/tmp/ && ssh -t acd@<vm-ip> 'sudo bash /tmp/seed_misconfig.sh'
```

Then VMware → Snapshot → **`seeded`**. Reset to `seeded` before every rehearsal.
What was seeded, and what should catch it, is in `answer_key.json` (detection-rate scoring).

## Scan by hand (what `acd scan` automates)

```bash
oscap info /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml | grep -A1 -i 'profile'
```

```bash
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig \
  --results /tmp/acd-results.xml --report /tmp/acd-report.html \
  /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml ; echo "exit $?"
```

(`oscap` exits 2 when any rule fails; that is normal.) Pull and parse:

```bash
scp acd@<vm-ip>:/tmp/acd-results.xml state/raw/ && python -m acd parse state/raw/acd-results.xml --out state/findings.json
```

If the `stig` profile is missing from the Rocky content, use `xccdf_org.ssgproject.content_profile_cis` for Day 1 and
drop the upstream `ssg-rhel9-ds.xml` (ComplianceAsCode release zip) into `/usr/share/xml/scap/ssg/content/` later.

## Fix library source

Every rule in the SSG datastream carries `<fix system="urn:xccdf:fix:script:sh">`; `acd parse` already lifts it into
`Finding.fix_script`. That is the vetted remediation library. Rollback = restore the before-state tarball the apply step
captures, then rescan.
