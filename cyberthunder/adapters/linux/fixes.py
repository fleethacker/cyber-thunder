"""Vetted Linux remediations.

These FixEntry objects are the only place executable Linux payloads exist. Native STIG fixes mirror the
ComplianceAsCode (SCAP Security Guide) bash remediations for the same rule. Hunt fixes remove or
quarantine one persistence item. Patch entries are runbooks for an offline enclave.

Every payload starts with the line "# cyberthunder-fix: <fix_ref>". The simulated host keys on that header
to apply the same effect to its state, and the adapter refuses a payload whose header does not match the
entry it was given.

Hunt fixes act on one subject (an account, an authorized_keys line, a file, a unit). The subject is never
part of the payload: the adapter validates it against the strict pattern in SUBJECT_PATTERNS, writes it to a
separate argument file, and the payload reads that file as data and validates it again before acting.

before_state keys understood by LinuxAdapter.capture_before_state / rollback:
  files      [paths]                      copied with mode, owner, group and mtime (absent files recorded)
  dirs       [{"dir", "pattern"}]         files matching a glob in a directory, captured like `files`
  commands   {name: command}              read-only command output kept as evidence
  services   [units]                      is-enabled / is-active restored on rollback
  sysctl     [keys]                       runtime value restored on rollback
  selinux    true                         runtime SELinux mode restored on rollback
  path_modes command                      prints "<mode> <path>" lines; modes are restored on rollback
  path_root  dir                          rollback only restores path_modes entries at or under this dir
  packages   [names]                      reinstalled (same NEVRA) from the enclave mirror on rollback if they
                                          were present; a package dnf removed as a dependent is not captured
  subject    user | key | path | unit     what the hunt fix acts on (adds that file / unit to the capture; a
                                          unit's enabled/active state is captured and restored too)
  quarantine true                         the payload moves the subject to QUARANTINE_DIR; rollback removes the copy
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from cyberthunder.remediation.library import FixEntry

from . import rules

QUARANTINE_DIR = "/var/quarantine/cyberthunder"
HEADER = "# cyberthunder-fix: "

SUBJECT_PATTERNS = {
    "user": re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$"),
    "key": re.compile(r"^/(root|home/[A-Za-z0-9._-]+)/\.ssh/authorized_keys\|[A-Za-z0-9+/]+=*$"),
    "path": re.compile(r"^/[A-Za-z0-9._/@+-]+$"),
    "unit": re.compile(r"^[A-Za-z0-9@._-]+\.service$"),
}
PROTECTED_PATHS = {"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers", "/etc/crontab",
                   "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/bash", "/usr/bin/sh"}


def quarantine_path(path: str) -> str:
    return f"{QUARANTINE_DIR}/{path.lstrip('/').replace('/', '_')}"


def valid_subject(kind: str, value: str, allow: tuple[str, ...] = ()) -> bool:
    """Same checks the payloads make in bash, so a bad subject is refused before anything is sent."""
    rx = SUBJECT_PATTERNS.get(kind)
    if not rx or not value or not rx.match(value):
        return False
    if kind == "user" and value == "root":
        return False
    if kind == "path":
        if ".." in value or value in PROTECTED_PATHS:
            return False
        if allow and not value.startswith(allow):
            return False
    return True


# ---------------------------------------------------------------------------------------------
# Native STIG rules and their fixes (one table drives checks, fixes and the simulated host)
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class NativeRule:
    rule_id: str                    # STIG ID when one is confirmed, otherwise linux:<name>
    family: str
    params: dict = field(default_factory=dict, hash=False, compare=False)
    stig_id: str | None = None
    ssg: str | None = None          # ComplianceAsCode rule name (fix_ref is ssg:<name>)
    title: str = ""                 # used when there is no STIG title
    severity: str = "medium"
    refs: tuple[str, ...] = ()      # citations when there is no STIG ID (CCIs)
    description: str = ""
    disruption: str = "low"
    restarts: tuple[str, ...] = ()
    reboot: bool = False

    @property
    def fix_ref(self) -> str:
        return f"ssg:{self.ssg or self.rule_id}"


def _stig(stig_id: str, family: str, params: dict, **kw) -> NativeRule:
    meta = rules.rule(stig_id)
    return NativeRule(rule_id=stig_id, stig_id=stig_id, family=family, params=params,
                      ssg=kw.pop("ssg", None) or meta.get("ssg_rule"), title=meta.get("title", stig_id),
                      severity=meta.get("severity", "medium"), **kw)


NATIVE: list[NativeRule] = [
    _stig("RHEL-09-255045", "sshd", {"keyword": "PermitRootLogin", "value": "no"}, restarts=("sshd",)),
    _stig("RHEL-09-255040", "sshd", {"keyword": "PermitEmptyPasswords", "value": "no"}, restarts=("sshd",)),
    _stig("RHEL-09-255050", "sshd", {"keyword": "UsePAM", "value": "yes"}, restarts=("sshd",)),
    _stig("RHEL-09-255155", "sshd", {"keyword": "X11Forwarding", "value": "no"}, restarts=("sshd",)),
    _stig("RHEL-09-255080", "sshd", {"keyword": "HostbasedAuthentication", "value": "no"}, restarts=("sshd",)),
    _stig("RHEL-09-232270", "file_mode", {"path": "/etc/shadow", "mode": "0000"}),
    _stig("RHEL-09-232150", "file_owner", {"path": "/etc/shadow", "owner": "root"}),
    _stig("RHEL-09-232075", "file_mode", {"path": "/etc/passwd", "mode": "0644"}),
    _stig("RHEL-09-232055", "file_mode", {"path": "/etc/group", "mode": "0644"}),
    _stig("RHEL-09-232065", "file_mode", {"path": "/etc/gshadow", "mode": "0000"}),
    _stig("RHEL-09-255110", "file_owner", {"path": "/etc/ssh/sshd_config", "owner": "root"}),
    _stig("RHEL-09-251015", "service_on", {"unit": "firewalld.service"}, disruption="medium",
          restarts=("firewalld",)),
    _stig("RHEL-09-653015", "service_on", {"unit": "auditd.service"}, restarts=("auditd",)),
    NativeRule("linux:disable_ctrlaltdel_reboot", "unit_mask", {"unit": "ctrl-alt-del.target"},
               ssg="disable_ctrlaltdel_reboot", severity="high", refs=("CCI-000366",),
               title="The x86 Ctrl-Alt-Delete key sequence must be disabled (ctrl-alt-del.target masked).",
               description="The STIG ID for masking ctrl-alt-del.target is not in the confirmed rule file, so this "
                           "check cites CCI-000366. RHEL-09-211045 (burst action) is the related confirmed rule."),
    _stig("RHEL-09-431010", "selinux", {}, disruption="medium"),
    _stig("RHEL-09-215040", "pkg_remove", {"package": "telnet-server"}),
    NativeRule("linux:package_rsh-server_removed", "pkg_remove", {"package": "rsh-server"},
               ssg="package_rsh-server_removed", severity="high", refs=("CCI-000381",),
               title="The rsh-server package must not be installed.",
               description="No confirmed RHEL 9 STIG ID for rsh-server is in the rule file, so this check cites "
                           "CCI-000381 (prohibited functions, ports, protocols and services)."),
    _stig("RHEL-09-411010", "login_defs", {"key": "PASS_MAX_DAYS", "value": "60"}),
    _stig("RHEL-09-213070", "sysctl", {"key": "kernel.randomize_va_space", "value": "2"}),
    _stig("RHEL-09-214025", "gpgcheck", {}),
    _stig("RHEL-09-213090", "coredump", {}),
    _stig("RHEL-09-411030", "runbook_dup_uid", {}),
    NativeRule("linux:dir_perms_world_writable_system_owned", "ww_dirs", {"root": "/var/log"},
               ssg="dir_perms_world_writable_system_owned", refs=("CCI-000366",),
               title="System log directories must not be world-writable.",
               description="No confirmed STIG ID for world-writable directories under /var/log is in the rule "
                           "file, so this check cites CCI-000366."),
    NativeRule("linux:sudo_remove_nopasswd", "sudo_nopasswd", {}, ssg="sudo_remove_nopasswd",
               refs=("CCI-002038",),
               title="sudo must require reauthentication: no NOPASSWD rules.",
               description="No confirmed RHEL 9 STIG ID for NOPASSWD is in the rule file, so this check cites "
                           "CCI-002038 (reauthentication for privilege escalation)."),
]
NATIVE_BY_ID = {r.rule_id: r for r in NATIVE}


def _sshd_payload(r: NativeRule) -> str:
    k, v = r.params["keyword"], r.params["value"]
    return f"""{HEADER}{r.fix_ref}
# {r.rule_id}: set {k} {v}. sshd uses the first value it reads, so the setting goes on line 1,
# ahead of the Include of sshd_config.d and any Match block.
set -euo pipefail
conf=/etc/ssh/sshd_config
LC_ALL=C sed -i '/^[[:space:]]*{k}[[:space:]]/Id' "$conf"
sed -i '1i {k} {v}' "$conf"
sshd -t
systemctl reload sshd
"""


def _native_payload(r: NativeRule) -> str:
    f, p, h = r.family, r.params, f"{HEADER}{r.fix_ref}\n# {r.rule_id}\nset -euo pipefail\n"
    if f == "sshd":
        return _sshd_payload(r)
    if f == "file_mode":
        return h + f"chmod {p['mode']} {p['path']}\n"
    if f == "file_owner":
        return h + f"chown {p['owner']} {p['path']}\n"
    if f == "service_on":
        u = p["unit"]
        return h + f"systemctl unmask {u}\nsystemctl enable --now {u}\nsystemctl is-active {u}\n"
    if f == "unit_mask":
        u = p["unit"]
        return h + f"systemctl disable --now {u} || true\nsystemctl mask --now {u}\n"
    if f == "selinux":
        return h + ("sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config\n"
                    "grep -q '^SELINUX=' /etc/selinux/config || echo 'SELINUX=enforcing' >> /etc/selinux/config\n"
                    "# setenforce fails when SELinux was disabled at boot; the config change then applies at next boot\n"
                    "setenforce 1 || echo 'SELinux disabled at boot: reboot required to enforce'\n")
    if f == "pkg_remove":
        return h + f"if rpm -q {p['package']} >/dev/null 2>&1; then dnf -y remove {p['package']}; fi\n"
    if f == "login_defs":
        k, v = p["key"], p["value"]
        return h + (f"if grep -q '^[[:space:]]*{k}' /etc/login.defs; then\n"
                    f"  sed -i 's/^[[:space:]]*{k}.*/{k} {v}/' /etc/login.defs\n"
                    f"else\n  echo '{k} {v}' >> /etc/login.defs\nfi\n")
    if f == "sysctl":
        k, v = p["key"], p["value"]
        return h + (f"sed -i '/^[[:space:]]*{re.escape(k)}[[:space:]]*=/d' /etc/sysctl.conf\n"
                    f"echo '{k} = {v}' >> /etc/sysctl.conf\n"
                    f"sysctl -q -w {k}={v}\n")
    if f == "gpgcheck":
        return h + ("sed -i 's/^[[:space:]]*gpgcheck[[:space:]]*=.*/gpgcheck=1/' /etc/dnf/dnf.conf\n"
                    "grep -q '^gpgcheck=' /etc/dnf/dnf.conf || sed -i '/^\\[main\\]/a gpgcheck=1' /etc/dnf/dnf.conf\n"
                    "for f in /etc/yum.repos.d/*.repo; do\n"
                    "  [ -f \"$f\" ] && sed -i 's/^[[:space:]]*gpgcheck[[:space:]]*=.*/gpgcheck=1/' \"$f\"\n"
                    "done\n")
    if f == "coredump":
        return h + ("f=/etc/systemd/coredump.conf\n"
                    "if grep -q '^[[:space:]]*Storage=' \"$f\"; then\n"
                    "  sed -i 's/^[[:space:]]*Storage=.*/Storage=none/' \"$f\"\n"
                    "else\n"
                    "  grep -q '^\\[Coredump\\]' \"$f\" || echo '[Coredump]' >> \"$f\"\n"
                    "  echo 'Storage=none' >> \"$f\"\nfi\n")
    if f == "ww_dirs":
        return h + f"find {p['root']} -xdev -type d -perm -0002 -exec chmod o-w {{}} +\n"
    if f == "sudo_nopasswd":
        return h + ("for f in /etc/sudoers /etc/sudoers.d/*; do\n"
                    "  [ -f \"$f\" ] && sed -i 's/NOPASSWD[[:space:]]*://g' \"$f\"\n"
                    "done\nvisudo -c\n")
    raise ValueError(f"no payload for family {f}")


def _native_before(r: NativeRule) -> dict:
    f, p = r.family, r.params
    if f == "sshd":
        return {"files": ["/etc/ssh/sshd_config"], "commands": {"sshd_effective": "sshd -T"}}
    if f in ("file_mode", "file_owner"):
        return {"files": [p["path"]], "commands": {"stat": f"stat -c '%a %U %G %n' {p['path']}"}}
    if f in ("service_on", "unit_mask"):
        return {"services": [p["unit"]]}
    if f == "selinux":
        return {"files": ["/etc/selinux/config"], "selinux": True, "commands": {"getenforce": "getenforce"}}
    if f == "pkg_remove":
        return {"packages": [p["package"]], "commands": {"rpm_q": f"rpm -q {p['package']}"}}
    if f == "login_defs":
        return {"files": ["/etc/login.defs"]}
    if f == "sysctl":
        return {"files": ["/etc/sysctl.conf"], "sysctl": [p["key"]]}
    if f == "gpgcheck":
        return {"files": ["/etc/dnf/dnf.conf"], "dirs": [{"dir": "/etc/yum.repos.d", "pattern": "*.repo"}]}
    if f == "coredump":
        return {"files": ["/etc/systemd/coredump.conf"]}
    if f == "ww_dirs":
        return {"path_modes": f"find {p['root']} -xdev -type d -perm -0002 -printf '%m %p\\n'",
                "path_root": p["root"]}
    if f == "sudo_nopasswd":
        return {"files": ["/etc/sudoers"], "dirs": [{"dir": "/etc/sudoers.d", "pattern": "*"}]}
    return {}


def _native_entry(r: NativeRule) -> FixEntry:
    meta = rules.rule(r.stig_id)
    cites = [x for x in (r.stig_id, meta.get("group_id"), *meta.get("cci", []), *r.refs) if x]
    applies = [r.rule_id] + ([rules.SSG_PREFIX + r.ssg] if r.ssg else [])
    if r.family == "runbook_dup_uid":
        return FixEntry(
            fix_ref=r.fix_ref, title=f"Give every account a unique UID ({r.rule_id})", asset_type="linux",
            applies_to=applies, kind="runbook", source="ssg", citations=cites, reversible=True,
            rollback_kind="manual", disruption="medium",
            steps=["List duplicates: awk -F: '{print $3}' /etc/passwd | sort | uniq -d",
                   "For each duplicate, confirm with the system owner which account is legitimate.",
                   "A second UID 0 account is an intrusion indicator: use the hunt fix 'hunt:linux:remove_account' "
                   "instead of renumbering it.",
                   "For other duplicates: usermod -u <new uid> <account>, then find / -xdev -uid <old uid> to re-own files.",
                   "Rescan to confirm."],
            rollback_steps=["usermod -u <old uid> <account> and re-own the same files."],
            verify={"rule_ids": [r.rule_id]})
    before = _native_before(r)
    restarts = list(r.restarts)
    return FixEntry(
        fix_ref=r.fix_ref, title=f"{r.title} ({r.rule_id})" if r.stig_id else r.title, asset_type="linux",
        applies_to=applies, kind="script", payload=_native_payload(r), disruption=r.disruption, reboot=r.reboot,
        restarts_services=restarts, reversible=True,
        rollback_kind="command" if r.family in ("service_on", "unit_mask", "pkg_remove", "ww_dirs") else "restore_files",
        before_state=before, verify={"rule_ids": [r.rule_id]}, citations=cites, source="ssg",
        notes=meta.get("fix_summary", r.description))


# ---------------------------------------------------------------------------------------------
# Hunt remediations
# ---------------------------------------------------------------------------------------------
_READ_ARG = 'arg=$(head -n 1 -- "$1")\n'
_REFUSE = 'refuse() { echo "refusing: $*" >&2; exit 2; }\n'


def _hunt_payload(ref: str, body: str) -> str:
    return f"{HEADER}{ref}\nset -euo pipefail\n{_REFUSE}[ -n \"${{1:-}}\" ] || refuse 'no subject file'\n{_READ_ARG}{body}"


_QUARANTINE = (f'q={QUARANTINE_DIR}\n'
               'install -d -m 0700 "$q"\n'
               'dest="$q/$(printf \'%s\' "${arg#/}" | tr \'/\' \'_\')"\n'
               'mv -f -- "$arg" "$dest"\n'
               'chmod 000 "$dest"\n'
               'echo "quarantined $arg -> $dest"\n')


def _path_guard(allow: tuple[str, ...]) -> str:
    g = ('[[ "$arg" =~ ^/[A-Za-z0-9._/@+-]+$ && "$arg" != *..* ]] || refuse "bad path"\n'
         'case "$arg" in ' + "|".join(sorted(PROTECTED_PATHS)) + ') refuse "protected path $arg";; esac\n')
    if allow:
        g += 'case "$arg" in ' + "|".join(a + "*" for a in allow) + ') ;; *) refuse "path outside allowed dirs";; esac\n'
    return g + '[ -e "$arg" ] || { echo "already gone: $arg"; exit 0; }\n'


HUNT_SPECS: dict[str, dict] = {
    "hunt:linux:remove_account": {
        "title": "Remove an unauthorized local account (passwd, shadow, group membership)",
        "subject": "user", "citations": ["T1136.001", "T1078.003"], "disruption": "low",
        "files": ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"],
        "body": ('[[ "$arg" =~ ^[a-z_][a-z0-9_.-]{0,31}$ ]] || refuse "bad account name"\n'
                 '[ "$arg" != root ] || refuse "root"\n'
                 'grep -q "^${arg}:" /etc/passwd || { echo "no such account: $arg"; exit 0; }\n'
                 'gid=$(awk -F: -v u="$arg" \'$1==u{print $4}\' /etc/passwd)\n'
                 '# drop supplementary group memberships first (gpasswd keeps gshadow in step)\n'
                 'for g in $(awk -F: -v u="$arg" \'{n=split($4,m,","); for(i=1;i<=n;i++) if(m[i]==u) print $1}\' /etc/group); do\n'
                 '  gpasswd -d "$arg" "$g" >/dev/null\n'
                 'done\n'
                 '# userdel is not used: a duplicate UID 0 account shares processes and possibly a home with root\n'
                 'sed -i "/^${arg}:/d" /etc/passwd /etc/shadow\n'
                 '# private group of the same name, only if nobody else uses it as primary group\n'
                 'if awk -F: -v u="$arg" -v g="$gid" \'$1==u && $3==g{f=1} END{exit !f}\' /etc/group \\\n'
                 '   && ! awk -F: -v g="$gid" \'$4==g{f=1} END{exit !f}\' /etc/passwd; then\n'
                 '  sed -i "/^${arg}:/d" /etc/group /etc/gshadow\n'
                 'fi\n'
                 'pwck -r -q >/dev/null 2>&1 || true\n'
                 'echo "removed account $arg"\n')},
    "hunt:linux:lock_account": {
        "title": "Lock an account that has an empty password",
        "subject": "user", "citations": ["T1078"], "disruption": "low", "files": ["/etc/shadow"],
        "body": ('[[ "$arg" =~ ^[a-z_][a-z0-9_.-]{0,31}$ ]] || refuse "bad account name"\n'
                 'usermod -L "$arg"\necho "locked $arg"\n')},
    "hunt:linux:remove_authorized_key": {
        "title": "Remove an unknown SSH key from authorized_keys",
        "subject": "key", "citations": ["T1098.004"], "disruption": "low",
        "body": ('file=${arg%%|*}; blob=${arg#*|}\n'
                 '[[ "$file" =~ ^/(root|home/[A-Za-z0-9._-]+)/\\.ssh/authorized_keys$ ]] || refuse "bad file"\n'
                 '[[ "$blob" =~ ^[A-Za-z0-9+/]+=*$ ]] || refuse "bad key"\n'
                 'tmp=$(mktemp "${file}.XXXXXX")\n'
                 'grep -vF -- "$blob" "$file" > "$tmp" || true\n'
                 '# cat keeps the original file mode, owner and SELinux label\n'
                 'cat "$tmp" > "$file"\nrm -f "$tmp"\necho "removed key from $file"\n')},
    "hunt:linux:remove_cron_file": {
        "title": "Quarantine a malicious cron file",
        "subject": "path", "allow": ("/etc/cron.d/", "/var/spool/cron/"), "quarantine": True,
        "citations": ["T1053.003"], "disruption": "low",
        "body": _QUARANTINE},
    "hunt:linux:remove_sudoers_dropin": {
        "title": "Quarantine a sudoers drop-in that grants NOPASSWD",
        "subject": "path", "allow": ("/etc/sudoers.d/",), "quarantine": True,
        "citations": ["T1548.003"], "disruption": "low",
        "body": _QUARANTINE + "visudo -c\n"},
    "hunt:linux:quarantine_file": {
        "title": "Quarantine a suspicious file (move to quarantine, mode 000)",
        "subject": "path", "quarantine": True, "citations": ["T1548.001", "T1070.006"], "disruption": "low",
        "body": _QUARANTINE},
    "hunt:linux:disable_unit": {
        "title": "Stop, disable and mask a rogue systemd service (unit file kept in quarantine)",
        # stops a running service: medium, and named as a service change so standing approval excludes it
        "subject": "unit", "quarantine": True, "citations": ["T1543.002", "T1571"], "disruption": "medium",
        "restarts": ["(the flagged unit)"],
        "body": ('[[ "$arg" =~ ^[A-Za-z0-9@._-]+\\.service$ ]] || refuse "bad unit name"\n'
                 'f=/etc/systemd/system/$arg\n'
                 '[ -f "$f" ] && [ ! -L "$f" ] || refuse "$f is not a local unit file"\n'
                 'systemctl disable --now "$arg"\n'
                 f'q={QUARANTINE_DIR}\ninstall -d -m 0700 "$q"\n'
                 'dest="$q/etc_systemd_system_$arg"\n'
                 'mv -f -- "$f" "$dest"\nchmod 000 "$dest"\n'
                 'systemctl daemon-reload\n'
                 'systemctl mask "$arg"\n'
                 'echo "disabled and masked $arg; unit file kept at $dest"\n')},
}

HUNT_RUNBOOKS: dict[str, dict] = {
    "hunt:linux:manual_review": {
        "title": "Preserve and review a suspicious artifact (manual)",
        "citations": ["T1564.001"],
        "steps": ["Do not delete anything yet: copy the item to removable media for the incident record "
                  "(tar --xattrs -czf /root/ir-<host>-<date>.tgz <path>; sha256sum the archive).",
                  "Record owner, mode, mtime and ctime (stat <path>) and which process or account created it "
                  "(ausearch -f <path> if auditd is running).",
                  "Report to the ISSM / cyber watch with the finding ID and the hash.",
                  "Remove the item only after the related hunt findings are fixed and the ISSM agrees.",
                  "Rescan the host."]},
    "hunt:linux:block_source": {
        "title": "Contain a brute-force source (manual)",
        "citations": ["T1110"],
        "steps": ["Confirm the source address is not a legitimate management host.",
                  "Block it: firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=<ip> drop' "
                  "&& firewall-cmd --reload",
                  "Check whether any login from that address succeeded: grep '<ip>' /var/log/secure | grep Accepted",
                  "If one did, treat the account as compromised: lock it (usermod -L) and report.",
                  "Rescan the host."]},
}


def _hunt_entries() -> list[FixEntry]:
    out = []
    for ref, s in HUNT_SPECS.items():
        before: dict = {"subject": s["subject"], "files": list(s.get("files", []))}
        if s.get("quarantine"):
            before["quarantine"] = True
        if s.get("allow"):
            before["allow"] = list(s["allow"])
        out.append(FixEntry(
            fix_ref=ref, title=s["title"], asset_type="linux", applies_to=[ref], kind="script",
            payload=_hunt_payload(ref, _path_guard(tuple(s.get("allow", ()))) + s["body"]
                                  if s["subject"] == "path" else s["body"]),
            disruption=s["disruption"], restarts_services=list(s.get("restarts", [])), reversible=True,
            rollback_kind="restore_files", before_state=before,
            verify={"rule_ids": [ref], "subject": s["subject"]}, citations=s["citations"], source="hunt",
            notes="Acts on the one subject named by the finding; the subject is validated and passed as data."))
    for ref, s in HUNT_RUNBOOKS.items():
        out.append(FixEntry(fix_ref=ref, title=s["title"], asset_type="linux", applies_to=[ref], kind="runbook",
                            steps=s["steps"], reversible=True, rollback_kind="manual",
                            rollback_steps=["Nothing to roll back: these steps only preserve evidence and block."],
                            citations=s["citations"], source="hunt"))
    return out


# ---------------------------------------------------------------------------------------------
# Patch runbooks (CVE findings carry fix_ref patch:<package>)
# ---------------------------------------------------------------------------------------------
PATCH_PACKAGES = ("openssh", "openssh-server", "openssh-clients", "openssl", "openssl-libs", "glibc", "sudo", "bash",
                  "kernel", "kernel-core", "curl", "libcurl", "xz", "xz-libs", "systemd", "polkit", "python3",
                  "python3-libs", "rsync", "expat", "libxml2", "zlib", "krb5-libs", "nss", "gnutls", "less",
                  "vim-minimal", "cups", "bind-libs", "httpd", "nginx", "samba", "git", "perl", "libssh")
_REBOOT = {"kernel", "kernel-core", "glibc", "systemd"}
_SERVICES = {"openssh": ["sshd"], "openssh-server": ["sshd"], "httpd": ["httpd"], "nginx": ["nginx"],
             "samba": ["smb"], "cups": ["cups"]}
_PKG_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$")


def patch_entry(pkg: str) -> FixEntry:
    if not _PKG_RX.match(pkg):
        raise ValueError(f"bad package name {pkg!r}")
    reboot = pkg in _REBOOT
    return FixEntry(
        fix_ref=f"patch:{pkg}", title=f"Update {pkg} from the enclave package mirror", asset_type="linux",
        applies_to=[f"patch:{pkg}"], kind="runbook", patch=True, reboot=reboot,
        restarts_services=_SERVICES.get(pkg, []), disruption="high" if reboot else "medium",
        reversible=True, rollback_kind="snapshot", source="patch",
        steps=[f"Stage the fixed {pkg} RPM (and the dependencies dnf reports) on the enclave mirror from the "
               "media delivered over the link; check signatures with rpm -K <file>.rpm.",
               "Take a VM snapshot (or LVM snapshot) of the host and record the current version: rpm -q " + pkg,
               f"Install from the local mirror only: dnf --disablerepo='*' --enablerepo=<enclave-mirror> update {pkg}",
               ("Reboot in the approved maintenance window." if reboot else
                f"Restart dependent services ({', '.join(_SERVICES.get(pkg, [])) or 'none listed'}) or check with "
                "needs-restarting -s."),
               f"Verify: rpm -q {pkg} reports the fixed version or later, then rescan the host."],
        rollback_steps=["dnf history undo last (same mirror), or revert to the snapshot taken before the change.",
                        f"Confirm with rpm -q {pkg} and rescan."],
        verify={"rule_ids": []}, notes="Patch-class change: never eligible for standing approval.")


def all_fixes() -> list[FixEntry]:
    entries = [_native_entry(r) for r in NATIVE]
    entries.extend(_hunt_entries())
    entries.extend(patch_entry(p) for p in PATCH_PACKAGES)
    return entries


def fix_header_ref(payload: str) -> str | None:
    first = (payload or "").splitlines()[0] if payload else ""
    return first[len(HEADER):].strip() if first.startswith(HEADER) else None
