"""Intrusion and persistence hunt for Linux hosts.

Each check reads collected output only and emits one open Finding per suspicious item:
  source "hunt", rule_id "hunt:linux:<check>:<subject>", tag "check:hunt:linux:<check>",
  tag "subject:<value>" (what the matching hunt fix acts on), ATT&CK citations, evidence, fix_ref.

Per-target tuning comes from Target.options:
  expected_ports          [22]   listening ports that are normal on this host (loopback is ignored)
  known_users             []     accounts that are expected; when empty the new-account check is skipped
  known_keys              []     authorized_keys entries that are expected (full line, blob, comment or SHA256 fingerprint)
  admin_users             ["root"]  accounts allowed to hold NOPASSWD in sudoers drop-ins
  suid_baseline           []     extra SUID/SGID paths that are normal on this host
  failed_login_threshold  10     failed logins from one source that count as a burst
"""
from __future__ import annotations

import re
from typing import Callable

from cyberthunder.adapters.base import Collected, make_finding
from cyberthunder.findings.schema import Finding

from . import parse as P

PREFIX = "hunt:linux:"
YEAR_S = 365 * 24 * 3600

SUID_BASELINE = {
    "/usr/bin/chage", "/usr/bin/gpasswd", "/usr/bin/newgrp", "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/su",
    "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/pkexec", "/usr/bin/crontab", "/usr/bin/chfn", "/usr/bin/chsh",
    "/usr/bin/at", "/usr/bin/fusermount", "/usr/bin/fusermount3", "/usr/bin/write", "/usr/bin/locate",
    "/usr/bin/ssh-agent", "/usr/sbin/unix_chkpwd", "/usr/sbin/pam_timestamp_check", "/usr/sbin/userhelper",
    "/usr/sbin/grub2-set-bootflag", "/usr/sbin/mount.nfs", "/usr/sbin/lockdev", "/usr/sbin/netreport",
    "/usr/libexec/dbus-1/dbus-daemon-launch-helper", "/usr/libexec/openssh/ssh-keysign",
    "/usr/libexec/utempter/utempter", "/usr/libexec/polkit-1/polkit-agent-helper-1",
    "/usr/lib/polkit-1/polkit-agent-helper-1", "/usr/libexec/sssd/krb5_child", "/usr/libexec/sssd/ldap_child",
    "/usr/libexec/sssd/proxy_child", "/usr/libexec/sssd/selinux_child", "/usr/libexec/cockpit-session",
    "/usr/bin/staprun", "/usr/sbin/usernetctl",
}
REFERENCE_SHELLS = ("/usr/bin/bash", "/usr/bin/sh", "/usr/bin/dash", "/usr/bin/zsh", "/usr/bin/python3",
                    "/usr/bin/perl", "/usr/libexec/platform-python")
SUSPICIOUS_CMD = re.compile(r"(/\.[^/\s]+|/tmp/|/var/tmp/|/dev/shm|\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bsocat\b|"
                            r"/dev/tcp/|/dev/udp/|base64\s+-d)")
# a shell must be a command word (bare or after a "/"), so a "start.sh" wrapper does not match
SUSPICIOUS_EXEC = re.compile(r"((?:^|[\s/])(?:ba|z|da)?sh(?=\s|$)(\s+-c)?|\bnc\b|\bncat\b|\bsocat\b|python[0-9.]*\s+-m\s+http\.server|"
                             r"python[0-9.]*\s+-c|/\.[^/\s]+|/tmp/|/var/tmp/|/dev/shm)")
FAILED_RX = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
HIDDEN_DIR_ROOTS = ("/usr/local/lib/", "/var/tmp/", "/dev/shm/")


def _opt(target, name, default):
    v = (target.options or {}).get(name)
    return default if v is None else v


def _finding(target, c: Collected, check: str, subject: str, *, title: str, severity: str, techniques: list[str],
             evidence: str, fix_ref: str | None, description: str, fix_arg: str | None = None,
             tags: tuple[str, ...] = ()) -> Finding:
    return make_finding(
        target=target, source="hunt", rule_id=f"{PREFIX}{check}:{subject}", title=title, severity=severity,
        description=description, evidence=evidence, references=techniques, fix_ref=fix_ref,
        tags=["hunt", f"check:{PREFIX}{check}", f"subject:{fix_arg if fix_arg is not None else subject}", *tags],
        collected_at=c.collected_at)


# -- accounts -----------------------------------------------------------------------------------
def uid0_duplicate(target, c):
    out = []
    for u in P.passwd(P.out(c, "passwd") or ""):
        if u["uid"] == 0 and u["name"] != "root":
            out.append(_finding(
                target, c, "uid0_duplicate", u["name"], title=f"Second UID 0 account: {u['name']}", severity="high",
                techniques=["T1136.001", "T1078.003"], fix_ref="hunt:linux:remove_account",
                evidence=f"/etc/passwd: {u['name']}:x:0:{u['gid']}:{u['gecos']}:{u['home']}:{u['shell']}",
                description="An account other than root has UID 0, so it has full root privileges under another "
                            "name. This is a common way to keep root access after an intrusion (ATT&CK T1136.001 "
                            "create local account, T1078.003 valid local accounts)."))
    return out


def empty_password(target, c):
    out = []
    for s in P.shadow(P.out(c, "shadow") or ""):
        if s["hash"] == "":
            out.append(_finding(
                target, c, "empty_password", s["name"], title=f"Account with an empty password: {s['name']}",
                severity="high", techniques=["T1078"], fix_ref="hunt:linux:lock_account",
                evidence=f"/etc/shadow: {s['name']} has an empty password field",
                description="Anyone can log in as this account without a password where PAM or sshd allows "
                            "empty passwords (ATT&CK T1078 valid accounts)."))
    return out


def unknown_user(target, c):
    known = set(_opt(target, "known_users", []))
    if not known:
        return []
    out = []
    for u in P.passwd(P.out(c, "passwd") or ""):
        interactive = u["shell"] not in P.NOLOGIN_SHELLS
        if interactive and (u["uid"] == 0 or u["uid"] >= 1000) and u["name"] not in known:
            out.append(_finding(
                target, c, "unknown_user", u["name"], title=f"Account not in the known-user list: {u['name']}",
                severity="medium", techniques=["T1136.001"], fix_ref="hunt:linux:remove_account",
                evidence=f"/etc/passwd: {u['name']} uid {u['uid']} shell {u['shell']} home {u['home']}",
                description="An interactive account exists that the system owner has not listed as expected. "
                            "Confirm it with the ISSO before removal (ATT&CK T1136.001 create local account)."))
    return out


# -- ssh keys -----------------------------------------------------------------------------------
def unknown_authorized_key(target, c):
    known = set(_opt(target, "known_keys", []))
    out = []
    for path, content in P.dump(P.out(c, "authkeys") or "").items():
        for line in content.splitlines():
            k = P.authorized_key(line)
            if not k:
                continue
            # the comment is free text whoever adds the key writes, so it never identifies a known key
            if known & {line.strip(), k["blob"], k["fingerprint"]}:
                continue
            out.append(_finding(
                target, c, "unknown_authorized_key", f"{path}:{k['fingerprint']}",
                title=f"Unknown SSH key in {path} ({k['comment'] or 'no comment'})", severity="high",
                techniques=["T1098.004"], fix_ref="hunt:linux:remove_authorized_key",
                fix_arg=f"{path}|{k['blob']}",
                evidence=f"{path}: {k['type']} {k['fingerprint']} {k['comment']}".strip(),
                description="An SSH public key that is not on the host's known-key list lets its holder log in "
                            "without a password (ATT&CK T1098.004 SSH authorized keys)."))
    return out


# -- persistence --------------------------------------------------------------------------------
def cron_suspicious(target, c):
    out = []
    for path, content in P.dump(P.out(c, "cron") or "").items():
        hits = []
        for line in content.splitlines():
            s = line.strip()
            if s and not s.startswith("#") and SUSPICIOUS_CMD.search(s):
                hits.append(s)
        hidden_name = path.rsplit("/", 1)[-1].startswith(".")
        if not hits and not hidden_name:
            continue
        removable = path.startswith(("/etc/cron.d/", "/var/spool/cron/"))
        out.append(_finding(
            target, c, "cron_suspicious", path, title=f"Suspicious cron entry in {path}", severity="high",
            techniques=["T1053.003"], fix_ref="hunt:linux:remove_cron_file" if removable else "hunt:linux:manual_review",
            evidence=f"{path}{' (hidden file name)' if hidden_name else ''}: " + " | ".join(hits[:5] or ["(no command lines)"]),
            description="A scheduled job runs from a hidden path, a temporary directory or pulls/pushes data over "
                        "the network. Cron is a common persistence mechanism (ATT&CK T1053.003 cron)."))
    return out


EXEC_KEYS = ("ExecStart", "ExecStartPre", "ExecStartPost")


def _unit_execs(content: str) -> list[str]:
    """Exec lines of a unit file. systemd allows whitespace around '=' and the -@:+! prefixes before
    the command, so both are stripped before the command is matched."""
    out = []
    for ln in content.splitlines():
        key, sep, val = ln.partition("=")
        if sep and key.strip() in EXEC_KEYS:
            cmd = val.strip().lstrip("-@:+!").strip()
            if cmd:
                out.append(cmd)
    return out


def rogue_unit(target, c):
    out = []
    for path, content in P.dump(P.out(c, "etc_units") or "").items():
        execs = _unit_execs(content)
        bad = [e for e in execs if SUSPICIOUS_EXEC.search(e)]
        if not bad:
            continue
        unit = path.rsplit("/", 1)[-1]
        out.append(_finding(
            target, c, "rogue_unit", unit, title=f"Suspicious systemd service {unit}", severity="high",
            techniques=["T1543.002"], fix_ref="hunt:linux:disable_unit",
            evidence=f"{path}: " + " | ".join(bad),
            description="A locally created service (not installed by a package) runs a shell, a network tool, an "
                        "ad-hoc web server or a binary from a hidden or temporary path (ATT&CK T1543.002 systemd service)."))
    return out


def unexpected_listener(target, c):
    expected = set(int(p) for p in _opt(target, "expected_ports", [22]))
    ps = P.procs(P.out(c, "procs") or "")
    units = {p.rsplit("/", 1)[-1] for p in P.dump(P.out(c, "etc_units") or "")}
    out, seen = [], set()
    for l in P.ss_listeners(P.out(c, "listeners") or ""):
        if l["port"] in expected or P.is_loopback(l["addr"]) or (l["proto"], l["port"]) in seen:
            continue
        seen.add((l["proto"], l["port"]))
        proc = ps.get(l["pid"] or -1, {})
        unit = proc.get("unit", "")
        local_unit = unit in units
        out.append(_finding(
            target, c, "unexpected_listener", f"{l['proto']}/{l['port']}",
            title=f"Unexpected listener on {l['proto']}/{l['port']} ({l['process'] or 'unknown process'})",
            severity="high" if local_unit else "medium", techniques=["T1571"],
            fix_ref="hunt:linux:disable_unit" if local_unit else "hunt:linux:manual_review",
            fix_arg=unit if local_unit else f"{l['proto']}/{l['port']}",
            evidence=f"ss: {l['line']}" + (f" | ps: pid {l['pid']} unit {unit} args {proc.get('args', '')}" if proc else ""),
            description="A service listens on a port that is not on this host's expected-port list. Backdoors and "
                        "command-and-control often use non-standard ports (ATT&CK T1571 non-standard port)."))
    return out


def suid_unexpected(target, c):
    baseline = SUID_BASELINE | set(_opt(target, "suid_baseline", []))
    hashes = c.raw.get("hashes") or {}
    shells = {hashes[p]: p for p in REFERENCE_SHELLS if p in hashes}
    out = []
    for row in P.find_printf(P.out(c, "suid") or "", ["mode", "owner", "size", "path"]):
        path = row["path"]
        if path in baseline:
            continue
        copy_of = shells.get(hashes.get(path, ""))
        hidden = "/." in path
        sev = "high" if copy_of or hidden else "medium"
        out.append(_finding(
            target, c, "suid_unexpected", path, title=f"Unexpected SUID/SGID file {path}"
            + (f" (copy of {copy_of})" if copy_of else ""), severity=sev, techniques=["T1548.001"],
            fix_ref="hunt:linux:quarantine_file",
            evidence=f"find -perm /6000: mode {row['mode']} owner {row['owner']} size {row['size']} {path}"
            + (f"; sha256 matches {copy_of}" if copy_of else ""),
            description="A set-uid or set-gid file outside the known baseline. A SUID copy of a shell or interpreter "
                        "gives any local user a root shell (ATT&CK T1548.001 setuid and setgid)."))
    return out


def sudoers_nopasswd(target, c):
    admins = set(_opt(target, "admin_users", ["root"]))
    out = []
    for path, content in P.dump(P.out(c, "sudoers") or "").items():
        if not path.startswith("/etc/sudoers.d/"):
            continue
        lines = [ln.strip() for ln in content.splitlines()
                 if ln.strip() and not ln.strip().startswith("#") and "NOPASSWD" in ln]
        principals = sorted({ln.split()[0] for ln in lines} - admins)
        if not principals:
            continue
        out.append(_finding(
            target, c, "sudoers_nopasswd", path, title=f"sudoers drop-in grants NOPASSWD: {path}", severity="high",
            techniques=["T1548.003"], fix_ref="hunt:linux:remove_sudoers_dropin",
            evidence=f"{path}: " + " | ".join(lines[:5]),
            description=f"{', '.join(principals)} can run commands as root without a password through a sudoers "
                        "drop-in (ATT&CK T1548.003 sudo and sudo caching)."))
    return out


# -- defence evasion ----------------------------------------------------------------------------
def _hidden_rows(c):
    return P.find_printf(P.out(c, "hidden") or "", ["type", "mode", "owner", "mtime", "ctime", "path"])


def timestomp(target, c):
    out = []
    for row in _hidden_rows(c):
        if row["type"] != "f":
            continue
        try:
            mtime, ctime = float(row["mtime"]), float(row["ctime"])
        except ValueError:
            continue
        if ctime - mtime < YEAR_S:
            continue
        years = (ctime - mtime) / YEAR_S
        out.append(_finding(
            target, c, "timestomp", row["path"], title=f"Modification time predates change time by {years:.1f} years: "
            f"{row['path']}", severity="medium", techniques=["T1070.006"], fix_ref="hunt:linux:quarantine_file",
            evidence=f"{row['path']}: mtime {int(mtime)} ctime {int(ctime)} mode {row['mode']} owner {row['owner']}",
            description="A hidden file whose modification time was set far into the past while its inode change "
                        "time is recent: the mark of `touch -d` used to blend in (ATT&CK T1070.006 timestomp)."))
    return out


def hidden_dir(target, c):
    out = []
    for row in _hidden_rows(c):
        p = row["path"]
        if row["type"] != "d" or not p.startswith(HIDDEN_DIR_ROOTS):
            continue
        if not p.rsplit("/", 1)[-1].startswith("."):
            continue
        out.append(_finding(
            target, c, "hidden_dir", p, title=f"Hidden directory {p}", severity="medium", techniques=["T1564.001"],
            fix_ref="hunt:linux:manual_review", evidence=f"{p}: mode {row['mode']} owner {row['owner']}",
            description="A hidden directory in a library or temporary path, a common place to stage tools "
                        "(ATT&CK T1564.001 hidden files and directories). Preserve it for the incident record."))
    return out


# -- credential access ----------------------------------------------------------------------------
def failed_login_burst(target, c):
    threshold = int(_opt(target, "failed_login_threshold", 10))
    counts: dict[str, int] = {}
    users: dict[str, set] = {}
    for line in (P.out(c, "auth_log") or "").splitlines():
        m = FAILED_RX.search(line)
        if m:
            counts[m.group(2)] = counts.get(m.group(2), 0) + 1
            users.setdefault(m.group(2), set()).add(m.group(1))
    for line in (P.out(c, "lastb") or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", parts[2]):
            # lastb repeats what the log shows; only count sources the log did not already cover
            if parts[2] not in users:
                counts[parts[2]] = counts.get(parts[2], 0) + 1
    out = []
    for src, n in sorted(counts.items()):
        if n < threshold:
            continue
        out.append(_finding(
            target, c, "failed_login_burst", src, title=f"{n} failed logins from {src}", severity="medium",
            techniques=["T1110"], fix_ref="hunt:linux:block_source",
            evidence=f"auth log / lastb: {n} failures from {src} for {', '.join(sorted(users.get(src, []))) or 'unknown users'}",
            description="A burst of failed logins from one source suggests password guessing (ATT&CK T1110 brute force)."))
    return out


HUNT_CHECKS: dict[str, tuple[Callable, tuple[str, ...]]] = {
    "uid0_duplicate": (uid0_duplicate, ("passwd",)),
    "empty_password": (empty_password, ("shadow",)),
    "unknown_user": (unknown_user, ("passwd",)),
    "unknown_authorized_key": (unknown_authorized_key, ("authkeys",)),
    "cron_suspicious": (cron_suspicious, ("cron",)),
    "rogue_unit": (rogue_unit, ("etc_units",)),
    "unexpected_listener": (unexpected_listener, ("listeners", "procs", "etc_units")),
    "suid_unexpected": (suid_unexpected, ("suid",)),
    "sudoers_nopasswd": (sudoers_nopasswd, ("sudoers",)),
    "timestomp": (timestomp, ("hidden",)),
    "hidden_dir": (hidden_dir, ("hidden",)),
    "failed_login_burst": (failed_login_burst, ("auth_log", "lastb")),
}
EXTRA_HUNT_CMDS = ("group", "unit_files", "running_units", "last")   # context for the operator, not checks


def check_name(rule_id: str) -> str | None:
    if not rule_id.startswith(PREFIX):
        return None
    name = rule_id[len(PREFIX):].split(":", 1)[0]
    return name if name in HUNT_CHECKS else None


def needs(rule_id: str) -> tuple[str, ...]:
    n = check_name(rule_id)
    return HUNT_CHECKS[n][1] if n else ()


def all_needs() -> set[str]:
    return {x for _, n in HUNT_CHECKS.values() for x in n} | set(EXTRA_HUNT_CMDS)


def run_hunt(target, c: Collected) -> list[Finding]:
    selected = list(HUNT_CHECKS)
    if c.rule_filter:
        selected = [n for n in selected if any(check_name(r) == n for r in c.rule_filter)]
    out: list[Finding] = []
    for name in selected:
        fn, _ = HUNT_CHECKS[name]
        try:
            out.extend(fn(target, c))
        except Exception as e:  # noqa: BLE001  one bad parser must not hide the other checks
            c.errors.append(f"hunt {name}: {e}")
    if c.rule_filter:
        wanted = set(c.rule_filter)
        out = [f for f in out if f.rule_id in wanted or any(w == f"{PREFIX}{check_name(w)}" for w in wanted)]
    return out
