"""Every command the Linux adapter runs while collecting, in one place.

Keeping the catalogue here means three things stay in step: what collect() runs, what each check says it
needs (so a targeted re-check after a fix only re-collects what that rule reads), and what the simulated
host answers. All of these are read-only. State-changing commands only exist inside FixEntry payloads.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Cmd:
    name: str
    cmd: str
    sudo: bool = False
    ok_exits: tuple[int, ...] = (0,)
    group: str = "check"            # facts | check | hunt
    timeout: int = 120
    spec: dict = field(default_factory=dict, compare=False, hash=False)   # dump roots for multi-file reads


def _dump(roots: list[str], maxdepth: int, *, name: str | None = None, type_: str = "f") -> str:
    """Print every matching file as '==> path <==' followed by its content (dotfiles included)."""
    name_expr = f" -name '{name}'" if name else ""
    return (f"find {' '.join(roots)} -maxdepth {maxdepth} -type {type_}{name_expr} "
            "-exec sh -c 'for f; do printf \"==> %s <==\n\" \"$f\"; cat \"$f\"; done' _ {} +")


def _dump_cmd(name: str, roots: list[str], maxdepth: int, *, file_name: str | None = None, sudo: bool = True,
              group: str = "hunt") -> Cmd:
    return Cmd(name, _dump(roots, maxdepth, name=file_name), sudo=sudo, ok_exits=(0, 1), group=group,
               spec={"roots": roots, "maxdepth": maxdepth, "name": file_name})


RPM_QF = "rpm -qa --qf '%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}\n'"
DPKG_QF = "dpkg-query -W -f '${Package}|${Version}|${Architecture}\n'"
SERVICE_UNITS = ("firewalld", "auditd", "sshd", "ctrl-alt-del.target")
STAT_FILES = ("/etc/shadow", "/etc/passwd", "/etc/group", "/etc/gshadow", "/etc/ssh/sshd_config")
HIDDEN_ROOTS = ("/usr/local/lib", "/var/tmp", "/dev/shm", "/opt", "/etc/cron.d")

_LIST = [
    # facts
    Cmd("os_release", "cat /etc/os-release", group="facts"),
    Cmd("hostname", "hostname", group="facts"),
    Cmd("kernel", "uname -r", group="facts"),
    Cmd("addrs", "ip -4 -o addr show", group="facts"),
    # one of rpm/dpkg is always absent, so a 127 from the wrong one is normal, not an error
    Cmd("rpm_packages", RPM_QF, group="facts", ok_exits=(0, 127), timeout=300),
    Cmd("dpkg_packages", DPKG_QF, group="facts", ok_exits=(0, 1, 127), timeout=300),
    # STIG native checks
    Cmd("sshd_t", "sshd -T", sudo=True),
    Cmd("stat_files", "stat -c '%a %U %G %n' " + " ".join(STAT_FILES), ok_exits=(0, 1)),
    Cmd("svc_state", "for u in " + " ".join(SERVICE_UNITS) + "; do printf '%s|%s|%s\n' \"$u\" "
        "\"$(systemctl is-enabled \"$u\" 2>/dev/null)\" \"$(systemctl is-active \"$u\" 2>/dev/null)\"; done"),
    Cmd("getenforce", "getenforce"),
    Cmd("rpm_absent", "rpm -q telnet-server rsh-server", ok_exits=(0, 1, 2)),
    Cmd("login_defs", "cat /etc/login.defs"),
    Cmd("aslr", "sysctl -n kernel.randomize_va_space"),
    Cmd("gpgcheck", "grep -rsH gpgcheck /etc/dnf/dnf.conf /etc/yum.repos.d", ok_exits=(0, 1, 2)),
    Cmd("coredump", "grep -rshE '^[[:space:]]*Storage=' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d",
        ok_exits=(0, 1, 2)),
    Cmd("ww_dirs", "find /var/log -xdev -type d -perm -0002 -printf '%m %u %p\n'", sudo=True, ok_exits=(0, 1)),
    Cmd("passwd", "cat /etc/passwd", group="check"),
    # hunt material
    Cmd("group", "cat /etc/group", group="hunt"),
    Cmd("shadow", "cat /etc/shadow", sudo=True, group="hunt"),
    _dump_cmd("sudoers", ["/etc/sudoers", "/etc/sudoers.d"], 1, group="check"),
    _dump_cmd("authkeys", ["/root/.ssh", "/home"], 3, file_name="authorized_keys"),
    _dump_cmd("cron", ["/etc/crontab", "/etc/cron.d", "/var/spool/cron"], 1),
    _dump_cmd("etc_units", ["/etc/systemd/system"], 1, file_name="*.service", sudo=False),
    Cmd("unit_files", "systemctl list-unit-files --type=service --no-legend --no-pager", group="hunt"),
    Cmd("running_units", "systemctl list-units --type=service --state=running --no-legend --no-pager", group="hunt"),
    Cmd("listeners", "ss -H -lntup", sudo=True, group="hunt"),
    Cmd("procs", "ps -eo pid=,unit=,args=", group="hunt"),
    Cmd("suid", "find / -xdev -perm /6000 -type f -printf '%m|%u|%s|%p\n'", sudo=True, ok_exits=(0, 1),
        group="hunt", timeout=600),
    Cmd("hidden", "find " + " ".join(HIDDEN_ROOTS) + " -xdev -path '*/.*' -printf '%y|%m|%u|%T@|%C@|%p\n'",
        sudo=True, ok_exits=(0, 1), group="hunt"),
    Cmd("auth_log", "tail -n 400 /var/log/secure 2>/dev/null || tail -n 400 /var/log/auth.log",
        sudo=True, ok_exits=(0, 1), group="hunt"),
    Cmd("last", "last -n 50", ok_exits=(0, 1), group="hunt"),
    Cmd("lastb", "lastb -n 50", sudo=True, ok_exits=(0, 1), group="hunt"),
]

CMDS: dict[str, Cmd] = {c.name: c for c in _LIST}
BY_STRING: dict[str, Cmd] = {c.cmd: c for c in _LIST}

FACT_CMDS = [c.name for c in _LIST if c.group == "facts" and c.name not in ("rpm_packages", "dpkg_packages")]
