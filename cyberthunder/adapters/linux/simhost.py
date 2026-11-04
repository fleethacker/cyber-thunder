"""SimulatedLinuxHost: a stateful emulation of the seeded range host.

It answers every read-only command the adapter issues (matched by the exact command string from
commands.py, so the catalogue and the simulation cannot drift apart) and renders its output from the state
dictionary in simstate.py. Running a vetted fix payload applies that fix's effect to the state, so verify
and rollback are real state transitions, not canned answers. Unknown commands return exit 127, which makes
missing coverage visible instead of silently passing.

State persists as JSON under <state_dir>/simulated/<target_id>.json so the CLI and API share one host.
"""
from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

from cyberthunder.transport.base import CommandResult, Transport

from . import commands as C
from . import fixes as FX
from . import simstate


class SimulatedLinuxHost(Transport):
    kind = "simulated"

    def __init__(self, target_id: str, state_dir: str | Path):
        self.target_id = target_id
        self.path = Path(state_dir) / "simulated" / f"{target_id}.json"
        self.scratch: dict[str, str] = {}   # staged payloads / arg files; in memory, not part of host state
        self.state = self._load()

    # -- persistence ------------------------------------------------------------------
    def _load(self) -> dict:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text(encoding="utf-8"))
            except ValueError:
                pass
        state = simstate.seed_state()
        self._save(state)
        return state

    def _save(self, state: dict | None = None) -> None:
        s = state if state is not None else self.state
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(s, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)

    def reset(self) -> None:
        self.state = simstate.seed_state()
        self._save()

    # -- rendering the passwd/shadow/group text views --------------------------------
    def _passwd_text(self) -> str:
        return "".join(f"{u['name']}:x:{u['uid']}:{u['gid']}:{u['gecos']}:{u['home']}:{u['shell']}\n"
                       for u in self.state["users"])

    def _shadow_text(self) -> str:
        sh = self.state["shadow"]
        return "".join(f"{u['name']}:{sh.get(u['name'], '!!')}:19000:1:60:7:::\n" for u in self.state["users"])

    def _group_text(self) -> str:
        return "".join(f"{g['name']}:x:{g['gid']}:{','.join(g['members'])}\n" for g in self.state["groups"])

    def _file_content(self, path: str) -> str:
        # passwd/shadow/group are always rendered from structured state; their files entry only carries
        # mode and ownership metadata, so the text and the structure can never drift apart.
        if path == "/etc/passwd":
            return self._passwd_text()
        if path == "/etc/shadow":
            return self._shadow_text()
        if path == "/etc/group":
            return self._group_text()
        f = self.state["files"].get(path)
        return f.get("content", "") if f is not None else ""

    # -- command dispatch -------------------------------------------------------------
    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult:
        cmd = C.BY_STRING.get(command)
        if cmd is not None:
            out, code = self._render(cmd)
            return CommandResult(command, code, out, "")
        # command -v probes: oscap and trivy are not present in the simulation
        if command.startswith("command -v "):
            return CommandResult(command, 1, "", "")
        if command.strip() in ("true", "systemctl is-system-running"):
            if command.strip() == "systemctl is-system-running":
                return CommandResult(command, 0, "running\n", "")
            return CommandResult(command, 0, "", "")
        m = re.fullmatch(r"systemctl is-active (\S+)", command.strip())
        if m:
            u = self._unit(m.group(1))
            active = u.get("active", "inactive")
            return CommandResult(command, 0 if active == "active" else 3, active + "\n", "")
        if command.startswith("sha256sum "):
            return CommandResult(command, 0, self._sha256sum(command), "")
        if self._is_fix_invocation(command):
            return self._run_fix(command)
        dyn = self._dynamic(command)
        if dyn is not None:
            return CommandResult(command, dyn[1], dyn[0], "" if dyn[1] in (0,) else dyn[0])
        return CommandResult(command, 127, "", f"simulated host: command not implemented: {command!r}")

    def _dynamic(self, command: str) -> tuple[str, int] | None:
        """Single commands the adapter issues while capturing a before-state or rolling back. Each mirrors
        the real tool's effect on the modelled state. Anything not matched here returns 127 to the caller."""
        cmd = command.strip()
        try:
            toks = shlex.split(cmd)
        except ValueError:
            return None
        s = self.state

        m = re.fullmatch(r"stat -c '%a %U %G %n' (.+)", cmd)
        if m:
            path = shlex.split(m.group(1))[0]
            f = s["files"].get(path)
            if f is None and path in ("/etc/passwd", "/etc/shadow", "/etc/group"):
                f = {"mode": 0o644 if path != "/etc/shadow" else 0o000, "owner": "root", "group": "root"}
            if f is None:
                return (f"stat: cannot statx '{path}': No such file or directory\n", 1)
            return (f"{f['mode'] & 0o7777:o} {f['owner']} {f['group']} {path}\n", 0)

        m = re.fullmatch(r"chmod ([0-7]{1,4}) (.+)", cmd)
        if m:
            path = shlex.split(m.group(2))[0]
            if path in s["files"]:
                s["files"][path]["mode"] = int(m.group(1), 8)
                self._save()
            return ("", 0)

        m = re.fullmatch(r"chown ([^:]+):(\S+) (.+)", cmd)
        if m:
            path = shlex.split(m.group(3))[0]
            if path in s["files"]:
                s["files"][path]["owner"] = m.group(1)
                s["files"][path]["group"] = m.group(2)
                self._save()
            return ("", 0)

        # rollback of a quarantine fix: move the quarantined original back into place
        if len(toks) == 5 and toks[:3] == ["mv", "-f", "--"] and toks[3].startswith(FX.QUARANTINE_DIR + "/"):
            key = toks[3][len(FX.QUARANTINE_DIR) + 1:]
            if key not in s["quarantine"]:
                return (f"mv: cannot stat '{toks[3]}': No such file or directory\n", 1)
            s["files"][toks[4]] = s["quarantine"].pop(key)
            self._save()
            return ("", 0)

        m = re.fullmatch(r"systemctl (mask|unmask|enable|disable|start|stop) (\S+)", cmd)
        if m:
            verb, unit = m.group(1), m.group(2)
            u = s["units"].setdefault(unit, {"enabled": "disabled", "active": "inactive"})
            if verb == "mask":
                u["enabled"], u["active"] = "masked", "inactive"
            elif verb == "unmask":
                u["enabled"] = "disabled" if u["enabled"] == "masked" else u["enabled"]
            elif verb == "enable":
                u["enabled"] = "enabled"
            elif verb == "disable":
                u["enabled"] = "disabled"
            elif verb == "start":
                u["active"] = "active"
            elif verb == "stop":
                u["active"] = "inactive"
            self._save()
            return ("", 0)

        m = re.fullmatch(r"systemctl is-enabled (\S+)", cmd)
        if m:
            u = self._unit(m.group(1))
            return (u.get("enabled", "disabled") + "\n", 0 if u.get("enabled") == "enabled" else 1)
        if re.fullmatch(r"systemctl reload-or-restart \S+", cmd) or re.fullmatch(r"systemctl daemon-reload", cmd):
            return ("", 0)

        m = re.fullmatch(r"sysctl -n (\S+)", cmd)
        if m:
            return (s["sysctl"].get(m.group(1), "0") + "\n", 0)
        m = re.fullmatch(r"sysctl -q -w (\S+)=(\S+)", cmd)
        if m:
            s["sysctl"][m.group(1)] = m.group(2)
            self._save()
            return ("", 0)

        m = re.fullmatch(r"setenforce ([01])", cmd)
        if m:
            s["selinux"] = "Enforcing" if m.group(1) == "1" else "Permissive"
            self._save()
            return ("", 0)

        m = re.fullmatch(r"rpm -q (\S+)", cmd)
        if m:
            p = self._installed(m.group(1))
            if p:
                return (f"{p['name']}-{p['version']}-{p['release']}.{p['arch']}\n", 0)
            return (f"package {m.group(1)} is not installed\n", 1)

        m = re.fullmatch(r"find (\S+) -maxdepth 1 -type f -name '([^']+)' 2>/dev/null", cmd)
        if m:
            directory, pattern = m.group(1), m.group(2)
            import fnmatch
            hits = [p for p in sorted(s["files"])
                    if p.rsplit("/", 1)[0] == directory.rstrip("/")
                    and fnmatch.fnmatch(p.rsplit("/", 1)[-1], pattern)]
            return ("\n".join(hits) + ("\n" if hits else ""), 0)
        return None

    def _unit(self, name: str) -> dict:
        u = self.state["units"]
        return u.get(name) or u.get(name + ".service") or u.get(name.removesuffix(".service")) or {}

    def _render(self, cmd: C.Cmd) -> tuple[str, int]:
        name, s = cmd.name, self.state
        if name == "os_release":
            return s["os_release"], 0
        if name == "hostname":
            return s["hostname"] + "\n", 0
        if name == "kernel":
            return s["kernel"] + "\n", 0
        if name == "addrs":
            return s["addrs"], 0
        if name == "rpm_packages":
            return "".join(f"{p['name']}|{p['epoch'] or '(none)'}|{p['version']}|{p['release']}|{p['arch']}\n"
                           for p in s["packages"]), 0
        if name == "dpkg_packages":
            return "", 127   # RHEL host: dpkg is not present
        if name == "sshd_t":
            return "".join(f"{k} {v}\n" for k, v in self._sshd_effective().items()), 0
        if name == "stat_files":
            return self._stat_files(), 0
        if name == "svc_state":
            return self._svc_state(), 0
        if name == "getenforce":
            return s["selinux"] + "\n", 0
        if name == "rpm_absent":
            return self._rpm_absent(), self._rpm_absent_code()
        if name == "login_defs":
            return self._file_content("/etc/login.defs"), 0
        if name == "aslr":
            return s["sysctl"].get("kernel.randomize_va_space", "0") + "\n", 0
        if name == "gpgcheck":
            return self._gpgcheck(), 0
        if name == "coredump":
            return self._grep_storage(), (0 if "Storage=" in self._grep_storage() else 1)
        if name == "ww_dirs":
            rows = s.get("ww_dirs", [])
            return "".join(f"{r['mode']} {r['owner']} {r['path']}\n" for r in rows), (0 if rows else 1)
        if name == "passwd":
            return self._passwd_text(), 0
        if name == "group":
            return self._group_text(), 0
        if name == "shadow":
            return self._shadow_text(), 0
        if name == "sudoers":
            return self._dump(["/etc/sudoers", "/etc/sudoers.d"]), 0
        if name == "authkeys":
            return self._dump_files(lambda p: p.endswith("/authorized_keys")), 0
        if name == "cron":
            return self._dump_cron(), 0
        if name == "etc_units":
            return self._dump_etc_units(), 0
        if name == "unit_files":
            return self._unit_files(), 0
        if name == "running_units":
            return self._running_units(), 0
        if name == "listeners":
            return self._listeners(), 0
        if name == "procs":
            return "".join(f"{pid} {p['unit']} {p['args']}\n" for pid, p in sorted(s["procs"].items())), 0
        if name == "suid":
            return self._suid(), 0
        if name == "hidden":
            return self._hidden(), 0
        if name == "auth_log":
            return s.get("auth_log", ""), 0
        if name == "last":
            return s.get("last", ""), 0
        if name == "lastb":
            return s.get("lastb", ""), 0
        return "", 127

    # -- individual renderers ---------------------------------------------------------
    def _sshd_effective(self) -> dict:
        """Base defaults overlaid with the directives in sshd_config (first occurrence wins, as sshd does)."""
        eff = dict(self.state.get("sshd_base", {}))
        over: dict[str, str] = {}
        for line in self._file_content("/etc/ssh/sshd_config").splitlines():
            s = line.strip()
            if not s or s.startswith("#") or s.lower().startswith("include") or s.lower().startswith("match"):
                continue
            parts = s.split(None, 1)
            key = parts[0].lower()
            if key not in over:
                over[key] = parts[1].strip() if len(parts) > 1 else ""
        eff.update(over)
        return eff

    def _stat_files(self) -> str:
        out = []
        for p in C.STAT_FILES:
            f = self.state["files"].get(p)
            if f is None:
                continue
            out.append(f"{f['mode'] & 0o7777:o} {f['owner']} {f['group']} {p}")
        return "\n".join(out) + ("\n" if out else "")

    def _svc_state(self) -> str:
        out = []
        for short in ("firewalld", "auditd", "sshd", "ctrl-alt-del.target"):
            u = self._unit(short)
            out.append(f"{short}|{u.get('enabled', 'unknown')}|{u.get('active', 'unknown')}")
        return "\n".join(out) + "\n"

    def _installed(self, pkg: str) -> dict | None:
        return next((p for p in self.state["packages"] if p["name"] == pkg), None)

    def _rpm_absent(self) -> str:
        out = []
        for pkg in ("telnet-server", "rsh-server"):
            p = self._installed(pkg)
            out.append(f"{p['name']}-{p['version']}-{p['release']}.{p['arch']}" if p
                       else f"package {pkg} is not installed")
        return "\n".join(out) + "\n"

    def _rpm_absent_code(self) -> int:
        return 0 if all(self._installed(p) for p in ("telnet-server", "rsh-server")) else 1

    def _gpgcheck(self) -> str:
        lines = []
        for line in self._file_content("/etc/dnf/dnf.conf").splitlines():
            if line.strip().replace(" ", "").startswith("gpgcheck="):
                lines.append(f"/etc/dnf/dnf.conf:{line.strip()}")
        return "\n".join(lines) + ("\n" if lines else "")

    def _grep_storage(self) -> str:
        out = [f"/etc/systemd/coredump.conf:{ln.strip()}"
               for ln in self._file_content("/etc/systemd/coredump.conf").splitlines()
               if ln.strip().startswith("Storage=")]
        return "\n".join(out) + ("\n" if out else "")

    def _dump(self, roots: list[str]) -> str:
        def match(p: str) -> bool:
            return any(p == r or p.startswith(r.rstrip("/") + "/") for r in roots)
        return self._dump_files(match)

    def _dump_files(self, match) -> str:
        out = []
        for path in sorted(self.state["files"]):
            if match(path):
                out.append(f"==> {path} <==\n{self._file_content(path)}")
        return "".join(out)

    def _dump_cron(self) -> str:
        roots = ("/etc/crontab", "/etc/cron.d", "/var/spool/cron")
        out = []
        for path in sorted(self.state["files"]):
            if path == "/etc/crontab" or path.startswith(("/etc/cron.d/", "/var/spool/cron/")):
                out.append(f"==> {path} <==\n{self._file_content(path)}")
        return "".join(out)

    def _dump_etc_units(self) -> str:
        out = []
        for path in sorted(self.state["files"]):
            if path.startswith("/etc/systemd/system/") and path.endswith(".service"):
                out.append(f"==> {path} <==\n{self._file_content(path)}")
        return "".join(out)

    def _unit_files(self) -> str:
        return "".join(f"{n:<40} {u['enabled']}\n" for n, u in sorted(self.state["units"].items())
                       if n.endswith(".service"))

    def _running_units(self) -> str:
        return "".join(f"{n:<40} loaded active running {n}\n" for n, u in sorted(self.state["units"].items())
                       if n.endswith(".service") and u.get("active") == "active")

    def _listeners(self) -> str:
        out = []
        for l in self.state["listeners"]:
            users = f'users:(("{l["process"]}",pid={l["pid"]},fd=3))' if l.get("process") else ""
            out.append(f"{l['proto']}   LISTEN 0      128    {l['addr']}:{l['port']}   *:*    {users}")
        return "\n".join(out) + ("\n" if out else "")

    def _sha256sum(self, command: str) -> str:
        """Hash the listed paths. A seeded bash copy hashes identically to /usr/bin/bash so the
        suid_unexpected hunt can flag it as a shell copy, exactly as it would on a live host."""
        import hashlib
        toks = shlex.split(command)[1:]
        paths = [t for t in toks if t != "--"]
        bash_digest = hashlib.sha256(b"cyberthunder-sim:/usr/bin/bash").hexdigest()
        out = []
        for p in paths:
            f = self.state["files"].get(p)
            if p in ("/usr/bin/bash", "/usr/bin/sh") or (f and f.get("is_bash_copy")):
                digest = bash_digest
            elif f is not None:
                digest = hashlib.sha256(f.get("content", "").encode("utf-8")).hexdigest()
            elif p in ("/usr/bin/dash", "/usr/bin/zsh", "/usr/bin/python3", "/usr/bin/perl",
                       "/usr/libexec/platform-python"):
                digest = hashlib.sha256(("cyberthunder-sim:" + p).encode()).hexdigest()
            else:
                continue
            out.append(f"{digest}  {p}")
        return "\n".join(out) + ("\n" if out else "")

    def _suid(self) -> str:
        """`find / -perm /6000`: the static system baseline plus any modelled file that carries a
        setuid/setgid bit. Deriving the latter from file mode means quarantining a SUID file (and
        restoring it on rollback) shows up here exactly as it would on a real host."""
        rows = list(self.state.get("suid", []))
        for path, f in sorted(self.state["files"].items()):
            if f.get("mode", 0) & 0o6000:
                size = str(len(f.get("content", "")) or 1234520)
                rows.append({"mode": f"{f['mode'] & 0o7777:o}", "owner": f.get("owner", "root"),
                             "size": size, "path": path})
        return "".join(f"{r['mode']}|{r['owner']}|{r.get('size', '0')}|{r['path']}\n" for r in rows)

    def _hidden(self) -> str:
        out = []
        hd = self.state.get("hidden_dir")
        if hd:
            out.append(f"d|0755|root|0|0|{hd}")
        for path, f in sorted(self.state["files"].items()):
            if "/." in path and (path.startswith(("/usr/local/lib/", "/var/tmp/", "/dev/shm/", "/opt/"))):
                mt = f.get("mtime", 1762000000.0)
                ct = f.get("ctime", 1762000000.0)
                out.append(f"f|{f['mode'] & 0o7777:o}|{f['owner']}|{mt}|{ct}|{path}")
        return "\n".join(out) + ("\n" if out else "")

    # -- file I/O ---------------------------------------------------------------------
    def read_file(self, path: str) -> bytes:
        if path in ("/etc/passwd", "/etc/shadow", "/etc/group"):
            return self._file_content(path).encode("utf-8")
        f = self.state["files"].get(path)
        if f is None:
            from cyberthunder.transport.base import TransportError
            raise TransportError(f"simulated host has no file {path!r}")
        return f.get("content", "").encode("utf-8")

    def write_file(self, path: str, data: bytes, *, mode: int | None = None, sudo: bool = False) -> None:
        text = data.decode("utf-8", "replace")
        # the fix argument file and the remote payload script live outside the modelled filesystem
        if path.startswith("/tmp/") or path.startswith("/var/tmp/ct-"):
            self.scratch[path] = text
            return
        # /etc/passwd, /etc/shadow and /etc/group are rendered from structured state, so a write-back
        # (a rollback restoring the captured file) feeds that structure; their files entry keeps only
        # mode/ownership, never a content copy, so the text and the structure cannot drift.
        if path in ("/etc/passwd", "/etc/shadow", "/etc/group"):
            self._ingest_account_file(path, text)
            if path in self.state["files"] and mode is not None:
                self.state["files"][path]["mode"] = mode
            self._save()
            return
        f = self.state["files"].setdefault(path, {"mode": mode or 0o644, "owner": "root", "group": "root"})
        f["content"] = text
        if mode is not None:
            f["mode"] = mode
        self._save()

    def _ingest_account_file(self, path: str, text: str) -> None:
        from . import parse
        if path == "/etc/passwd":
            self.state["users"] = parse.passwd(text)
        elif path == "/etc/group":
            self.state["groups"] = parse.group(text)
        elif path == "/etc/shadow":
            self.state["shadow"] = {r["name"]: r["hash"] for r in parse.shadow(text)}

    # -- applying a fix ---------------------------------------------------------------
    def _is_fix_invocation(self, command: str) -> bool:
        return "/ct-fix-" in command or bool(re.search(r"bash\s+\S*ct-fix", command))

    def _run_fix(self, command: str) -> CommandResult:
        """The engine writes the payload to a temp file then runs it; we recover the payload from scratch,
        read its header to find the fix, and apply that fix's effect to the state."""
        scratch = self.scratch
        script = arg = None
        toks = shlex.split(command)
        for i, t in enumerate(toks):
            if "ct-fix-" in t and t.endswith(".sh"):
                script = scratch.get(t)
            if "ct-fix-" in t and t.endswith(".arg"):
                arg = scratch.get(t, "")
        if script is None:
            # fall back to the last staged script
            for p, text in reversed(list(scratch.items())):
                if p.endswith(".sh"):
                    script = text
                    break
        ref = FX.fix_header_ref(script or "")
        if not ref:
            return CommandResult(command, 2, "", "simulated host: payload has no cyberthunder-fix header")
        subject = (arg or "").splitlines()[0].strip() if arg else ""
        try:
            msg = apply_fix(self.state, ref, subject)
        except FixRefused as e:
            return CommandResult(command, 2, "", f"refusing: {e}")
        self._save()
        return CommandResult(command, 0, msg + "\n", "")


class FixRefused(Exception):
    pass


def apply_fix(state: dict, ref: str, subject: str = "") -> str:
    """Mutate the simulated state as the vetted fix would. Mirrors fixes._native_payload/_hunt_payload."""
    if ref.startswith("ssg:"):
        return _apply_native(state, ref)
    if ref.startswith("hunt:"):
        return _apply_hunt(state, ref, subject)
    if ref.startswith("patch:"):
        return _apply_patch(state, ref)
    raise FixRefused(f"unknown fix ref {ref}")


def _native_rule(ref: str) -> FX.NativeRule:
    for r in FX.NATIVE:
        if r.fix_ref == ref:
            return r
    raise FixRefused(f"no native rule for {ref}")


def _apply_native(state: dict, ref: str) -> str:
    r = _native_rule(ref)
    f, p = r.family, r.params
    if f == "sshd":
        # same net effect as `sed -i '/^KEYWORD/Id; 1i KEYWORD value'`: drop existing, insert at line 1
        conf = state["files"]["/etc/ssh/sshd_config"]
        kw = p["keyword"]
        kept = [ln for ln in conf["content"].splitlines()
                if ln.strip().split(None, 1)[:1] != [kw] and not ln.strip().lower().startswith(kw.lower() + " ")]
        conf["content"] = f"{kw} {p['value']}\n" + "\n".join(kept) + "\n"
        return f"set {p['keyword']} {p['value']}"
    if f == "file_mode":
        state["files"][p["path"]]["mode"] = int(p["mode"], 8)
        return f"chmod {p['mode']} {p['path']}"
    if f == "file_owner":
        state["files"][p["path"]]["owner"] = p["owner"]
        return f"chown {p['owner']} {p['path']}"
    if f == "service_on":
        state["units"][p["unit"]] = {"enabled": "enabled", "active": "active"}
        return f"enabled {p['unit']}"
    if f == "unit_mask":
        state["units"][p["unit"]] = {"enabled": "masked", "active": "inactive"}
        return f"masked {p['unit']}"
    if f == "selinux":
        state["selinux"] = "Enforcing"
        state["files"]["/etc/selinux/config"]["content"] = "SELINUX=enforcing\nSELINUXTYPE=targeted\n"
        return "SELinux set to enforcing"
    if f == "pkg_remove":
        pkgs = state["packages"]
        state["packages"] = [x for x in pkgs if x["name"] != p["package"]]
        if len(state["packages"]) != len(pkgs):
            state["removed_packages"].append(p["package"])
        return f"removed {p['package']}"
    if f == "login_defs":
        _set_kv_file(state, "/etc/login.defs", p["key"], p["value"])
        return f"set {p['key']} {p['value']}"
    if f == "sysctl":
        state["sysctl"][p["key"]] = p["value"]
        return f"set {p['key']}={p['value']}"
    if f == "gpgcheck":
        _set_assign(state, "/etc/dnf/dnf.conf", "gpgcheck", "1")
        return "gpgcheck=1"
    if f == "coredump":
        _set_assign(state, "/etc/systemd/coredump.conf", "Storage", "none")
        return "Storage=none"
    if f == "ww_dirs":
        state["ww_dirs"] = []
        return "cleared world-writable bit"
    if f == "sudo_nopasswd":
        for path, meta in state["files"].items():
            if path == "/etc/sudoers" or path.startswith("/etc/sudoers.d/"):
                meta["content"] = meta["content"].replace("NOPASSWD:", "").replace("NOPASSWD :", "")
        return "removed NOPASSWD"
    raise FixRefused(f"no simulated effect for family {f}")


def _apply_hunt(state: dict, ref: str, subject: str) -> str:
    name = ref.split(":", 2)[-1]
    if name == "remove_account":
        if not FX.valid_subject("user", subject):
            raise FixRefused(f"bad account {subject!r}")
        state["users"] = [u for u in state["users"] if u["name"] != subject]
        state["shadow"].pop(subject, None)
        for g in state["groups"]:
            if subject in g["members"]:
                g["members"].remove(subject)
        state["groups"] = [g for g in state["groups"] if g["name"] != subject]
        return f"removed account {subject}"
    if name == "lock_account":
        if subject in state["shadow"]:
            state["shadow"][subject] = "!" + (state["shadow"][subject] or "")
        return f"locked {subject}"
    if name == "remove_authorized_key":
        path, _, blob = subject.partition("|")
        f = state["files"].get(path)
        if not f:
            return f"already gone: {path}"
        f["content"] = "".join(ln + "\n" for ln in f["content"].splitlines() if blob not in ln)
        return f"removed key from {path}"
    if name in ("remove_cron_file", "remove_sudoers_dropin", "quarantine_file"):
        return _quarantine(state, subject)
    if name == "disable_unit":
        if not FX.valid_subject("unit", subject):
            raise FixRefused(f"bad unit {subject!r}")
        upath = f"/etc/systemd/system/{subject}"
        if upath in state["files"]:
            state["quarantine"][f"etc_systemd_system_{subject}"] = state["files"].pop(upath)
        state["units"][subject] = {"enabled": "masked", "active": "inactive"}
        state["procs"] = {pid: p for pid, p in state["procs"].items() if p.get("unit") != subject}
        state["listeners"] = [l for l in state["listeners"]
                              if state_proc_unit(state, l.get("pid")) != subject]
        return f"disabled and masked {subject}"
    raise FixRefused(f"no simulated effect for hunt fix {ref}")


def state_proc_unit(state: dict, pid) -> str | None:
    p = state["procs"].get(pid) if pid is not None else None
    return p.get("unit") if p else None


def _quarantine(state: dict, path: str) -> str:
    if path not in state["files"]:
        return f"already gone: {path}"
    key = path.lstrip("/").replace("/", "_")
    state["quarantine"][key] = state["files"].pop(path)
    return f"quarantined {path}"


def _apply_patch(state: dict, ref: str) -> str:
    pkg = ref.split(":", 1)[1]
    for p in state["packages"]:
        if p["name"] == pkg:
            p["release"] = p["release"] + ".ct1"
    return f"patched {pkg}"


# -- small file editors (same net effect the bash payloads have) --------------------------------
def _set_kv_file(state: dict, path: str, key: str, value: str) -> None:
    f = state["files"][path]
    lines, done = [], False
    for ln in f["content"].splitlines():
        if ln.strip().split(None, 1)[:1] == [key]:
            lines.append(f"{key} {value}")
            done = True
        else:
            lines.append(ln)
    if not done:
        lines.append(f"{key} {value}")
    f["content"] = "\n".join(lines) + "\n"


def _set_assign(state: dict, path: str, key: str, value: str) -> None:
    f = state["files"][path]
    lines, done = [], False
    for ln in f["content"].splitlines():
        if ln.strip().replace(" ", "").startswith(key + "="):
            lines.append(f"{key}={value}")
            done = True
        else:
            lines.append(ln)
    if not done:
        lines.append(f"{key}={value}")
    f["content"] = "\n".join(lines) + "\n"
