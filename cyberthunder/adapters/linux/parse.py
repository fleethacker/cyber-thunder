"""Parsers for the text the collection commands return. Pure functions, no I/O."""
from __future__ import annotations

import base64
import hashlib
import re

from cyberthunder.adapters.base import Collected

from .commands import CMDS

KEY_TYPES = ("ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
             "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
NOLOGIN_SHELLS = {"/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false", "/bin/sync",
                  "/sbin/shutdown", "/sbin/halt", "/usr/bin/sync", "/usr/sbin/shutdown", "/usr/sbin/halt"}


# -- access to collected command output ----------------------------------------------------------
def result(c: Collected, name: str) -> dict | None:
    return (c.raw.get("cmd") or {}).get(name)


def out(c: Collected, name: str) -> str | None:
    """stdout of a collected command, or None if it was not collected or exited with an unexpected code."""
    r = result(c, name)
    if r is None:
        return None
    ok_exits = CMDS[name].ok_exits if name in CMDS else (0,)
    if r.get("exit") not in ok_exits:
        return None
    return r.get("out", "")


# -- parsers -----------------------------------------------------------------------------------
def os_release(text: str) -> dict:
    d = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip().strip('"')
    return d


def sshd_t(text: str) -> dict[str, str]:
    """`sshd -T` prints effective settings as lowercase 'key value'. First occurrence wins."""
    d: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if parts and parts[0].lower() not in d:
            d[parts[0].lower()] = parts[1].strip() if len(parts) > 1 else ""
    return d


def stat_lines(text: str) -> dict[str, tuple[int, str, str]]:
    """'%a %U %G %n' -> {path: (mode, owner, group)}"""
    d = {}
    for line in text.splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4 and re.fullmatch(r"[0-7]{1,4}", parts[0]):
            d[parts[3]] = (int(parts[0], 8), parts[1], parts[2])
    return d


def svc_state(text: str) -> dict[str, tuple[str, str]]:
    d = {}
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) == 3:
            d[parts[0]] = (parts[1].strip() or "unknown", parts[2].strip() or "unknown")
    return d


def dump(text: str) -> dict[str, str]:
    """'==> path <==' blocks -> {path: content}"""
    files: dict[str, list[str]] = {}
    cur = None
    for line in text.splitlines():
        m = re.fullmatch(r"==> (.+) <==", line)
        if m:
            cur = m.group(1)
            files[cur] = []
        elif cur is not None:
            files[cur].append(line)
    return {k: "\n".join(v) + ("\n" if v else "") for k, v in files.items()}


def passwd(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        p = line.split(":")
        if len(p) >= 7 and p[2].lstrip("-").isdigit():
            rows.append({"name": p[0], "uid": int(p[2]), "gid": int(p[3]) if p[3].isdigit() else -1,
                         "gecos": p[4], "home": p[5], "shell": p[6]})
    return rows


def shadow(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        p = line.split(":")
        if len(p) >= 2 and p[0]:
            rows.append({"name": p[0], "hash": p[1]})
    return rows


def group(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        p = line.split(":")
        if len(p) >= 4:
            rows.append({"name": p[0], "gid": int(p[2]) if p[2].isdigit() else -1,
                         "members": [m for m in p[3].split(",") if m]})
    return rows


def ss_listeners(text: str) -> list[dict]:
    """`ss -H -lntup` lines -> [{proto, addr, port, process, pid}]"""
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] not in ("tcp", "udp"):
            continue
        local = parts[4]
        addr, _, port = local.rpartition(":")
        proc = pid = None
        m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        if m:
            proc, pid = m.group(1), int(m.group(2))
        rows.append({"proto": parts[0], "addr": addr.strip("[]"), "port": int(port) if port.isdigit() else -1,
                     "process": proc, "pid": pid, "line": line.strip()})
    return rows


def is_loopback(addr: str) -> bool:
    a = addr.split("%", 1)[0]
    return a.startswith("127.") or a in ("::1", "localhost")


def procs(text: str) -> dict[int, dict]:
    """`ps -eo pid=,unit=,args=` -> {pid: {unit, args}}"""
    d = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) >= 2 and parts[0].isdigit():
            d[int(parts[0])] = {"unit": parts[1], "args": parts[2] if len(parts) > 2 else ""}
    return d


def find_printf(text: str, fields: list[str]) -> list[dict]:
    rows = []
    n = len(fields)
    for line in text.splitlines():
        parts = line.split("|", n - 1)
        if len(parts) == n:
            rows.append(dict(zip(fields, parts)))
    return rows


def rpm_packages(text: str) -> list[dict]:
    pkgs = []
    for line in text.splitlines():
        p = line.strip().split("|")
        if len(p) == 5 and p[0]:
            pkgs.append({"name": p[0], "epoch": None if p[1] in ("(none)", "") else p[1],
                         "version": p[2], "release": p[3], "arch": p[4]})
    return pkgs


def dpkg_packages(text: str) -> list[dict]:
    pkgs = []
    for line in text.splitlines():
        p = line.strip().split("|")
        if len(p) != 3 or not p[0]:
            continue
        ver = p[1]
        epoch = None
        if ":" in ver:
            epoch, ver = ver.split(":", 1)
        if "-" in ver:
            version, _, release = ver.rpartition("-")
        else:
            version, release = ver, ""
        pkgs.append({"name": p[0], "epoch": epoch, "version": version, "release": release, "arch": p[2]})
    return pkgs


def kv_file(text: str, sep: str | None = None) -> dict[str, str]:
    """Simple 'KEY value' / 'KEY=value' config file; first occurrence wins, comments ignored."""
    d: dict[str, str] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if sep:
            if sep not in s:
                continue
            k, v = s.split(sep, 1)
        else:
            parts = s.split(None, 1)
            k, v = parts[0], parts[1] if len(parts) > 1 else ""
        d.setdefault(k.strip(), v.strip())
    return d


def authorized_key(line: str) -> dict | None:
    """Split an authorized_keys line into options, type, blob and comment."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    toks = s.split()
    for i, t in enumerate(toks):
        if t in KEY_TYPES and i + 1 < len(toks):
            blob = toks[i + 1]
            return {"options": " ".join(toks[:i]), "type": t, "blob": blob, "comment": " ".join(toks[i + 2:]),
                    "fingerprint": fingerprint(blob)}
    return None


def fingerprint(blob: str) -> str:
    """OpenSSH-style SHA256 fingerprint of a base64 key blob (what `ssh-keygen -lf` prints)."""
    try:
        raw = base64.b64decode(blob.encode(), validate=False)
    except Exception:  # noqa: BLE001
        raw = blob.encode()
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def sha256sums(text: str) -> dict[str, str]:
    d = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            d[parts[1].lstrip("*")] = parts[0]
    return d
