"""Intrusion and persistence hunt for Windows hosts. Every finding cites a MITRE ATT&CK technique.

hunt.ps1 collects raw inventory as one JSON document; this module decides what is suspicious. Keeping the
judgement here (pure Python) means the same rules run on live output, fixtures and the simulated host.

hunt.ps1 output (schema 1):
  now                 ISO-8601 time on the host
  admins              [{name, sid, object_class, source}]      members of BUILTIN\\Administrators (S-1-5-32-544)
  users               [{name, sid, enabled, description}]
  created_accounts    [{time, name, by}]                       Security 4720 in the last 30 days
  run_keys            [{key, name, value}]                     HKLM/HKU Run and RunOnce values
  tasks               [{path, name, state, author, actions: [{execute, arguments}]}]   outside \\Microsoft\\
  services            [{name, display, path, start_type, status, account}]
  service_installs    [{time, service, image, account}]        System 7045 in the last 30 days
  listeners           [{address, port, pid, process}]          TCP listeners
  wmi                 [{filter, query, consumer, consumer_class, command}]
  hidden_accounts     [{name, value}]                          Winlogon\\SpecialAccounts\\UserList
  rdp                 {enabled, key_last_write, nla}
  failed_logons       [{time, user, ip}]                       Security 4625 in the last 24 hours (capped)
  defender_exclusions {paths, processes, extensions}

Each hunt finding carries a stable rule id 'win:hunt:<check>:<item>' so a later scan of the same host
yields the same finding id, and a structured item (`params`) that the matching remediation acts on.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

SOURCE = "hunt"

USER_WRITABLE = (
    "\\users\\", "\\appdata\\", "\\temp\\", "\\tmp\\", "\\programdata\\", "\\windows\\temp\\",
    "%appdata%", "%localappdata%", "%temp%", "%tmp%", "%userprofile%", "%public%", "%programdata%",
)
ENCODED_RE = re.compile(r"(?i)(?:^|\s)-e(?:c|n[a-z]*)?\s+[A-Za-z0-9+/=]{20,}")
DOWNLOAD_RE = re.compile(r"(?i)frombase64string|downloadstring|invoke-expression|\biex\b|net\.webclient")

# Ports Windows itself listens on; anything else must be in target.options.expected_ports.
WINDOWS_BASELINE_PORTS = {135, 139, 445, 5040, 7680}
RPC_DYNAMIC = range(49152, 65536)
RPC_PROCESSES = {"lsass", "wininit", "services", "svchost", "spoolsv", "system"}

BRUTE_WINDOW = timedelta(minutes=5)
BRUTE_THRESHOLD = 10
RECENT = timedelta(days=30)


@dataclass
class HuntHit:
    check: str                 # short check name
    technique: str             # ATT&CK id
    item: str                  # stable item key within the check
    title: str
    severity: str
    evidence: str
    description: str
    params: dict = field(default_factory=dict)   # structured item for the remediation (never free text)
    fix_ref: str | None = None
    extra_refs: tuple[str, ...] = ()

    @property
    def rule_id(self) -> str:
        return f"win:hunt:{self.check}:{self.item}"


def _parse_time(v) -> datetime | None:
    if not v:
        return None
    s = str(v).strip()
    m = re.match(r"^/Date\((\d+)", s)    # ConvertTo-Json on Windows PowerShell 5.1 DateTime
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc)
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _short(name: str | None) -> str:
    n = (name or "").strip()
    return n.split("\\")[-1]


def _key(*parts: str) -> str:
    raw = "|".join(p or "" for p in parts)
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", parts[-1] if parts else "")[:40].strip("_") or "item"
    return f"{slug}-{hashlib.sha256(raw.lower().encode('utf-8')).hexdigest()[:8]}"


def user_writable(path: str | None) -> bool:
    p = (path or "").lower().replace("/", "\\")
    return any(x in p for x in USER_WRITABLE)


def _list(v) -> list:
    """ConvertTo-Json writes a single-element array as an object and an empty one as null."""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _now(state: dict) -> datetime:
    return _parse_time(state.get("now")) or datetime.now(timezone.utc)


def rogue_admins(state: dict, opts: dict) -> list[HuntHit]:
    known = {k.lower() for k in opts.get("known_admins", [])}
    out = []
    for m in _list(state.get("admins")):
        sid = str(m.get("sid") or "")
        name = _short(m.get("name"))
        if sid.endswith("-500") or sid.endswith("-512") or name.lower() in known:
            continue    # built-in administrator, Domain Admins, or explicitly approved
        out.append(HuntHit(
            "admin_member", "T1078.003", _key(name), f"Unapproved member of local Administrators: {name}", "high",
            f"{m.get('name')} (SID {sid or 'unknown'}, {m.get('object_class') or 'User'}) is in BUILTIN\\Administrators; "
            f"approved admins: {sorted(known) or 'none listed'}",
            "An account with local administrator rights that is not on the approved list is a common way an "
            "intruder keeps privileged access after the first compromise (valid local accounts).",
            params={"member": m.get("name") or name}, fix_ref="windows:hunt:remove_admin_member"))
    return out


def _disabled_users(state: dict) -> set[str]:
    return {str(u.get("name")).lower() for u in _list(state.get("users")) if u.get("enabled") is False}


def new_accounts(state: dict, opts: dict) -> list[HuntHit]:
    now = _now(state)
    disabled = _disabled_users(state)
    out = []
    for e in _list(state.get("created_accounts")):
        if _short(e.get("name")).lower() in disabled:
            continue
        t = _parse_time(e.get("time"))
        if t and now - t > RECENT:
            continue
        name = _short(e.get("name"))
        out.append(HuntHit(
            "new_account", "T1136.001", _key(name), f"Local account created recently: {name}", "medium",
            f"Security event 4720 at {e.get('time')}: account {name!r} created by {e.get('by') or 'unknown'}",
            "A local account created in the last 30 days. Confirm it was requested through change control; "
            "attackers create local accounts to keep access.",
            params={"name": name}, fix_ref="windows:hunt:disable_account"))
    return out


def run_keys(state: dict, opts: dict) -> list[HuntHit]:
    out = []
    for r in _list(state.get("run_keys")):
        val = str(r.get("value") or "")
        why = []
        if user_writable(val):
            why.append("points into a user-writable path")
        if ENCODED_RE.search(val) or DOWNLOAD_RE.search(val):
            why.append("runs encoded or downloaded PowerShell")
        if not why:
            continue
        out.append(HuntHit(
            "run_key", "T1547.001", _key(r.get("key"), r.get("name")), f"Suspicious autorun value: {r.get('name')}", "high",
            f"{r.get('key')}\\{r.get('name')} = {val!r} ({'; '.join(why)})",
            "A Run/RunOnce registry value starts a program at every logon. Programs started from user-writable "
            "folders or as encoded PowerShell are a standard persistence technique.",
            params={"key": r.get("key"), "name": r.get("name")}, fix_ref="windows:hunt:remove_run_value"))
    return out


def scheduled_tasks(state: dict, opts: dict) -> list[HuntHit]:
    out = []
    for t in _list(state.get("tasks")):
        if str(t.get("state")) == "Disabled":
            continue    # disabled tasks do not run; the remediation for this check disables the task
        acts = _list(t.get("actions"))
        why = []
        for a in acts:
            line = f"{a.get('execute') or ''} {a.get('arguments') or ''}"
            if user_writable(line):
                why.append("action runs from a user-writable path")
            if ENCODED_RE.search(line) or DOWNLOAD_RE.search(line):
                why.append("action runs encoded or downloaded PowerShell")
        if not why:
            continue
        shown = "; ".join(f"{a.get('execute')} {a.get('arguments') or ''}".strip()[:200] for a in acts)
        full = f"{t.get('path') or chr(92)}{t.get('name')}"
        out.append(HuntHit(
            "scheduled_task", "T1053.005", _key(t.get("path"), t.get("name")), f"Suspicious scheduled task: {full}",
            "high", f"task {full} (state {t.get('state')}, author {t.get('author') or 'unknown'}) runs: {shown} "
                    f"({'; '.join(sorted(set(why)))})",
            "A scheduled task that launches encoded PowerShell or a binary from a user-writable folder is a common "
            "way to keep code running on a host.",
            params={"path": t.get("path") or "\\", "name": t.get("name")}, fix_ref="windows:hunt:disable_task"))
    return out


def _unquoted(path: str) -> bool:
    p = (path or "").strip()
    if not p or p.startswith('"'):
        return False
    exe = re.split(r"(?i)\.exe", p, maxsplit=1)[0]
    return " " in exe and not exe.lower().startswith(r"c:\windows")


def services(state: dict, opts: dict) -> list[HuntHit]:
    now = _now(state)
    installs = {}
    for e in _list(state.get("service_installs")):
        t = _parse_time(e.get("time"))
        if t is None or now - t <= RECENT:
            installs[str(e.get("service") or "").lower()] = e
    out = []
    for s in _list(state.get("services")):
        name = s.get("name") or ""
        path = str(s.get("path") or "")
        if str(s.get("start_type")) == "Disabled" and str(s.get("status")) != "Running":
            continue    # cannot start; the remediation for this check stops and disables the service
        strong = []
        if user_writable(path):
            strong.append("binary in a user-writable path")
        if _unquoted(path):
            strong.append("unquoted binary path with spaces")
        inst = installs.get(name.lower()) or installs.get(str(s.get("display") or "").lower())
        low = path.lower()
        # A recent install on its own is normal (updates, drivers) when the binary sits under Windows or
        # Program Files; it is reported only together with another indicator or from anywhere else.
        if inst and (strong or not ("\\windows\\" in low or "\\program files" in low)):
            why = [f"installed {inst.get('time')} (System event 7045)", *strong]
        else:
            why = strong
        if not why:
            continue
        out.append(HuntHit(
            "service", "T1543.003", _key(name), f"Suspicious service: {name}", "high",
            f"service {name} ({s.get('display')}) start {s.get('start_type')}, status {s.get('status')}, "
            f"account {s.get('account') or 'LocalSystem'}, binary {path!r}: {'; '.join(why)}",
            "A Windows service runs as SYSTEM at boot. A recently installed service, or one whose binary lives in a "
            "folder ordinary users can write to, is a high-confidence persistence indicator.",
            params={"name": name}, fix_ref="windows:hunt:disable_service"))
    return out


def listeners(state: dict, opts: dict) -> list[HuntHit]:
    expected = {int(p) for p in opts.get("expected_ports", [])} | WINDOWS_BASELINE_PORTS
    seen: dict[int, dict] = {}
    for l in _list(state.get("listeners")):
        try:
            port = int(l.get("port"))
        except (TypeError, ValueError):
            continue
        proc = str(l.get("process") or "").lower().removesuffix(".exe")
        if port in expected or (port in RPC_DYNAMIC and proc in RPC_PROCESSES):
            continue
        if str(l.get("address")) in ("127.0.0.1", "::1"):
            continue
        seen.setdefault(port, l)
    return [HuntHit(
        "listener", "T1571", _key(str(port)), f"Unexpected listening port tcp/{port}", "medium",
        f"tcp/{port} on {l.get('address')} owned by {l.get('process')} (pid {l.get('pid')}); "
        f"expected ports: {sorted(int(p) for p in opts.get('expected_ports', []))}",
        "A listener that is not on the host's expected port list can be a backdoor or a command-and-control "
        "channel on a non-standard port. Identify the owning program before closing it.",
        params={"port": port}) for port, l in sorted(seen.items())]


def wmi_subscriptions(state: dict, opts: dict) -> list[HuntHit]:
    out = []
    for w in _list(state.get("wmi")):
        name = str(w.get("consumer") or w.get("filter") or "subscription")
        out.append(HuntHit(
            "wmi_subscription", "T1546.003", _key(name), f"WMI event subscription: {name}", "high",
            f"filter {w.get('filter')!r} ({w.get('query')!r}) bound to {w.get('consumer_class')} {name!r}: "
            f"{str(w.get('command') or '')[:300]!r}",
            "Permanent WMI event subscriptions run code when an event fires and survive reboots. They are rare on "
            "workstations and are a known stealthy persistence mechanism.",
            params={"consumer": name}))
    return out


def hidden_accounts(state: dict, opts: dict) -> list[HuntHit]:
    out = []
    for h in _list(state.get("hidden_accounts")):
        if str(h.get("value")) not in ("0", "False", "false"):
            continue
        name = _short(h.get("name"))
        if name.lower() in _disabled_users(state):
            continue
        out.append(HuntHit(
            "hidden_account", "T1564.002", _key(name), f"Account hidden from the logon screen: {name}", "high",
            f"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\\{name} = 0",
            "Hiding a user from the sign-in screen is used to conceal attacker-created accounts.",
            params={"name": name}, fix_ref="windows:hunt:disable_account"))
    return out


def rdp_recent(state: dict, opts: dict) -> list[HuntHit]:
    rdp = state.get("rdp") or {}
    if not rdp.get("enabled"):
        return []
    t = _parse_time(rdp.get("key_last_write"))
    if not t or _now(state) - t > RECENT:
        return []
    return [HuntHit(
        "rdp_enabled", "T1021.001", "rdp", "Remote Desktop enabled recently", "medium",
        f"fDenyTSConnections = 0; Terminal Server key last written {rdp.get('key_last_write')}; "
        f"NLA (UserAuthentication) = {rdp.get('nla')}",
        "Remote Desktop was switched on within the last 30 days. Confirm the change was authorised; attackers "
        "enable RDP for interactive access.")]


def brute_force(state: dict, opts: dict) -> list[HuntHit]:
    events = sorted((t, e) for e in _list(state.get("failed_logons")) if (t := _parse_time(e.get("time"))))
    if len(events) < BRUTE_THRESHOLD:
        return []
    best, start, j = 0, None, 0
    for i in range(len(events)):
        while events[i][0] - events[j][0] > BRUTE_WINDOW:
            j += 1
        if i - j + 1 > best:
            best, start = i - j + 1, events[j][0]
    if best < BRUTE_THRESHOLD:
        return []
    users = sorted({str(e.get("user")) for _, e in events})[:10]
    ips = sorted({str(e.get("ip")) for _, e in events if e.get("ip")})[:10]
    return [HuntHit(
        "failed_logons", "T1110", "burst", f"Burst of failed logons ({best} in 5 minutes)", "medium",
        f"{best} Security 4625 events within 5 minutes starting {start.isoformat()}; {len(events)} in 24 h; "
        f"accounts {users}; sources {ips}",
        "Many failed logons in a short window indicate password guessing or spraying.")]


def defender_exclusions(state: dict, opts: dict) -> list[HuntHit]:
    ex = state.get("defender_exclusions") or {}
    allowed = {str(x).lower() for x in opts.get("expected_defender_exclusions", [])}
    out = []
    for kind in ("paths", "processes", "extensions"):
        for v in _list(ex.get(kind)):
            if str(v).lower() in allowed:
                continue
            out.append(HuntHit(
                "defender_exclusion", "T1562.001", _key(kind, str(v)), f"Microsoft Defender exclusion: {v}", "high",
                f"Defender {kind[:-1]} exclusion {v!r} is configured and not on the approved list",
                "An antivirus exclusion stops Defender scanning that location or program. Attackers add exclusions "
                "so their tools are not detected.", params={"kind": kind, "value": v}))
    return out


HUNTS = (rogue_admins, new_accounts, run_keys, scheduled_tasks, services, listeners, wmi_subscriptions,
         hidden_accounts, rdp_recent, brute_force, defender_exclusions)


def hits(state: dict, opts: dict) -> list[HuntHit]:
    out: list[HuntHit] = []
    for fn in HUNTS:
        out.extend(fn(state, opts))
    return out


def find_hit(state: dict, opts: dict, rule_id: str) -> HuntHit | None:
    for h in hits(state, opts):
        if h.rule_id == rule_id:
            return h
    return None


def evaluate(target, state: dict, *, collected_at: str | None = None, raw_ref: str | None = None) -> list:
    from cyberthunder.adapters.base import make_finding

    out = []
    for h in hits(state, target.options or {}):
        out.append(make_finding(
            target=target, source=SOURCE, rule_id=h.rule_id, title=h.title, severity=h.severity, status="open",
            description=h.description, evidence=h.evidence, references=[h.technique, *h.extra_refs],
            fix_ref=h.fix_ref, tags=["windows", "hunt", f"hunt:{h.check}", f"attack:{h.technique}"],
            raw_ref=raw_ref, collected_at=collected_at))
    return out
