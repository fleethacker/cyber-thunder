"""Native STIG checks and the merge with OpenSCAP results.

Each native check reads only collected command output (no network) and returns pass, fail or unknown with
the evidence it used. Identifiers come from stig_rules.json through fixes.NATIVE.

Merge with OpenSCAP, by STIG ID (Finding.rule_version):
  - only native result      -> the native finding (source "native", rule_id = STIG ID)
  - only OpenSCAP result    -> the OpenSCAP finding, with fix_ref set when the library has the SSG rule
  - both, same status       -> the OpenSCAP finding (its description and fix text are the richer ones),
                               native evidence appended
  - both, status disagrees  -> the OpenSCAP finding with the NATIVE status, and both results in evidence.
                               Native evidence is the effective runtime state (sshd -T, stat, systemctl), which
                               is what the operator verifies against after a fix.
A native check that could not run (unknown) never overrides OpenSCAP.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from cyberthunder.adapters.base import Collected, make_finding
from cyberthunder.findings.schema import Finding, Status
from cyberthunder.parsers.xccdf import parse_xccdf

from . import parse as P
from . import rules
from .fixes import NATIVE, NATIVE_BY_ID, NativeRule

log = logging.getLogger(__name__)

PASS, FAIL, UNKNOWN = "pass", "fail", "unknown"
Result = tuple[str, str]


def _need(c: Collected, name: str) -> str:
    text = P.out(c, name)
    if text is None:
        r = P.result(c, name)
        detail = f"exit {r.get('exit')}: {(r.get('err') or '').strip()[:200]}" if r else "not collected"
        raise _Missing(f"{name} unavailable ({detail})")
    return text


class _Missing(Exception):
    pass


# -- check implementations by family ------------------------------------------------------------
def _sshd(r: NativeRule, c: Collected) -> Result:
    eff = P.sshd_t(_need(c, "sshd_t"))
    key = r.params["keyword"].lower()
    want = r.params["value"].lower()
    got = eff.get(key)
    if got is None:
        return FAIL, f"sshd -T: {key} not reported (expected {want})"
    return (PASS if got.lower() == want else FAIL), f"sshd -T: {key} {got} (required: {want})"


def _file_mode(r: NativeRule, c: Collected) -> Result:
    st = P.stat_lines(_need(c, "stat_files"))
    path, maxmode = r.params["path"], int(r.params["mode"], 8)
    if path not in st:
        return UNKNOWN, f"stat: {path} not reported"
    mode, owner, grp = st[path]
    ok = (mode & ~maxmode) == 0
    return (PASS if ok else FAIL), f"{path} mode {mode:04o} owner {owner}:{grp} (required: {maxmode:04o} or less permissive)"


def _file_owner(r: NativeRule, c: Collected) -> Result:
    st = P.stat_lines(_need(c, "stat_files"))
    path, want = r.params["path"], r.params["owner"]
    if path not in st:
        return UNKNOWN, f"stat: {path} not reported"
    mode, owner, grp = st[path]
    return (PASS if owner == want else FAIL), f"{path} owner {owner}:{grp} mode {mode:04o} (required owner: {want})"


def _svc(c: Collected, unit: str) -> tuple[str, str]:
    st = P.svc_state(_need(c, "svc_state"))
    short = unit.removesuffix(".service")
    return st.get(short) or st.get(unit) or ("unknown", "unknown")


def _service_on(r: NativeRule, c: Collected) -> Result:
    unit = r.params["unit"]
    enabled, active = _svc(c, unit)
    ok = enabled == "enabled" and active == "active"
    return (PASS if ok else FAIL), f"systemctl: {unit} is-enabled={enabled} is-active={active} (required: enabled, active)"


def _unit_mask(r: NativeRule, c: Collected) -> Result:
    unit = r.params["unit"]
    enabled, active = _svc(c, unit)
    return (PASS if enabled == "masked" else FAIL), f"systemctl: {unit} is-enabled={enabled} (required: masked)"


def _selinux(r: NativeRule, c: Collected) -> Result:
    mode = _need(c, "getenforce").strip()
    return (PASS if mode.lower() == "enforcing" else FAIL), f"getenforce: {mode} (required: Enforcing)"


def _pkg_remove(r: NativeRule, c: Collected) -> Result:
    text = _need(c, "rpm_absent")
    pkg = r.params["package"]
    for line in text.splitlines():
        s = line.strip()
        if s == f"package {pkg} is not installed":
            return PASS, f"rpm -q: {s}"
        if s.startswith(pkg + "-") and not s.startswith("package "):
            return FAIL, f"rpm -q: {s} is installed"
    return UNKNOWN, f"rpm -q: no line for {pkg}"


def _login_defs(r: NativeRule, c: Collected) -> Result:
    d = P.kv_file(_need(c, "login_defs"))
    k, limit = r.params["key"], int(r.params["value"])
    v = d.get(k)
    if v is None or not v.strip().lstrip("-").isdigit():
        return FAIL, f"/etc/login.defs: {k} not set (required: 1..{limit})"
    n = int(v)
    return (PASS if 0 < n <= limit else FAIL), f"/etc/login.defs: {k} {n} (required: 1..{limit})"


def _sysctl(r: NativeRule, c: Collected) -> Result:
    v = _need(c, "aslr").strip()
    return (PASS if v == r.params["value"] else FAIL), f"sysctl {r.params['key']} = {v} (required: {r.params['value']})"


def _gpgcheck(r: NativeRule, c: Collected) -> Result:
    text = _need(c, "gpgcheck")
    bad, main_ok = [], False
    for line in text.splitlines():
        path, _, setting = line.partition(":")
        k, _, v = setting.replace(" ", "").partition("=")
        if k != "gpgcheck":
            continue
        if v not in ("1", "True", "true", "yes"):
            bad.append(f"{path}: {setting.strip()}")
        elif path.endswith("/etc/dnf/dnf.conf"):
            main_ok = True
    if bad:
        return FAIL, "gpgcheck disabled: " + "; ".join(bad)
    if not main_ok:
        return FAIL, "/etc/dnf/dnf.conf: gpgcheck=1 not set"
    return PASS, "gpgcheck=1 in /etc/dnf/dnf.conf and no repository disables it"


def _coredump(r: NativeRule, c: Collected) -> Result:
    vals = [line.split("=", 1)[1].strip() for line in _need(c, "coredump").splitlines() if "=" in line]
    if not vals:
        return FAIL, "coredump.conf: Storage not set (default is external; required: none)"
    return (PASS if vals[-1].lower() == "none" else FAIL), f"coredump.conf: Storage={vals[-1]} (required: none)"


def _dup_uid(r: NativeRule, c: Collected) -> Result:
    rows = P.passwd(_need(c, "passwd"))
    by_uid: dict[int, list[str]] = {}
    for row in rows:
        by_uid.setdefault(row["uid"], []).append(row["name"])
    dups = {u: n for u, n in by_uid.items() if len(n) > 1}
    if dups:
        return FAIL, "duplicate UIDs: " + "; ".join(f"uid {u}: {', '.join(n)}" for u, n in sorted(dups.items()))
    return PASS, f"{len(rows)} accounts, all UIDs unique"


def _ww_dirs(r: NativeRule, c: Collected) -> Result:
    lines = [ln.strip() for ln in _need(c, "ww_dirs").splitlines() if ln.strip()]
    if lines:
        return FAIL, "world-writable directories under /var/log: " + "; ".join(lines[:20])
    return PASS, "no world-writable directories under /var/log"


def _sudo_nopasswd(r: NativeRule, c: Collected) -> Result:
    files = P.dump(_need(c, "sudoers"))
    hits = []
    for path, content in files.items():
        for line in content.splitlines():
            s = line.strip()
            if s and not s.startswith("#") and "NOPASSWD" in s:
                hits.append(f"{path}: {s}")
    if hits:
        return FAIL, "NOPASSWD rules: " + "; ".join(hits[:10])
    return PASS, f"no NOPASSWD rules in {len(files)} sudoers file(s)"


FAMILY: dict[str, tuple[Callable[[NativeRule, Collected], Result], tuple[str, ...]]] = {
    "sshd": (_sshd, ("sshd_t",)),
    "file_mode": (_file_mode, ("stat_files",)),
    "file_owner": (_file_owner, ("stat_files",)),
    "service_on": (_service_on, ("svc_state",)),
    "unit_mask": (_unit_mask, ("svc_state",)),
    "selinux": (_selinux, ("getenforce",)),
    "pkg_remove": (_pkg_remove, ("rpm_absent",)),
    "login_defs": (_login_defs, ("login_defs",)),
    "sysctl": (_sysctl, ("aslr",)),
    "gpgcheck": (_gpgcheck, ("gpgcheck",)),
    "coredump": (_coredump, ("coredump",)),
    "runbook_dup_uid": (_dup_uid, ("passwd",)),
    "ww_dirs": (_ww_dirs, ("ww_dirs",)),
    "sudo_nopasswd": (_sudo_nopasswd, ("sudoers",)),
}


def needs(rule_id: str) -> tuple[str, ...]:
    r = NATIVE_BY_ID.get(rule_id)
    return FAMILY[r.family][1] if r else ()


def all_needs() -> set[str]:
    return {n for r in NATIVE for n in FAMILY[r.family][1]}


def _selected(rule_filter: list[str] | None) -> list[NativeRule]:
    if not rule_filter:
        return list(NATIVE)
    wanted = set(rule_filter)
    return [r for r in NATIVE if r.rule_id in wanted or (r.ssg and rules.SSG_PREFIX + r.ssg in wanted)]


def native_findings(target, c: Collected) -> list[Finding]:
    out = []
    for r in _selected(c.rule_filter):
        fn, _ = FAMILY[r.family]
        try:
            status, evidence = fn(r, c)
        except _Missing as e:
            status, evidence = UNKNOWN, f"could not check: {e}"
        meta = rules.rule(r.stig_id)
        out.append(make_finding(
            target=target, source="native", rule_id=r.rule_id, title=r.title, severity=r.severity,
            status={PASS: "not_a_finding", FAIL: "open", UNKNOWN: "not_reviewed"}[status],
            description=r.description or meta.get("check_summary", ""), evidence=evidence,
            references=[*meta.get("cci", []), *r.refs], fix_ref=r.fix_ref, rule_version=r.stig_id,
            group_id=meta.get("group_id"), benchmark=rules.BENCHMARK if r.stig_id else "Cyber Thunder Linux checks",
            benchmark_release=rules.RELEASE if r.stig_id else None, check_text=meta.get("check_summary"),
            fix_text=meta.get("fix_summary"), tags=["native"], collected_at=c.collected_at))
    return out


def oscap_findings(target, c: Collected) -> list[Finding]:
    out: list[Finding] = []
    for name in sorted(k for k in c.artifacts if k.startswith("oscap_results")):
        path = c.artifacts[name]
        try:
            parsed = parse_xccdf(path, host=target.id, source="openscap")
        except Exception as e:  # noqa: BLE001  a truncated results file must not hide the native checks
            c.errors.append(f"oscap results {Path(path).name}: {e}")
            continue
        for f in parsed.findings:
            f.asset_type = "linux"
            f.host = target.id
            f.id = Finding.make_id(f.host, f.source, f.rule_id)
            if f.rule_id.startswith(rules.SSG_PREFIX):
                ssg = f.rule_id[len(rules.SSG_PREFIX):]
                match = next((r for r in NATIVE if r.ssg == ssg), None)
                if match:
                    f.fix_ref = match.fix_ref
                    if not f.rule_version and match.stig_id:
                        f.rule_version = match.stig_id
            if c.rule_filter and f.rule_id not in c.rule_filter and f.rule_version not in c.rule_filter:
                continue
            out.append(f)
    return out


def merge(native: list[Finding], oscap: list[Finding]) -> list[Finding]:
    by_stig = {f.rule_version: f for f in oscap if f.rule_version}
    merged: list[Finding] = []
    used: set[str] = set()
    for n in native:
        o = by_stig.get(n.rule_version) if n.rule_version else None
        if o is None:
            merged.append(n)
            continue
        used.add(o.id)
        if n.status in (Status.OPEN, Status.NOT_A_FINDING) and n.status != o.status:
            o.evidence = (f"native check: {n.status.value} ({n.evidence}); "
                          f"openscap: {o.status.value} ({o.evidence or 'no message'}). Native status kept.")
            o.status = n.status
        elif n.evidence:
            o.evidence = f"{o.evidence + '; ' if o.evidence else ''}native check: {n.evidence}"
        o.fix_ref = o.fix_ref or n.fix_ref
        if "native-checked" not in o.tags:
            o.tags.append("native-checked")
        merged.append(o)
    merged.extend(f for f in oscap if f.id not in used)
    return merged


def run_checks(target, c: Collected) -> list[Finding]:
    return merge(native_findings(target, c), oscap_findings(target, c))
