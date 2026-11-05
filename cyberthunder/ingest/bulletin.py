"""IAVM / CVE bulletins and matching against collected package inventories.

A bulletin arrives as JSON over the link:

  {"id": "2026-A-0123", "title": "...", "severity": "high", "cves": ["CVE-2026-1234"],
   "affected": [{"package": "openssh*", "versions_below": "8.7p1-38.el9"},
                {"product": "Enterprise Linux", "versions_below": "9.4"},
                {"cpe": "cpe:/o:redhat:enterprise_linux:9"}],
   "source": "DISA IAVM", "published": "2026-11-03"}

Package specs match an installed package when the name equals or globs the spec and either no
versions_below is given or the installed EVR is older (RPM comparison rules). Bulletins usually state
fixed versions without an epoch while RHEL ships openssl, gnutls and friends with Epoch 1 or 2, so the
installed epoch is only compared when versions_below names one ("1:3.0.7-25.el9"); otherwise only
version-release is compared.

Product specs match on the target's os_name (and os_version when versions_below is given). CPE specs are
split into vendor, product and version: vendor:product is mapped through CPE_OS_NAMES to the os_name it
appears as (cpe:/o:canonical:ubuntu_linux -> "Ubuntu"), falling back to the product text, and a CPE
version must equal os_version or be its leading component (cpe ...:9 matches 9.4, not 8.10). Matching is
a pure function of the collected inventories the Scanner already wrote; nothing here touches a host.
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Mapping

from cyberthunder.adapters.base import make_finding
from cyberthunder.findings.schema import RE_IAVM, Finding, Severity

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.inventory.targets import Target
    from cyberthunder.store import StateStore


class BulletinError(ValueError):
    pass


@dataclass
class Bulletin:
    id: str
    title: str
    severity: str = "high"
    cves: list[str] = field(default_factory=list)
    affected: list[dict] = field(default_factory=list)
    source: str = ""
    published: str | None = None
    description: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def parse_bulletin(data: bytes | str | Mapping) -> Bulletin:
    d: Any = data
    if isinstance(d, (bytes, bytearray)):
        d = d.decode("utf-8-sig")
    if isinstance(d, str):
        try:
            d = json.loads(d)
        except json.JSONDecodeError as e:
            raise BulletinError(f"bulletin is not valid JSON: {e}") from None
    if not isinstance(d, Mapping):
        raise BulletinError("bulletin must be a JSON object")
    bid = str(d.get("id") or "").strip()
    if not bid:
        raise BulletinError("bulletin has no id")
    cves = [str(c).strip() for c in d.get("cves") or [] if str(c).strip()]
    if not RE_IAVM.fullmatch(bid) and not cves:
        # Locally numbered bulletins are accepted, but then the CVEs are the only citation we have.
        raise BulletinError(f"bulletin {bid!r} is not an IAVM id (YYYY-A-NNNN) and lists no CVEs to cite")
    affected = d.get("affected") or []
    if not isinstance(affected, list) or not all(isinstance(a, Mapping) for a in affected):
        raise BulletinError("affected must be a list of objects")
    for a in affected:
        if not any(a.get(k) for k in ("package", "product", "cpe")):
            raise BulletinError(f"affected entry needs package, product or cpe: {dict(a)}")
    return Bulletin(id=bid, title=str(d.get("title") or bid), severity=Severity.parse(d.get("severity")).value,
                    cves=cves, affected=[dict(a) for a in affected], source=str(d.get("source") or ""),
                    published=d.get("published"), description=str(d.get("description") or ""))


# -- RPM version comparison ---------------------------------------------------------------------

def _isdigit(c: str) -> bool:
    return "0" <= c <= "9"


def _isalpha(c: str) -> bool:
    return ("a" <= c <= "z") or ("A" <= c <= "Z")


def _isalnum(c: str) -> bool:
    return _isdigit(c) or _isalpha(c)


def rpmvercmp(a: str, b: str) -> int:
    """rpm's rpmvercmp(): compare one version or release string. Returns -1, 0 or 1.

    Alternating digit / letter segments, separators ignored; numeric segments compare as integers and beat
    alphabetic ones; '~' sorts before anything (pre-releases), '^' sorts after the base but before any
    further segment (post-release snapshots); if all segments match, the string with more left wins.
    """
    if a == b:
        return 0
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        while i < la and not _isalnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < lb and not _isalnum(b[j]) and b[j] not in "~^":
            j += 1
        ca = a[i] if i < la else ""
        cb = b[j] if j < lb else ""
        if ca == "~" or cb == "~":
            if ca != "~":
                return 1
            if cb != "~":
                return -1
            i, j = i + 1, j + 1
            continue
        if ca == "^" or cb == "^":
            if not ca:
                return -1
            if not cb:
                return 1
            if ca != "^":
                return 1
            if cb != "^":
                return -1
            i, j = i + 1, j + 1
            continue
        if not ca or not cb:
            break
        test = _isdigit if _isdigit(ca) else _isalpha
        isnum = test is _isdigit
        si, sj = i, j
        while i < la and test(a[i]):
            i += 1
        while j < lb and test(b[j]):
            j += 1
        s1, s2 = a[si:i], b[sj:j]
        if not s2:
            return 1 if isnum else -1
        if isnum:
            s1, s2 = s1.lstrip("0"), s2.lstrip("0")
            if len(s1) != len(s2):
                return 1 if len(s1) > len(s2) else -1
        if s1 != s2:
            return 1 if s1 > s2 else -1
    if i >= la and j >= lb:
        return 0
    return -1 if i >= la else 1


def split_evr(s: str) -> tuple[int, str, str | None]:
    """'2:1.0-3.el9' -> (2, '1.0', '3.el9'). Missing epoch is 0; missing release is None."""
    s = str(s).strip()
    epoch = 0
    if ":" in s:
        e, s = s.split(":", 1)
        epoch = int(e) if e.strip().isdigit() else 0
    version, _, release = s.partition("-")
    return epoch, version, (release or None)


def rpm_vercmp(a: str, b: str) -> int:
    """Compare full [epoch:]version[-release] strings. The release is only compared when both have one,
    so 'below 1.2' means every 1.1-x is affected and every 1.2-x is not."""
    ea, va, ra = split_evr(a)
    eb, vb, rb = split_evr(b)
    if ea != eb:
        return 1 if ea > eb else -1
    c = rpmvercmp(va, vb)
    if c or ra is None or rb is None:
        return c
    return rpmvercmp(ra, rb)


def is_older(installed_evr: str, below: str) -> bool:
    """True when installed_evr is older than below. The epoch only counts when below states one."""
    below = str(below).strip()
    if ":" not in below:
        installed_evr = split_evr_text(installed_evr)
    return rpm_vercmp(installed_evr, below) < 0


def split_evr_text(evr: str) -> str:
    """'1:3.0.7-24.el9' -> '3.0.7-24.el9' (the version-release part, epoch dropped)."""
    s = str(evr).strip()
    return s.split(":", 1)[1] if ":" in s else s


def package_evr(pkg: Mapping) -> str:
    epoch = str(pkg.get("epoch") or "").strip()
    v = str(pkg.get("version") or "")
    r = str(pkg.get("release") or "")
    evr = f"{v}-{r}" if r else v
    return f"{epoch}:{evr}" if epoch and epoch not in ("0", "(none)") else evr


# -- matching -------------------------------------------------------------------------------------

# vendor:product of an OS CPE -> the os_name substrings that release reports (lower case).
CPE_OS_NAMES: dict[tuple[str, str], tuple[str, ...]] = {
    ("canonical", "ubuntu_linux"): ("ubuntu",),
    ("redhat", "enterprise_linux"): ("red hat enterprise linux",),
    ("rocky", "rocky"): ("rocky linux",),
    ("rockylinux", "rocky_linux"): ("rocky linux",),
    ("almalinux", "almalinux"): ("almalinux",),
    ("oracle", "linux"): ("oracle linux",),
    ("debian", "debian_linux"): ("debian",),
    ("centos", "centos"): ("centos",),
    ("microsoft", "windows_server_2016"): ("windows server 2016",),
    ("microsoft", "windows_server_2019"): ("windows server 2019",),
    ("microsoft", "windows_server_2022"): ("windows server 2022",),
    ("microsoft", "windows_server_2025"): ("windows server 2025",),
    ("microsoft", "windows_10"): ("windows 10",),
    ("microsoft", "windows_11"): ("windows 11",),
}


def parse_cpe(cpe: str) -> tuple[str, str, str]:
    """(vendor, product, version) of a CPE 2.2 URI or 2.3 formatted string; '*' / '-' versions become ''."""
    # cpe:/o:redhat:enterprise_linux:9  or  cpe:2.3:o:redhat:enterprise_linux:9:*:...
    cpe = cpe.strip()
    parts = cpe.split(":")
    if cpe.startswith("cpe:2.3:"):
        parts = parts[1:]
    vendor = parts[2].lower() if len(parts) > 2 else ""
    product = parts[3].lower() if len(parts) > 3 else ""
    version = parts[4] if len(parts) > 4 else ""
    return vendor, product, ("" if version in ("*", "-") else version)


def _cpe_product(cpe: str) -> str:
    return parse_cpe(cpe)[1].replace("_", " ")


def _cpe_matches(cpe: str, os_name: str, os_version: str) -> bool:
    vendor, product, version = parse_cpe(cpe)
    if not product:
        return False
    names = CPE_OS_NAMES.get((vendor, product)) or (product.replace("_", " "),)
    if not any(n in os_name.lower() for n in names):
        return False
    if version:
        return os_version == version or os_version.startswith(version + ".")
    return True


def _facts(collected: Mapping) -> dict:
    f = collected.get("facts") or {}
    return f if isinstance(f, dict) else {}


def _target_for(target_id: str, collected: Mapping, targets: Mapping | None) -> "Target":
    from cyberthunder.inventory.targets import ASSET_TYPES, Target
    if targets and target_id in targets:
        return targets[target_id]
    at = collected.get("asset_type") if collected.get("asset_type") in ASSET_TYPES else "linux"
    return Target(id=target_id, name=target_id, asset_type=at, transport="fixture")


def _refs(bulletin: Bulletin) -> list[str]:
    return [*bulletin.cves, bulletin.id]


def match(bulletin: Bulletin, collected_by_target: Mapping[str, Mapping],
          targets: Mapping[str, "Target"] | None = None) -> list[Finding]:
    """Findings for every (target, affected package or product) the bulletin hits.

    collected_by_target maps target id -> Collected.to_dict() (raw.packages and facts are used).
    targets optionally maps target id -> inventory Target; otherwise a minimal Target is built."""
    out: list[Finding] = []
    for tid, col in collected_by_target.items():
        target = _target_for(tid, col, targets)
        packages = ((col.get("raw") or {}).get("packages")) or []
        facts = _facts(col)
        collected_at = col.get("collected_at")
        seen: set[str] = set()
        for spec in bulletin.affected:
            below = spec.get("versions_below")
            if spec.get("package"):
                pat = str(spec["package"])
                for pkg in packages:
                    name = str(pkg.get("name") or "")
                    if not name or not (name == pat or fnmatch.fnmatchcase(name, pat)):
                        continue
                    evr = package_evr(pkg)
                    if below and not is_older(evr, str(below)):
                        continue
                    if name in seen:
                        continue
                    seen.add(name)
                    out.append(_finding(bulletin, target, name, evr, below, pkg.get("arch"), collected_at))
            else:
                os_name = str(facts.get("os_name") or "")
                os_version = str(facts.get("os_version") or "")
                if spec.get("product"):
                    product = str(spec["product"]).strip()
                    if not product or product.lower() not in os_name.lower():
                        continue
                else:
                    cpe = str(spec.get("cpe") or "")
                    product = _cpe_product(cpe).strip()
                    if not product or not _cpe_matches(cpe, os_name, os_version):
                        continue
                if below and (not os_version or rpm_vercmp(os_version, str(below)) >= 0):
                    continue
                if product in seen:
                    continue
                seen.add(product)
                out.append(_finding(bulletin, target, product, f"{os_name} {os_version}".strip(), below, None,
                                    collected_at, os_level=True))
    return out


def _finding(bulletin: Bulletin, target: "Target", pkg: str, installed: str, below: str | None,
             arch: str | None, collected_at: str | None, os_level: bool = False) -> Finding:
    what = "operating system" if os_level else "package"
    fix = f"update {pkg} to >= {below}" if below else f"update {pkg} to the release named in {bulletin.id}"
    cites = ", ".join(_refs(bulletin))
    desc = (f"{bulletin.title}. {target.id} has {what} {pkg} {installed}"
            + (f" ({arch})" if arch else "")
            + (f", older than the fixed {below}" if below else ", which the bulletin lists as affected")
            + f". Source: {bulletin.source or 'bulletin'} {bulletin.id}; cites {cites}.")
    return make_finding(target=target, source="iavm", rule_id=f"iavm:{bulletin.id}:{pkg}", title=f"{bulletin.title} ({pkg})",
                        severity=bulletin.severity, description=desc, evidence=f"{pkg} {installed}".strip(),
                        references=_refs(bulletin), fix_text=fix, fix_ref=f"patch:{pkg}",
                        tags=["bulletin", f"pkg:{pkg}"], benchmark=bulletin.id, collected_at=collected_at)


# -- inventories on disk --------------------------------------------------------------------------

def latest_collected(store: "StateStore") -> dict[str, dict]:
    """Newest collected.json per target across all scan runs (runs ordered newest first)."""
    out: dict[str, dict] = {}
    seen_dirs: list[Path] = []
    for run in store.list_scan_runs():
        seen_dirs.append(store.scans_dir / run["id"])
    for d in sorted(store.scans_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if d.is_dir() and d not in seen_dirs:
            seen_dirs.append(d)
    for d in seen_dirs:
        raw = d / "raw"
        if not raw.is_dir():
            continue
        for p in sorted(raw.glob("*/collected.json")):
            tid = p.parent.name
            if tid in out:
                continue
            try:
                out[tid] = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
    return out


def bulletins_dir(store: "StateStore") -> Path:
    return store.ingest_dir / "bulletins"


def save_bulletin(store: "StateStore", bulletin: Bulletin, extra: dict | None = None) -> Path:
    from cyberthunder.ingest.delta import safe_name
    p = bulletins_dir(store) / f"{safe_name(bulletin.id)}.json"
    store.write_json(p, dict(bulletin.to_dict(), **(extra or {})))
    return p


def list_bulletins(store: "StateStore") -> list[dict]:
    out = [store.read_json(p) for p in store.list_json(bulletins_dir(store))]
    return sorted((d for d in out if d), key=lambda d: d.get("ingested_at", ""), reverse=True)


def affected_hosts(findings: Iterable[Finding]) -> list[str]:
    hosts: list[str] = []
    for f in findings:
        if f.host not in hosts:
            hosts.append(f.host)
    return hosts
