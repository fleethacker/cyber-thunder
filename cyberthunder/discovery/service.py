"""DiscoveryService: sweep the configured scopes, reconcile what answered against the inventory, and let a
named operator accept candidates into it.

Guardrails, in code order:
  * scopes are saved by a human with a reason and audited (discovery.scopes); quick, full and passive
    sweeps run only inside saved scopes, and public space needs allow_public plus a reason
  * the kill switch is checked before the first scope, between scopes and before the extra sources
  * only fixed commands run (nmap option table, show commands, Get-ADComputer, Get-VM, vmrun list);
    addresses on an nmap command line come from validated scopes or from nmap's own ping sweep
  * switches, clusters, directories and hypervisors are only asked when they are in-scope inventory targets
  * nothing reaches the inventory except through accept(), which refuses machine actors and empty
    reasons and is audited as inventory.add (and scope.change when the new target is in scope)

State lives under <state_dir>/discovery/: scopes.json, assets.json, ignored.json, runs/<id>.json.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Callable, Iterable

from cyberthunder.adapters.base import make_finding
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.findings.schema import Finding, utcnow
from cyberthunder.inventory.targets import ASSET_TYPES, TRANSPORTS, Target

from . import applicability
from .classify import apply_classification
from .models import RUN_MODES, DiscoveredAsset, DiscoveryRun, DiscoveryScope, asset_id_for
from .oui import tag_virtual
from .simulated import DEMO_SCOPE, SimulatedSweep
from .sources import active_directory, hypervisor, kube, neighbors, network_gear, nmap

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext
    from cyberthunder.transport.base import Transport

log = logging.getLogger(__name__)

MACHINE_ACTORS = frozenset({"agent", "llm", "system"})
DEFAULT_TRANSPORT = {"linux": "ssh", "windows": "winrm", "cisco_ios": "ssh", "kubernetes": "kubeconfig",
                     "containers": "ssh"}
# management port to record on the new target, by transport, in order of preference
TRANSPORT_PORTS = {"ssh": (22,), "winrm": (5986, 5985), "kubeconfig": (6443,)}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def require_human(actor: str | None) -> str:
    """The actor for a human-only decision: refuses empty and machine identities."""
    a = (actor or "").strip()
    if not a:
        raise PermissionError("an operator identity is required")
    if a.lower() in MACHINE_ACTORS or a.lower().startswith(("agent:", "llm:", "system:")):
        raise PermissionError(f"actor {a!r} is reserved for the machine; a named operator must decide this")
    return a


def _reason(reason: str | None) -> str:
    r = (reason or "").strip()
    if not r:
        raise ValueError("a reason is required")
    return r


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s[:48] or "asset"


def target_address(t: Target) -> str | None:
    addr = t.address or (t.options or {}).get("address")
    try:
        return str(ipaddress.ip_address(str(addr).strip())) if addr else None
    except ValueError:
        return None


class DiscoveryService:
    def __init__(self, ctx: "AppContext"):
        self.ctx = ctx
        self.dir = Path(ctx.store.root) / "discovery"
        (self.dir / "runs").mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._threads: dict[str, threading.Thread] = {}
        # the transport that runs nmap when no scope names a scanner_target; replaceable for tests
        self.local_transport_factory: Callable[[], "Transport"] = self._default_local_transport

    # -- files ---------------------------------------------------------------------------------
    @property
    def scopes_file(self) -> Path: return self.dir / "scopes.json"
    @property
    def assets_file(self) -> Path: return self.dir / "assets.json"
    @property
    def ignored_file(self) -> Path: return self.dir / "ignored.json"

    def _run_file(self, run_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9_.\-]+", run_id or ""):
            raise KeyError(f"unknown discovery run {run_id!r}")
        return self.dir / "runs" / f"{run_id}.json"

    def _read(self, path: Path, default):
        return self.ctx.store.read_json(path, default)

    def _write(self, path: Path, data) -> None:
        self.ctx.store.write_json(path, data)

    def _load_assets(self) -> dict[str, DiscoveredAsset]:
        raw = self._read(self.assets_file, {}) or {}
        return {k: DiscoveredAsset.from_dict(v) for k, v in raw.items()}

    def _save_assets(self, assets: dict[str, DiscoveredAsset]) -> None:
        self._write(self.assets_file, {k: a.to_dict() for k, a in assets.items()})

    def _ignored(self) -> dict[str, dict]:
        return self._read(self.ignored_file, {}) or {}

    # -- scopes --------------------------------------------------------------------------------
    def scopes(self) -> list[DiscoveryScope]:
        return [DiscoveryScope.from_dict(d) for d in (self._read(self.scopes_file, []) or [])]

    def set_scopes(self, scopes: Iterable, actor: str, reason: str) -> list[DiscoveryScope]:
        actor, reason = require_human(actor), _reason(reason)
        new: list[DiscoveryScope] = []
        for s in scopes:
            sc = s if isinstance(s, DiscoveryScope) else DiscoveryScope.from_dict(s)
            sc.added_by = sc.added_by or actor
            sc.reason = (sc.reason or "").strip() or reason
            sc.validate()
            if sc.scanner_target:
                t = self.ctx.inventory.get(sc.scanner_target)      # KeyError for an unknown target
                if not t.in_scope:
                    raise ValueError(f"scanner target {t.id} is out of scope")
            if all(x.cidr != sc.cidr for x in new):
                new.append(sc)
        with self._lock:
            before = [s.to_dict() for s in self.scopes()]
            self._write(self.scopes_file, [s.to_dict() for s in new])
        self.ctx.audit.append("discovery.scopes", actor, {
            "before": [s["cidr"] for s in before], "after": [s.cidr for s in new],
            "allow_public": [s.cidr for s in new if s.allow_public], "reason": reason})
        return new

    def _sweep_scopes(self, scopes, mode: str) -> list[DiscoveryScope]:
        saved = self.scopes()
        if scopes is None:
            chosen = saved or ([DiscoveryScope(cidr=DEMO_SCOPE, reason="simulated enclave")]
                               if mode == "simulated" else [])
        else:
            chosen = [s if isinstance(s, DiscoveryScope) else DiscoveryScope.from_dict(s) for s in scopes]
            if mode != "simulated":
                out = []
                for s in chosen:
                    cover = next((x for x in saved if x.covers(s)), None)
                    if cover is None:
                        raise ValueError(f"{s.cidr} is not inside a saved discovery scope; add it with a reason first")
                    out.append(DiscoveryScope(cidr=s.cidr, allow_public=cover.allow_public, added_by=cover.added_by,
                                              reason=cover.reason, scanner_target=s.scanner_target or cover.scanner_target))
                chosen = out
        if not chosen:
            raise ValueError("no discovery scopes saved; add one (CIDR and reason) before sweeping")
        for s in chosen:
            s.validate()
        return chosen

    # -- sweeps --------------------------------------------------------------------------------
    def sweep(self, scopes=None, mode: str = "quick", actor: str = "operator",
              background: bool = True) -> DiscoveryRun:
        if mode not in RUN_MODES:
            raise ValueError(f"unknown mode {mode!r}; expected one of {RUN_MODES}")
        actor = (actor or "").strip() or "operator"
        chosen = self._sweep_scopes(scopes, mode)
        run = DiscoveryRun(id=self.ctx.store.new_id("disc-"), mode=mode, scopes=[s.cidr for s in chosen],
                           requested_by=actor)
        self.ctx.audit.append("discovery.start", actor, {"run": run.id, "mode": mode, "scopes": run.scopes},
                              subject=run.id)
        try:
            self.ctx.killswitch.guard("discovery.sweep", actor)
        except KillSwitchEngaged as e:
            self._stopped(run, actor, str(e))
            raise
        self._save_run(run)
        if not background:
            self._execute(run, chosen, actor, raise_stop=True)
            return run
        th = threading.Thread(target=self._execute, args=(run, chosen, actor), name=f"discovery-{run.id}", daemon=True)
        self._threads[run.id] = th
        th.start()
        return run

    def join(self, run_id: str, timeout: float | None = None) -> DiscoveryRun:
        th = self._threads.get(run_id)
        if th is not None:
            th.join(timeout)
        return self.get_run(run_id)

    def _stopped(self, run: DiscoveryRun, actor: str, why: str) -> None:
        run.status, run.finished_at = "stopped", utcnow()
        run.errors.append(why)
        self._save_run(run)
        self.ctx.audit.append("discovery.finish", actor, {"run": run.id, "status": "stopped", **run.counts(),
                                                          "errors": run.errors[-3:]}, outcome="blocked", subject=run.id)

    def _execute(self, run: DiscoveryRun, scopes: list[DiscoveryScope], actor: str, raise_stop: bool = False) -> None:
        try:
            observed, baseline = self._collect(run, scopes, actor)
            self._finish(run, scopes, observed, baseline, actor)
        except KillSwitchEngaged as e:
            self._stopped(run, actor, str(e))
            if raise_stop:
                raise
        except Exception as e:  # noqa: BLE001 - a background run must always end with a recorded status
            log.exception("discovery run %s failed", run.id)
            run.status, run.finished_at = "failed", utcnow()
            run.errors.append(f"{type(e).__name__}: {e}")
            self._save_run(run)
            self.ctx.audit.append("discovery.finish", actor, {"run": run.id, "status": "failed", **run.counts(),
                                                              "errors": run.errors[-3:]}, outcome="error", subject=run.id)
            if raise_stop:
                raise

    def _collect(self, run: DiscoveryRun, scopes: list[DiscoveryScope], actor: str):
        """Gather raw observations from every source. Returns (assets, baseline ports or None)."""
        observed: list[DiscoveredAsset] = []
        baseline: dict[str, set[str]] | None = None
        sim = SimulatedSweep(self.ctx.inventory.all()) if run.mode == "simulated" else None
        if sim is not None:
            baseline = sim.baseline
        for scope in scopes:
            self.ctx.killswitch.guard("discovery.sweep", actor)
            if sim is not None:
                got = [a for a in sim.assets() if scope.contains(a.address)]
            elif run.mode == "passive":
                got = self._passive(scope, run)
            else:
                got = self._nmap(scope, run)
            observed.extend(got)
        if sim is None:
            self.ctx.killswitch.guard("discovery.sweep", actor)
            observed.extend(self._inventory_sources(scopes, run))
        return observed, baseline

    # -- sources -------------------------------------------------------------------------------
    @staticmethod
    def _default_local_transport() -> "Transport":
        from cyberthunder.transport.local import LocalTransport
        return LocalTransport()

    def _scanner(self, scope: DiscoveryScope) -> tuple["Transport", str, bool]:
        """(transport, nmap executable, privileged) for this scope."""
        if scope.scanner_target:
            t = self.ctx.inventory.assert_in_scope(scope.scanner_target)
            return self.ctx.transport_for(t), "nmap", bool(t.sudo)
        # -O needs raw sockets: only when this process already runs as root (never escalates locally)
        privileged = sys.platform != "win32" and getattr(os, "geteuid", lambda: 1)() == 0
        return self.local_transport_factory(), nmap.find_nmap() or "nmap", privileged

    def _nmap(self, scope: DiscoveryScope, run: DiscoveryRun) -> list[DiscoveredAsset]:
        transport, exe, privileged = self._scanner(scope)
        try:
            ping = nmap.run_nmap(transport, nmap.build_ping_command([scope], nmap=exe))
            hosts = [h for h in nmap.live_hosts(ping) if scope.contains(h)]
            if not hosts:
                return []
            argv = nmap.build_command([scope], run.mode, privileged, hosts=hosts, nmap=exe)
            xml = nmap.run_nmap(transport, argv, sudo=privileged and bool(scope.scanner_target))
            return [a for a in nmap.parse_xml(xml) if scope.contains(a.address)]
        except (nmap.NmapError, ValueError) as e:
            run.errors.append(f"nmap {scope.cidr}: {e}")
            return []
        except Exception as e:  # noqa: BLE001 - transport failures are recorded, not fatal
            run.errors.append(f"nmap {scope.cidr}: {type(e).__name__}: {e}")
            return []
        finally:
            self._close(transport)

    def _passive(self, scope: DiscoveryScope, run: DiscoveryRun) -> list[DiscoveredAsset]:
        transport, _, _ = self._scanner(scope)
        powershell = getattr(transport, "shell", None) == "powershell"
        got: list[DiscoveredAsset] = []
        try:
            cmds = [neighbors.NEIGHBOR_COMMANDS["powershell"]] if powershell else \
                [neighbors.NEIGHBOR_COMMANDS["posix"], neighbors.NEIGHBOR_COMMANDS["posix_fallback"]]
            for cmd in cmds:
                r = transport.run(cmd, timeout=60)
                if r.ok and r.stdout.strip():
                    got.extend(neighbors.parse_neighbors(r.stdout))
                    break
            else:
                run.errors.append(f"passive {scope.cidr}: no neighbor table could be read")
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts" if powershell else "/etc/hosts"
            for label, reader, parser in (
                    ("hosts file", lambda: transport.read_file(hosts_path).decode("utf-8", "replace"),
                     neighbors.parse_hosts_file),
                    ("known_hosts", lambda: self._known_hosts(transport, powershell), neighbors.parse_known_hosts)):
                try:
                    got.extend(parser(reader() or ""))
                except Exception as e:  # noqa: BLE001 - a missing file is normal
                    run.errors.append(f"passive {scope.cidr}: {label}: {e}")
        except Exception as e:  # noqa: BLE001
            run.errors.append(f"passive {scope.cidr}: {type(e).__name__}: {e}")
        finally:
            self._close(transport)
        return [a for a in got if scope.contains(a.address)]

    @staticmethod
    def _known_hosts(transport: "Transport", powershell: bool) -> str:
        cmd = "Get-Content -Raw $HOME\\.ssh\\known_hosts" if powershell else "cat ~/.ssh/known_hosts"
        r = transport.run(cmd, timeout=30)
        if not r.ok:
            raise FileNotFoundError((r.stderr or "known_hosts not readable").strip()[:200])
        return r.stdout

    def _inventory_sources(self, scopes: list[DiscoveryScope], run: DiscoveryRun) -> list[DiscoveredAsset]:
        """Switch tables, cluster nodes, directory and hypervisor listings from in-scope inventory targets."""
        got: list[DiscoveredAsset] = []
        for t in self.ctx.inventory.all():
            if not t.in_scope:
                continue
            o = t.options or {}
            jobs: list[tuple[str, Callable[["Transport"], list[DiscoveredAsset]]]] = []
            if t.asset_type == "cisco_ios":
                jobs.append(("network gear", lambda tr, t=t: self._gear(tr, t, run)))
            if t.asset_type == "kubernetes":
                jobs.append(("kubernetes", lambda tr: kube.parse_nodes(tr.check_output(kube.KUBE_COMMAND, timeout=60))))
            if t.asset_type == "windows" and o.get("directory_source") is True:
                jobs.append(("active directory", lambda tr: active_directory.parse_ad_computers(
                    tr.check_output(active_directory.AD_COMMAND, timeout=120))))
            if o.get("hypervisor") == "hyperv":
                jobs.append(("hyper-v", lambda tr, t=t: hypervisor.parse_hyperv_vms(
                    tr.check_output(hypervisor.HYPERV_COMMAND, timeout=120), host=t.name)))
            if o.get("hypervisor") == "vmware":
                jobs.append(("vmware", lambda tr, t=t: self._vmware(tr, t, run)))
            if not jobs:
                continue
            try:
                transport = self.ctx.transport_for(t)
            except Exception as e:  # noqa: BLE001
                run.errors.append(f"{t.id}: no transport: {e}")
                continue
            try:
                for label, job in jobs:
                    try:
                        for a in job(transport):
                            a.facts.setdefault("reported_by", t.id)
                            got.append(a)
                    except Exception as e:  # noqa: BLE001 - one source failing must not hide the rest
                        run.errors.append(f"{label} via {t.id}: {e}")
            finally:
                self._close(transport)
        # devices on the enclave only: anything a source reports outside the swept scopes is dropped,
        # except powered-off VMs, which have no address and are tied to a hypervisor already in scope
        return [a for a in got if any(s.contains(a.address) for s in scopes) or (not a.address and a.facts.get("vm_name"))]

    @staticmethod
    def _gear(transport: "Transport", t: Target, run: DiscoveryRun) -> list[DiscoveredAsset]:
        outputs: dict[str, str] = {}
        for key, cmd in network_gear.GEAR_COMMANDS.items():
            try:
                r = transport.run(cmd, timeout=60)
            except Exception as e:  # noqa: BLE001
                run.errors.append(f"{t.id}: {cmd}: {e}")
                continue
            if r.ok:
                outputs[key] = r.stdout
            else:
                run.errors.append(f"{t.id}: {cmd}: exit {r.exit_code} {(r.stderr or '').strip()[:120]}")
        return network_gear.assets_from_gear(outputs, seen_by=t.id)

    @staticmethod
    def _vmware(transport: "Transport", t: Target, run: DiscoveryRun) -> list[DiscoveredAsset]:
        assets, errors = hypervisor.assets_from_vmware(transport.check_output(hypervisor.VMRUN_LIST, timeout=60),
                                                       transport.read_file, host=t.name)
        run.errors.extend(f"{t.id}: {e}" for e in errors)
        return assets

    @staticmethod
    def _close(transport) -> None:
        try:
            transport.close()
        except Exception:  # noqa: BLE001
            pass

    # -- reconcile -----------------------------------------------------------------------------
    @staticmethod
    def merge_observations(observed: Iterable[DiscoveredAsset]) -> list[DiscoveredAsset]:
        """One asset per device: observations sharing a MAC or an address are folded together."""
        out: list[DiscoveredAsset] = []
        for a in observed:
            hit = next((x for x in out if (a.mac and x.mac == a.mac) or (a.address and x.address == a.address)), None)
            if hit is None:
                out.append(a)
                continue
            hit.merge(a)
            if hit.mac or hit.address:
                hit.id = asset_id_for(hit.mac, hit.address)
        return out

    def reconcile(self, observed: Iterable[DiscoveredAsset], scopes: list[DiscoveryScope],
                  baseline: dict[str, set[str]] | None = None,
                  previous: dict[str, DiscoveredAsset] | None = None) -> tuple[list[DiscoveredAsset], dict]:
        """Classify and compare against the inventory and the previous sweep. Returns (assets, counts)."""
        previous = self._load_assets() if previous is None else previous
        ignored = self._ignored()
        targets = self.ctx.inventory.all()
        by_addr = {a: t for t in targets if (a := target_address(t))}
        prev_by_addr = {p.address: p for p in previous.values() if p.address}
        seen = self.merge_observations(observed)
        counts = {"hosts_seen": len(seen), "new": 0, "known": 0, "changed": 0, "missing": 0}
        out: list[DiscoveredAsset] = []
        for a in seen:
            apply_classification(a)
            tag_virtual(a)
            prev = previous.get(a.id) or (prev_by_addr.get(a.address) if a.address else None)
            if prev is not None:
                a.first_seen = prev.first_seen
            a.last_seen = utcnow()
            a.changes = []
            t = by_addr.get(a.address) if a.address else None
            if t is None and prev is not None and prev.inventory_target_id:
                t = next((x for x in targets if x.id == prev.inventory_target_id), None)
            if t is not None:
                a.status, a.inventory_target_id = "known", t.id
                counts["known"] += 1
                if a.asset_type_guess not in ("unknown", t.asset_type):
                    a.changes.append({"kind": "type_changed", "inventory": t.asset_type, "observed": a.asset_type_guess,
                                      "detail": f"inventory says {t.asset_type}, evidence says {a.asset_type_guess} "
                                                f"({a.confidence:.2f})"})
            else:
                a.inventory_target_id = None
                a.status = "ignored" if a.id in ignored else "new"
                if a.status == "new":
                    counts["new"] += 1
            before = baseline.get(a.address) if baseline is not None and a.address in baseline else \
                (set(prev.port_keys) if prev is not None and prev.open_ports else None)
            if before is not None and a.open_ports:
                opened, closed = sorted(a.port_keys - before), sorted(before - a.port_keys)
                if opened:
                    a.changes.append({"kind": "new_listener", "ports": opened,
                                      "detail": "listening since the previous sweep: " + ", ".join(
                                          p.label() for p in a.open_ports if p.key in opened)})
                if closed:
                    a.changes.append({"kind": "closed_port", "ports": closed,
                                      "detail": "no longer listening: " + ", ".join(closed)})
            if a.status == "known" and any(c["kind"] in ("type_changed", "new_listener") for c in a.changes):
                counts["changed"] += 1
            out.append(a)
        seen_addrs = {a.address for a in out if a.address}
        seen_targets = {a.inventory_target_id for a in out if a.inventory_target_id}
        for t in targets:
            addr = target_address(t)
            if not addr or addr in seen_addrs or t.id in seen_targets or not any(s.contains(addr) for s in scopes):
                continue
            prev = previous.get(asset_id_for(None, addr))
            m = DiscoveredAsset(address=addr, hostname=t.name, asset_type_guess=t.asset_type, status="missing",
                                inventory_target_id=t.id, sources=["inventory"],
                                first_seen=prev.first_seen if prev else utcnow(),
                                last_seen=prev.last_seen if prev and prev.status != "missing" else utcnow())
            m.id = asset_id_for(None, addr)
            m.evidence.append(f"inventory target {t.id} at {addr} did not answer this sweep")
            m.changes.append({"kind": "missing", "detail": f"{t.id} not seen inside {', '.join(s.cidr for s in scopes)}"})
            counts["missing"] += 1
            out.append(m)
        return out, counts

    def _finish(self, run: DiscoveryRun, scopes, observed, baseline, actor: str) -> None:
        with self._lock:
            previous = self._load_assets()
            assets, counts = self.reconcile(observed, scopes, baseline, previous)
            for a in assets:
                previous[a.id] = a
            self._save_assets(previous)
        for k, v in counts.items():
            setattr(run, k, v)
        run.asset_ids = [a.id for a in assets]
        run.status, run.finished_at = "finished", utcnow()
        self._save_run(run, assets)
        self.ctx.audit.append("discovery.finish", actor, {"run": run.id, "status": run.status, "mode": run.mode,
                                                          **counts, "errors": run.errors[:5]}, subject=run.id)

    # -- runs and assets -----------------------------------------------------------------------
    def _save_run(self, run: DiscoveryRun, assets: list[DiscoveredAsset] | None = None) -> None:
        data = run.to_dict()
        if assets is None:
            old = self._read(self._run_file(run.id), {}) or {}
            data["assets"] = old.get("assets", [])
        else:
            data["assets"] = [a.to_dict() for a in assets]
        with self._lock:
            self._write(self._run_file(run.id), data)

    def runs(self) -> list[DiscoveryRun]:
        out = [DiscoveryRun.from_dict(d) for d in
               (self._read(p, None) for p in (self.dir / "runs").glob("*.json")) if d]
        return sorted(out, key=lambda r: (r.started_at, r.id), reverse=True)

    def get_run(self, run_id: str) -> DiscoveryRun:
        d = self._read(self._run_file(run_id), None)
        if not d:
            raise KeyError(f"unknown discovery run {run_id!r}")
        return DiscoveryRun.from_dict(d)

    def run_assets(self, run_id: str) -> list[DiscoveredAsset]:
        d = self._read(self._run_file(run_id), None)
        if not d:
            raise KeyError(f"unknown discovery run {run_id!r}")
        return [DiscoveredAsset.from_dict(a) for a in d.get("assets", [])]

    def last_run(self) -> DiscoveryRun | None:
        runs = self.runs()
        return runs[0] if runs else None

    def list_assets(self, status: str | None = None) -> list[DiscoveredAsset]:
        def key(a: DiscoveredAsset):
            try:
                return (0, int(ipaddress.ip_address(a.address)))
            except ValueError:
                return (1, 0)
        out = [a for a in self._load_assets().values() if status is None or a.status == status]
        return sorted(out, key=lambda a: (key(a) if a.address else (2, 0), a.hostname or "", a.id))

    def get_asset(self, asset_id: str) -> DiscoveredAsset:
        a = self._load_assets().get(asset_id)
        if a is None:
            raise KeyError(f"unknown discovered asset {asset_id!r}")
        return a

    def counts(self) -> dict:
        out = {s: 0 for s in ("new", "known", "ignored", "missing")}
        for a in self._load_assets().values():
            out[a.status] = out.get(a.status, 0) + 1
        return out

    # -- decisions -----------------------------------------------------------------------------
    def accept(self, asset_id: str, actor: str, *, name: str | None = None, asset_type: str | None = None,
               transport: str | None = None, username: str | None = None, credential_ref: str | None = None,
               in_scope: bool, reason: str) -> Target:
        """Turn a discovered asset into an inventory target. The only path from discovery to the inventory."""
        actor, reason = require_human(actor), _reason(reason)
        if not isinstance(in_scope, bool):
            raise ValueError("in_scope must be decided explicitly (true or false)")
        self.ctx.killswitch.guard("discovery.accept", actor)
        with self._lock:
            assets = self._load_assets()
            a = assets.get(asset_id)
            if a is None:
                raise KeyError(f"unknown discovered asset {asset_id!r}")
            if a.status in ("known", "missing") and a.inventory_target_id:
                raise ValueError(f"asset {asset_id} is already in the inventory as {a.inventory_target_id}")
            typ = asset_type or a.asset_type_guess
            if typ not in ASSET_TYPES:
                raise ValueError(f"choose an asset type for {a.address or a.hostname or asset_id}; "
                                 f"expected one of {ASSET_TYPES}")
            kind = transport or DEFAULT_TRANSPORT[typ]
            if kind not in TRANSPORTS:
                raise ValueError(f"unknown transport {kind!r}; expected one of {TRANSPORTS}")
            label = (name or a.hostname or f"{typ}-{a.address or asset_id}").strip()
            tid, n = _slug(label), 2
            existing = {t.id for t in self.ctx.inventory.all()}
            while tid in existing:
                tid, n = f"{_slug(label)}-{n}", n + 1
            port = next((p for p in TRANSPORT_PORTS.get(kind, ()) if a.has_port(p)), None)
            options = {k: v for k, v in {"discovered_asset_id": a.id, "mac": a.mac, "vendor": a.vendor,
                                         "discovered_os": a.os_guess}.items() if v}
            # discovered_os, not os: an nmap guess is a range, and options.os is read as an operator hint
            if a.facts.get("virtual_platform"):
                options["virtual_platform"] = a.facts["virtual_platform"]
            target = Target(id=tid, name=label, asset_type=typ, transport=kind, address=a.address, port=port,
                            username=username or None, credential_ref=credential_ref or None, tags=["discovered"],
                            in_scope=in_scope, options=options,
                            notes=f"accepted from discovery by {actor}: {reason}")
            self.ctx.inventory.add(target)
            self.ctx.save_inventory(actor, "inventory.add", {
                "source": "discovery", "target": target.id,
                "asset": {"id": a.id, "address": a.address, "mac": a.mac, "vendor": a.vendor,
                          "type_guess": a.asset_type_guess, "confidence": a.confidence},
                "asset_type": typ, "in_scope": in_scope, "reason": reason})
            if in_scope:
                self.ctx.audit.append("scope.change", actor, {"target": target.id, "before": None, "after": True,
                                                              "reason": reason}, subject=target.id)
            a.status, a.inventory_target_id = "known", target.id
            assets[a.id] = a
            self._save_assets(assets)
            ignored = self._ignored()
            if ignored.pop(a.id, None) is not None:
                self._write(self.ignored_file, ignored)
        return target

    def ignore(self, asset_id: str, actor: str, reason: str) -> DiscoveredAsset:
        actor, reason = require_human(actor), _reason(reason)
        with self._lock:
            assets = self._load_assets()
            a = assets.get(asset_id)
            if a is None:
                raise KeyError(f"unknown discovered asset {asset_id!r}")
            if a.status == "known":
                raise ValueError(f"asset {asset_id} is in the inventory as {a.inventory_target_id}; remove it there")
            a.status = "ignored"
            assets[a.id] = a
            self._save_assets(assets)
            ignored = self._ignored()
            ignored[a.id] = {"by": actor, "at": utcnow(), "reason": reason, "address": a.address, "mac": a.mac}
            self._write(self.ignored_file, ignored)
        self.ctx.audit.append("discovery.ignore", actor, {"asset": a.id, "address": a.address, "mac": a.mac,
                                                          "reason": reason}, subject=a.id)
        return a

    # -- findings ------------------------------------------------------------------------------
    def _host(self, a: DiscoveredAsset):
        if a.inventory_target_id:
            try:
                return self.ctx.inventory.get(a.inventory_target_id)
            except KeyError:
                pass
        return SimpleNamespace(id=f"discovered:{a.address or a.mac or a.id}", asset_type="unknown")

    @staticmethod
    def _evidence(a: DiscoveredAsset, extra: str = "") -> str:
        parts = [a.summary(), f"type guess {a.asset_type_guess} ({a.confidence:.2f})",
                 f"sources {','.join(a.sources) or '-'}"]
        if a.notes:
            parts.append(f"notes {a.notes}")
        if extra:
            parts.append(extra)
        return "; ".join(parts)

    def findings(self, run_id: str | None = None) -> list[Finding]:
        if run_id is None:
            last = next((r for r in self.runs() if r.status == "finished"), None)
            if last is None:
                return []
            run_id = last.id
        assets = self.run_assets(run_id)
        current = self._load_assets()
        out: list[Finding] = []
        for a in assets:
            now = current.get(a.id)
            status = now.status if now is not None else a.status
            if status == "ignored":
                continue
            host = self._host(a)
            where = a.address or a.mac or a.hostname or a.id
            if status == "new":
                out.append(make_finding(
                    target=host, source="discovery", rule_id="discovery:unknown_asset", severity="high",
                    title=f"Unknown device on the enclave: {where}",
                    description=("A device answered inside a discovery scope but is not in the inventory. Until "
                                 "someone accounts for it, treat it as unauthorized hardware: find it, identify "
                                 "its owner, then accept it into the inventory or remove it from the network."),
                    evidence=self._evidence(a), references=["T1200", "T1046"], tags=["discovery"]))
            if a.facts.get("iot") and status in ("new", "known"):
                out.append(make_finding(
                    target=host, source="discovery", rule_id="discovery:consumer_device", severity="medium",
                    title=f"Consumer or IoT class device present: {where}",
                    description=("The evidence matches a printer or single-board computer. No adapter manages "
                                 "these and they often ship with telnet, default passwords and no patching."),
                    evidence=self._evidence(a), references=["T1200"], tags=["discovery"]))
            for c in a.changes:
                if c["kind"] == "type_changed" and status == "known":
                    out.append(make_finding(
                        target=host, source="discovery", rule_id="discovery:type_changed", severity="medium",
                        title=f"Asset type changed: {host.id} looks like {c['observed']}, inventory says {c['inventory']}",
                        description=("What answers at this address no longer matches its inventory entry. Either the "
                                     "inventory is stale or a different device has taken the address."),
                        evidence=self._evidence(a, c["detail"]), references=["T1036"], tags=["discovery"]))
                elif c["kind"] == "new_listener" and status == "known":
                    out.append(make_finding(
                        target=host, source="discovery", rule_id="discovery:new_listener", severity="medium",
                        title=f"New listener on {host.id}: {', '.join(c['ports'])}",
                        description=("A port is open now that was closed in the previous sweep. Confirm it belongs "
                                     "to an approved service; an unexpected listener is a common sign of a backdoor "
                                     "or an unapproved tool."),
                        evidence=self._evidence(a, c["detail"]), references=["T1571"], tags=["discovery"]))
            if status == "missing":
                out.append(make_finding(
                    target=host, source="discovery", rule_id="discovery:missing_asset", severity="low",
                    title=f"Inventory asset not seen: {host.id} ({a.address})",
                    description=("For information: this inventory target lies inside the swept scopes but did not "
                                 "answer. It may be powered off or moved; if it was retired, update the inventory "
                                 "so the baseline configuration record stays accurate."),
                    evidence=self._evidence(a), references=["CCI-000366"], tags=["discovery"]))
        out.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity.value, 9), f.host, f.rule_id))
        return out

    # -- applicability -------------------------------------------------------------------------
    def applicable(self, benchmark_id: str | None = None, title: str | None = None, product: str | None = None,
                   asset_type: str | None = None) -> list[dict]:
        hits = applicability.applicable_targets(self.ctx, benchmark_id, title, product)
        return [{"target": h.target.id, "name": h.target.name, "asset_type": h.target.asset_type, "rule": h.rule,
                 "basis": h.basis, "reason": h.reason}
                for h in hits if asset_type is None or h.target.asset_type == asset_type]


def service_for(ctx: "AppContext") -> DiscoveryService:
    """The context's discovery service, created once and cached on the context."""
    svc = getattr(ctx, "discovery", None)
    if svc is None:
        svc = DiscoveryService(ctx)
        try:
            ctx.discovery = svc
        except AttributeError:
            pass
    return svc
