"""Kubernetes cluster adapter.

Transports: 'kubeconfig' (KubectlTransport, a live cluster through target.options.kubeconfig),
'simulated' (in-memory cluster persisted under the state directory) and the generic 'fixture' replay.
Every command this adapter sends is a kubectl command; state-changing ones come only from a FixEntry
payload rendered for one validated object, or from the object saved before the change (rollback).
"""
from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Iterable

from cyberthunder.adapters.base import MODULES, Adapter, AssetFacts, Collected, register
from cyberthunder.findings.schema import Finding
from cyberthunder.remediation.library import FixEntry
from cyberthunder.remediation.models import (ApplyResult, BeforeState, HealthCheck, HealthResult, RollbackResult,
                                             VerifyResult)

from . import checks, fixes, hunt, k3s, scope
from .kubectl import (KubectlTransport, ObjRef, heredoc, ref_from_finding, render, split_commands,
                      strip_server_fields)
from .simulated import SimulatedClusterTransport

log = logging.getLogger(__name__)

DEMO_TARGET_ID = "sim-k8s-01"
CONFIGZ = "kubectl get --raw /api/v1/nodes/{node}/proxy/configz"


def _settings_state_dir(settings) -> Path:
    if settings is None:
        from cyberthunder.config import Settings
        settings = Settings.from_env()
    return Path(settings.state_dir)


def _json(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


@register
class KubernetesAdapter(Adapter):
    asset_type = "kubernetes"
    display_name = "Kubernetes cluster"
    transports = ("fixture",)
    own_transports = ("kubeconfig", "simulated")

    # -- transports / simulation ------------------------------------------------------------
    @staticmethod
    def simulated_state_path(target, settings=None) -> Path:
        return _settings_state_dir(settings) / "simulated" / f"{target.id}.json"

    def make_transport(self, target, settings=None):
        namespaces = self._namespace_scope(target, None)
        if target.transport == "simulated":
            return SimulatedClusterTransport(self.simulated_state_path(target, settings))
        if target.transport == "kubeconfig":
            kc = (target.options or {}).get("kubeconfig")
            if not kc:
                raise ValueError(f"target {target.id}: options.kubeconfig is required for the kubeconfig transport")
            transport = KubectlTransport(kc, context=(target.options or {}).get("context"),
                                        kubectl=(target.options or {}).get("kubectl", "kubectl"),
                                        namespaces=list(namespaces) if namespaces is not None else None)
            connection = (str(kc), transport.context, transport.kubectl)
            identity = (target.id, target.transport, target.in_scope)

            def guard_namespace():
                try:
                    current = scope.namespace_scope(target.options)
                except ValueError:
                    raise PermissionError("namespace selection invalid; reconnect using current permissions") from None
                if current != namespaces or transport.namespace_scope != namespaces:
                    raise PermissionError("namespace selection changed; reconnect using current permissions")
                if namespaces is not None:
                    options = target.options
                    selected = (str(options.get("kubeconfig")), options.get("context"), options.get("kubectl", "kubectl"))
                    if ((target.id, target.transport, target.in_scope) != identity or selected != connection
                            or (transport.kubeconfig, transport.context, transport.kubectl) != connection):
                        raise PermissionError("namespace connection changed; reconnect using current permissions")
            transport.namespace_guard = guard_namespace
            return transport
        return None

    def demo_targets(self):
        from cyberthunder.inventory.targets import Target
        return [Target(id=DEMO_TARGET_ID, name="k3s-01 (simulated)", asset_type="kubernetes", transport="simulated",
                       simulated=True, sudo=False, tags=["demo", "kubernetes"],
                       options={"allowed_registries": ["registry.local", "docker.io/library"]},
                       notes="Simulated k3s cluster seeded to match range/answer_key/kubernetes.json")]

    def reset_simulated(self, target, settings=None) -> bool:
        self._require_mutable(target, None)
        if not target.simulated and target.transport != "simulated":
            return False
        SimulatedClusterTransport(self.simulated_state_path(target, settings)).reset()
        return True

    # -- discovery / collection ---------------------------------------------------------------
    def discover(self, target, transport) -> AssetFacts:
        namespaces = self._namespace_scope(target, transport)
        if namespaces is not None:
            return self._namespace_facts(target, scope.collection_coverage(namespaces))
        ver = _json(transport.run("kubectl version -o json").stdout) or {}
        nodes = _json(transport.run("kubectl get nodes -o json").stdout) or {}
        return self._facts(target, ver, nodes)

    @staticmethod
    def _namespace_scope(target, transport):
        namespaces = scope.namespace_scope(target.options)
        if namespaces is not None and target.transport not in {"kubeconfig", "fixture"}:
            raise ValueError("namespace collection requires kubeconfig or fixture transport")
        if isinstance(transport, KubectlTransport) and transport.namespace_scope != namespaces:
            raise PermissionError("target and transport namespace selections differ")
        return namespaces

    @staticmethod
    def _namespace_facts(target, coverage):
        return AssetFacts(hostname=target.name, os_name="Kubernetes", model="Namespace collection; nodes unavailable",
                          extra={"node_count": None, "nodes_ready": None, "nodes": None,
                                 scope.SCOPE_KEY: coverage})

    @staticmethod
    def _require_mutable(target, transport, evidence=None):
        namespaces = scope.namespace_scope(target.options)
        provenance = getattr(evidence, "collection_provenance", None) or {}
        if (namespaces is not None or getattr(transport, "namespace_scope", None) is not None
                or scope.SCOPE_KEY in provenance or "k8s:namespace-read-only" in getattr(evidence, "tags", [])):
            raise PermissionError(scope.READ_ONLY)

    @staticmethod
    def _facts(target, ver: dict, nodes: dict) -> AssetFacts:
        sv = (ver or {}).get("serverVersion") or {}
        items = (nodes or {}).get("items", [])
        ready = sum(1 for n in items if _node_ready(n))
        node_info = (items[0].get("status", {}).get("nodeInfo", {}) if items else {})
        return AssetFacts(hostname=target.name, os_name="Kubernetes", os_version=sv.get("gitVersion"),
                          model=f"{len(items)} node(s)",
                          extra={"server_version": sv.get("gitVersion"), "node_count": len(items), "nodes_ready": ready,
                                 "nodes": [n["metadata"]["name"] for n in items],
                                 "node_os": node_info.get("osImage"), "runtime": node_info.get("containerRuntimeVersion")})

    def collect(self, target, transport, workdir: Path, *, modules: Iterable[str] = MODULES,
                rule_filter: list[str] | None = None) -> Collected:
        namespaces = self._namespace_scope(target, transport)
        workdir = Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        col = Collected(target_id=target.id, asset_type=self.asset_type, workdir=str(workdir),
                        modules=[m for m in modules if m in ("check", "hunt")], rule_filter=rule_filter)
        if namespaces is not None:
            scope.collect_lists(col, transport, namespaces)
            col.facts = self._namespace_facts(target, col.raw[scope.SCOPE_KEY])
            col.raw.update(server_version=None, node_count=None)
            return col
        for name, cmd in checks.ARTIFACTS.items():
            r = transport.run(cmd)
            if not r.ok:
                col.errors.append(f"{cmd}: exit {r.exit_code}: {(r.stderr or r.stdout).strip()[:200]}")
                continue
            document = _json(r.stdout)
            if not isinstance(document, dict):
                col.errors.append(f"{cmd}: output is not JSON")
                continue
            if name != "version":
                if not isinstance(document.get("items"), list) or any(not isinstance(item, dict) for item in document["items"]):
                    col.errors.append(f"{cmd}: output is not a Kubernetes object list")
                    continue
                metadata = document.get("metadata") or {}
                if isinstance(metadata, dict) and metadata.get("continue"):
                    col.errors.append(f"{cmd}: object list is incomplete (continuation token present)")
            p = workdir / f"{name}.json"
            p.write_text(r.stdout, encoding="utf-8")
            col.artifacts[name] = str(p)
        data = checks.KubeData(col)
        # kubelet configuration per node (live clusters; not every API server allows the node proxy)
        for node in data.items("nodes"):
            name = node["metadata"]["name"]
            try:
                ObjRef(None, "node", name)
            except ValueError:
                continue
            r = transport.run(CONFIGZ.format(node=name))
            if r.ok and _json(r.stdout) is not None:
                p = workdir / f"configz_{name}.json"
                p.write_text(r.stdout, encoding="utf-8")
                col.artifacts[f"configz_{name}"] = str(p)
        node_id = (target.options or {}).get("node_target")
        if "k3d_cluster" in (target.options or {}):
            from . import k3d
            try:
                col.raw[checks.K3S_FLAGS] = {"servers": k3d.collect(target, data)}
            except Exception as e:  # unavailable input never becomes passing defaults
                col.errors.append(f"k3d configuration collection unavailable: {e}")
        elif node_id:
            self._collect_k3s_node(target, str(node_id), data, col,
                                   factory=getattr(transport, "secondary_transport", None))
        col.facts = self._facts(target, data.doc("version") or {}, data.doc("nodes") or {})
        col.raw["server_version"] = col.facts.os_version
        col.raw["node_count"] = col.facts.extra.get("node_count")
        return col

    def node_transport(self, node_id: str, factory=None):
        """(node target, transport) for the k3s server node named by options.node_target. The node must be an
        in-scope linux target. Verified sessions must use the parent's guarded secondary factory."""
        if factory is not None:
            if not callable(factory):
                raise PermissionError("a guarded secondary transport factory is required")
            return factory(node_id)
        try:
            from cyberthunder.control.principal import current_principal
        except ModuleNotFoundError as error:
            # Legacy development checkouts may not include the identity module.
            # An import failure inside an installed identity module is never a fallback.
            if error.name != "cyberthunder.control.principal":
                raise
            principal = None
        else:
            principal = current_principal()
        if principal is not None and getattr(principal, "verified", False):
            raise PermissionError("verified node collection requires a guarded secondary transport factory")
        from cyberthunder.config import Settings
        from cyberthunder.inventory.targets import Inventory
        from cyberthunder.store import StateStore
        from cyberthunder.transport.base import make_transport
        settings = Settings.from_env()
        node = Inventory.load(StateStore(settings.state_dir).targets).assert_in_scope(node_id)
        if node.asset_type != "linux":
            raise ValueError(f"node_target {node_id} is a {node.asset_type} target, not linux")
        return node, make_transport(node, settings)

    def _collect_k3s_node(self, target, node_id: str, data: checks.KubeData, col: Collected, *, factory=None) -> None:
        """Read the k3s control-plane flags from the server node (see k3s.py). Only the parsed component
        flags are kept; the raw config file (which may hold the join token) is never written out."""
        try:
            node, nt = self.node_transport(node_id, factory=factory)
        except PermissionError:
            raise
        except Exception as e:  # noqa: BLE001  unknown target or transport setup failure
            col.errors.append(f"node_target {node_id}: {e}")
            return
        denied = False
        try:
            if node.id != node_id or node.asset_type != "linux" or node.in_scope is not True:
                raise PermissionError("secondary transport must select the requested in-scope Linux target")
            self._read_k3s_node(target, node_id, node, nt, data, col)
        except PermissionError:
            denied = True
            raise
        finally:
            try:
                nt.close()
            except Exception:
                if not denied:
                    raise

    def _read_k3s_node(self, target, node_id, node, nt, data, col):
        """Read and parse the node through the already-authorized transport."""
        cfg = nt.run(k3s.READ_CONFIG, sudo=bool(getattr(node, "sudo", True)))
        unit = nt.run(k3s.READ_EXECSTART)
        env = nt.run(k3s.READ_ENVIRONMENT)
        if not cfg.ok:
            col.errors.append(f"node_target {node_id}: configuration read exit {cfg.exit_code}: "
                              "configuration files unavailable")
        if not unit.ok:
            col.errors.append(f"node_target {node_id}: {k3s.READ_EXECSTART}: exit {unit.exit_code}")
        if not env.ok or env.stdout.strip():
            col.errors.append(f"node_target {node_id}: service environment or environment files require review")
            return
        if not cfg.ok or not unit.ok:
            return
        try:
            flags = k3s.effective_flags(None, unit.stdout, files=k3s.config_bundle(cfg.stdout))
        except ValueError as e:
            col.errors.append(f"node_target {node_id}: {e}")
            return
        flags["node"] = (target.options or {}).get("node_name") or _node_for(data, node) or node_id
        flags["node_target"] = node_id
        col.raw[checks.K3S_FLAGS] = flags

    # -- detection ---------------------------------------------------------------------------------
    def check(self, target, collected: Collected) -> list[Finding]:
        findings = checks.run_checks(target, collected)
        return _filter(scope.annotate(fixes.point_at_applicable_fix(findings), collected), collected.rule_filter)

    def hunt(self, target, collected: Collected) -> list[Finding]:
        findings = hunt.run_hunt(target, collected)
        if scope.SCOPE_KEY in collected.raw:
            findings.append(checks.namespace_coverage_finding(target, collected, source="hunt"))
        return _filter(scope.annotate(fixes.point_at_applicable_fix(findings), collected), collected.rule_filter)

    # -- remediation -------------------------------------------------------------------------------
    def fixes(self) -> list[FixEntry]:
        return fixes.kubernetes_fixes() + [FixEntry(
            fix_ref="k8s:runbook:namespace-read-only", title="Review namespace collection with the resource owner",
            asset_type="kubernetes", applies_to=[], kind="runbook", rollback_kind="manual", reversible=False,
            steps=[scope.READ_ONLY, "Review findings and unavailable inputs with the namespace owner.",
                   "Arrange separately authorized changes and collect fresh evidence afterwards."],
            rollback_steps=["No automated changes are performed in namespace collection mode."],
            verify={"rule_ids": ["k8s:coverage:namespace"]},
            citations=["CCI-000366"], source="kubernetes", notes=scope.READ_ONLY)]

    @staticmethod
    def _meta(fix: FixEntry) -> fixes.FixMeta | None:
        if not fixes.META:
            fixes.kubernetes_fixes()
        return fixes.META.get(fix.fix_ref)

    def _object_ref(self, fix: FixEntry, finding: Finding) -> tuple[ObjRef, ObjRef]:
        """(object named by the finding, object captured and restored on rollback)."""
        meta = self._meta(fix)
        if meta is None:
            raise ValueError(f"{fix.fix_ref} is not a Kubernetes manifest fix")
        ref = ref_from_finding(finding)
        if ref.kind not in meta.kinds:
            raise ValueError(f"{fix.fix_ref} applies to {', '.join(sorted(meta.kinds))}, not {ref.kind} "
                             f"({ref.key()}); use the runbook for this object")
        restore = meta.rollback_object(ref) if meta.rollback_object else ObjRef(ref.namespace, ref.kind, ref.name)
        return ref, restore

    def capture_before_state(self, target, transport, fix: FixEntry, finding: Finding, dest: Path) -> BeforeState:
        self._require_mutable(target, transport, finding)
        # Reject before returning a snapshot: the engine must not attempt automatic rollback for a
        # blocked historical payload that never ran. Guard the stable ref, not the mutable payload.
        if reason := fixes.retired_reason(fix):
            raise ValueError(reason)
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        before = BeforeState(target_id=target.id, fix_ref=fix.fix_ref, dir=str(dest))
        if fix.kind == "runbook":
            before.notes = "runbook: nothing is changed by the tool, nothing captured"
            return before
        ref, restore = self._object_ref(fix, finding)
        before.extra["object_ref"] = ref.to_str()
        before.extra["restore_ref"] = restore.to_str()
        for name, template in (fix.before_state.get("commands") or {}).items():
            cmd = render(template, ref)
            r = transport.run(cmd)
            fname = f"{name}.json"
            (dest / fname).write_text(r.stdout if r.ok else "", encoding="utf-8")
            before.commands[name] = fname
            if name == "object":
                obj = _json(r.stdout) if r.ok else None
                before.extra["existed"] = obj is not None
                if obj is not None:
                    clean = strip_server_fields(obj)
                    before.extra["object"] = clean
                    (dest / "object.clean.json").write_text(json.dumps(clean, indent=2), encoding="utf-8")
                elif "NotFound" not in (r.stderr or "") and "not found" not in (r.stderr or ""):
                    raise RuntimeError(f"could not read {restore.key()} before the change: {r.stderr.strip()[:200]}")
        before.notes = f"saved {restore.key()} ({'present' if before.extra.get('existed') else 'absent'})"
        return before

    def apply(self, target, transport, fix: FixEntry, finding: Finding, before: BeforeState) -> ApplyResult:
        self._require_mutable(target, transport, finding)
        if reason := fixes.retired_reason(fix):
            return ApplyResult(ok=False, changed=False, output=reason)
        if fix.kind == "runbook":
            return ApplyResult(ok=False, changed=False,
                               output="Runbook fix: the tool does not change the cluster. The operator performs these "
                                      "steps, then re-runs the scan:\n" + fix.preview_text(),
                               details={"runbook": True, "steps": list(fix.steps)})
        if fix.kind != "manifest":
            return ApplyResult(ok=False, changed=False, output=f"unsupported fix kind {fix.kind!r} for kubernetes")
        try:
            ref, _ = self._object_ref(fix, finding)
            commands = split_commands(render(fix.payload, ref))
        except ValueError as e:
            return ApplyResult(ok=False, changed=False, output=str(e))
        outputs, ran = [], []
        for cmd in commands:
            if not cmd.startswith("kubectl "):
                return ApplyResult(ok=False, changed=bool(ran), output=f"refused non-kubectl payload line: {cmd[:80]!r}",
                                   details={"ran": ran})
            r = transport.run(cmd, timeout=240)
            ran.append(cmd)
            outputs.append(f"$ {cmd.splitlines()[0]}\n{r.stdout}{r.stderr}")
            if not r.ok:
                return ApplyResult(ok=False, changed=len(ran) > 1, output="\n".join(outputs),
                                   details={"ran": ran, "exit_code": r.exit_code, "object": ref.to_str()})
        return ApplyResult(ok=True, changed=True, output="\n".join(outputs), details={"ran": ran, "object": ref.to_str()})

    def _redetect(self, target, transport, expected_ref: ObjRef | None = None) -> tuple[list[Finding], list[str]]:
        with tempfile.TemporaryDirectory(prefix="ct-k8s-verify-") as tmp:
            col = self.collect(target, transport, Path(tmp))
            if expected_ref is not None:
                # The preliminary object GET and collection are separate reads. A disappearing object
                # or container must not turn an unevaluated rule into a passing configuration check.
                data = checks.KubeData(col)
                present = any(item.get("metadata", {}).get("name") == expected_ref.name
                              and item.get("metadata", {}).get("namespace") == expected_ref.namespace
                              for item in data.items(expected_ref.plural))
                if not present:
                    col.errors.append(f"original object {expected_ref.key()} is absent from the verification collection")
                elif expected_ref.container:
                    containers = [c for workload in checks.workloads(data)
                                  if workload.ref.key() == expected_ref.key()
                                  for c in checks.containers_of(workload.pod_spec)]
                    if not any(c.get("name") == expected_ref.container for c in containers):
                        col.errors.append(f"original container {expected_ref.to_str()} is absent from the verification collection")
            found = self.run_detection(target, col)
            return found, list(col.errors)

    def verify(self, target, transport, fix: FixEntry, finding: Finding) -> VerifyResult:
        self._require_mutable(target, transport, finding)
        if fixes.retired_reason(fix) or fix.fix_ref in fixes.REVIEW_FIXES:
            return VerifyResult(ok=False, rule_passed=None, health=HealthResult(ok=False),
                                evidence="Owner investigation and service validation required. Containment or object "
                                         "absence does not prove remediation; application health was not assessed.",
                                details={"manual_review": True, "application_health": "not assessed"})
        health = self.health_check(target, transport)
        try:
            ref = ref_from_finding(finding)
        except ValueError:
            return VerifyResult(ok=False, rule_passed=None, health=health,
                                evidence="Cannot identify the original object for verification.")
        present = transport.run(ObjRef(ref.namespace, ref.kind, ref.name).get_command())
        if not present.ok or not _json(present.stdout):
            return VerifyResult(ok=False, rule_passed=None, health=health,
                                evidence="Original object is absent or unreadable; disappearance does not prove "
                                         "remediation or application health.",
                                details={"application_health": "not assessed"})
        found, errors = self._redetect(target, transport, ref)
        still = [f for f in found if f.rule_id == finding.rule_id and f.is_open]
        unreviewed = [f for f in found if f.rule_id == finding.rule_id and not f.is_open]
        if errors:
            rule_passed = None
            evidence = "could not re-collect: " + "; ".join(errors[:3])
        elif unreviewed:
            rule_passed = None
            evidence = "The original rule was not evaluated as an open finding; review its current status manually."
        else:
            rule_passed = not still
            evidence = (f"{finding.rule_id} no longer detected" if rule_passed
                        else f"still detected: {still[0].evidence}")
        return VerifyResult(ok=bool(rule_passed) and health.ok, rule_passed=rule_passed, health=health,
                            evidence=evidence + "; configuration check only, application health not assessed",
                            details={"rescan_findings": len(found), "errors": errors[:5],
                                     "application_health": "not assessed"})

    def health_check(self, target, transport) -> HealthResult:
        if self._namespace_scope(target, transport) is not None:
            return HealthResult(ok=False, checks=[HealthCheck("cluster_health", False,
                                "Cluster and application health unavailable in namespace collection mode")])
        res: list[HealthCheck] = []
        v = transport.run("kubectl version -o json")
        ver = _json(v.stdout) if v.ok else None
        sv = (ver or {}).get("serverVersion", {}).get("gitVersion")
        res.append(HealthCheck("apiserver", bool(sv), f"server {sv}" if sv else (v.stderr or "no answer").strip()[:200]))
        n = transport.run("kubectl get nodes -o json")
        nodes = (_json(n.stdout) or {}).get("items", []) if n.ok else []
        not_ready = [x["metadata"]["name"] for x in nodes if not _node_ready(x)]
        res.append(HealthCheck("nodes_ready", bool(nodes) and not not_ready,
                               f"{len(nodes) - len(not_ready)}/{len(nodes)} Ready" + (f"; not ready: {', '.join(not_ready)}" if not_ready else "")))
        p = transport.run("kubectl get pods -n kube-system -o json")
        pods = (_json(p.stdout) or {}).get("items", []) if p.ok else []
        bad = [x["metadata"]["name"] for x in pods if _pod_unhealthy(x)]
        res.append(HealthCheck("kube_system_pods", p.ok and not bad,
                               (f"{len(pods)} pods, unhealthy: {', '.join(bad)}" if bad else f"{len(pods)} pods healthy")
                               if p.ok else (p.stderr or "no answer").strip()[:200]))
        return HealthResult(ok=all(c.ok for c in res), checks=res)

    def rollback(self, target, transport, fix: FixEntry, before: BeforeState) -> RollbackResult:
        self._require_mutable(target, transport)
        if fix.kind == "runbook":
            return RollbackResult(ok=True, output="Runbook fix: nothing was changed by the tool. Manual rollback:\n"
                                  + fix.rollback_plan_text(), details={"runbook": True})
        if fixes.retired_reason(fix) and not before.extra.get("existed"):
            return RollbackResult(ok=False, output="Retired deletion fix has no previously existing object to restore; "
                                  "rollback will not delete a current object.")
        restore_s = before.extra.get("restore_ref")
        if not restore_s:
            return RollbackResult(ok=False, output="before-state has no saved object reference; cannot roll back")
        restore = ObjRef.parse(restore_s)
        obj = before.extra.get("object")
        if obj is None and before.extra.get("existed"):
            p = Path(before.dir) / "object.clean.json"
            obj = json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
        outputs: list[str] = []
        if before.extra.get("existed"):
            if obj is None:
                return RollbackResult(ok=False, output=f"saved copy of {restore.key()} is missing")
            body = json.dumps(obj, indent=2)
            exists = transport.run(restore.get_command()).ok
            cmd = heredoc("kubectl replace -f -" if exists else "kubectl apply -f -", body)
        else:
            ns = f" -n {restore.namespace}" if restore.namespace else ""
            cmd = f"kubectl delete {restore.kind} {restore.name}{ns} --ignore-not-found"
        r = transport.run(cmd, timeout=240)
        outputs.append(f"$ {cmd.splitlines()[0]}\n{r.stdout}{r.stderr}")
        if not r.ok:
            return RollbackResult(ok=False, output="\n".join(outputs), details={"object": restore.to_str()})
        meta = self._meta(fix)
        if meta and meta.rollout and restore.kind == "deployment" and before.extra.get("existed"):
            rc = f"kubectl rollout status deployment/{restore.name} -n {restore.namespace} --timeout=180s"
            r2 = transport.run(rc, timeout=240)
            outputs.append(f"$ {rc}\n{r2.stdout}{r2.stderr}")
            if not r2.ok:
                return RollbackResult(ok=False, output="\n".join(outputs), details={"object": restore.to_str()})
        return RollbackResult(ok=True, output="\n".join(outputs) + "\n" + fixes.RECOVERY_LIMITS,
                              details={"object": restore.to_str(), "application_health": "not assessed"})


def _filter(findings: list[Finding], rule_filter: list[str] | None) -> list[Finding]:
    if not rule_filter:
        return findings
    keys = set(rule_filter)
    return [f for f in findings if f.rule_id in keys or f.rule_version in keys or any(r.id in keys for r in f.references)]


def _node_for(data: checks.KubeData, node_target) -> str | None:
    """The cluster node name matching the node target's name, hostname or address."""
    names = {str(x).lower() for x in (getattr(node_target, "name", None), getattr(node_target, "id", None),
                                      getattr(node_target, "host", None), getattr(node_target, "address", None)) if x}
    for n in data.items("nodes"):
        md = n.get("metadata", {})
        cand = {str(md.get("name", "")).lower(), str((md.get("labels") or {}).get("kubernetes.io/hostname", "")).lower()}
        cand |= {str(a.get("address", "")).lower() for a in (n.get("status") or {}).get("addresses", []) or []}
        if names & (cand - {""}):
            return md.get("name")
    return None


def _node_ready(node: dict) -> bool:
    return any(c.get("type") == "Ready" and c.get("status") == "True"
               for c in node.get("status", {}).get("conditions", []))


def _pod_unhealthy(pod: dict) -> bool:
    st = pod.get("status", {})
    if st.get("phase") in ("Failed", "Unknown"):
        return True
    for cs in st.get("containerStatuses", []) or []:
        reason = ((cs.get("state") or {}).get("waiting") or {}).get("reason", "")
        term = ((cs.get("state") or {}).get("terminated") or {}).get("reason", "")
        if reason in ("CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerError") or term == "Error":
            return True
    return False
