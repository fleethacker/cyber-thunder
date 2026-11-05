"""Survey the Kubernetes cluster this service runs in and build namespace risk profiles.

The scan path is deliberately read-only. Kubernetes data comes from `kubectl get ... -o json`; image
vulnerabilities come from `trivy image --format json`. OpenAI text generation is optional decoration: the
deterministic profile is always returned and stored even when the API key, network or model is unavailable.
"""
from __future__ import annotations

import json
import hashlib
import logging
import os
import subprocess
import time
import urllib.error
import urllib.request
from collections import defaultdict
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator

from cyberthunder.control.identity import normalize_actor, require_human
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.cluster.findings import (
    database_provenance, is_stale, mark_missing_sections, normalize_findings, parse_report,
)
from cyberthunder.findings.schema import Finding, summarize, utcnow
from cyberthunder.inventory.targets import Inventory, ScopeViolation, Target
from cyberthunder.scan import ScanRun, TargetScanResult

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext

log = logging.getLogger(__name__)

WORKLOAD_KINDS = (
    ("apps", "Deployment", "deployments"),
    ("apps", "StatefulSet", "statefulsets"),
    ("apps", "DaemonSet", "daemonsets"),
    ("batch", "CronJob", "cronjobs"),
    ("batch", "Job", "jobs"),
    ("core", "Pod", "pods"),
)
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEVERITY_WEIGHT = {"CRITICAL": 40.0, "HIGH": 15.0, "MEDIUM": 4.0, "LOW": 1.0, "UNKNOWN": 0.25}


@dataclass
class WorkloadRef:
    namespace: str
    kind: str
    name: str
    images: list[str] = field(default_factory=list)
    replicas: int | None = None
    labels: dict[str, str] = field(default_factory=dict)
    uid: str | None = None

    def key(self) -> str:
        return f"{self.namespace}/{self.kind}/{self.name}"

    def to_dict(self) -> dict:
        return asdict(self)


def _safe_name(text: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in text)[:180] or "image"


def _containers_from_pod_spec(spec: dict) -> list[dict]:
    return (list(spec.get("initContainers") or []) + list(spec.get("containers") or [])
            + list(spec.get("ephemeralContainers") or []))


def _pod_spec(obj: dict, kind: str) -> dict:
    spec = obj.get("spec") or {}
    if kind in ("Deployment", "StatefulSet", "DaemonSet"):
        return spec.get("template", {}).get("spec", {}) or {}
    if kind == "CronJob":
        return spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {}) or {}
    if kind == "Job":
        return spec.get("template", {}).get("spec", {}) or {}
    if kind == "Pod":
        return spec
    return {}


def _replicas(obj: dict, kind: str) -> int | None:
    spec = obj.get("spec") or {}
    status = obj.get("status") or {}
    if kind == "DaemonSet":
        return status.get("desiredNumberScheduled")
    if kind == "Pod":
        return 1
    if kind == "CronJob":
        return None
    return spec.get("replicas", 1)


def _image_vulns(report: dict) -> list[dict]:
    out: list[dict] = []
    for res in report.get("Results") or []:
        target = res.get("Target")
        for v in res.get("Vulnerabilities") or []:
            sev = str(v.get("Severity") or "UNKNOWN").upper()
            scores = []
            for cvss in (v.get("CVSS") or {}).values():
                if isinstance(cvss, dict):
                    for key in ("V3Score", "V40Score"):
                        try:
                            scores.append(float(cvss[key]))
                        except (KeyError, TypeError, ValueError):
                            pass
            out.append({
                "id": v.get("VulnerabilityID"),
                "package": v.get("PkgName"),
                "installed_version": v.get("InstalledVersion"),
                "fixed_version": v.get("FixedVersion"),
                "severity": sev if sev in SEVERITY_WEIGHT else "UNKNOWN",
                "cvss": max(scores) if scores else None,
                "status": v.get("Status"),
                "title": v.get("Title") or v.get("Description") or "",
                "target": target,
            })
    return out


class ClusterGuardError(ScopeViolation):
    """Authorization could not be checked; never recover this as a tool failure."""


@dataclass(frozen=True)
class _ClusterBinding:
    target_id: str
    kubeconfig: str
    context: str
    kubectl: str

    def argv(self) -> list[str]:
        return [self.kubectl, "--kubeconfig", self.kubeconfig, "--context", self.context]


class ClusterBaselineService:
    def __init__(self, ctx: "AppContext"):
        self.ctx = ctx
        self.root = Path(ctx.store.root) / "cluster"
        self.root.mkdir(parents=True, exist_ok=True)

    def _binding(self, target_id: str) -> _ClusterBinding:
        inventory_path = self.ctx.inventory.path
        if inventory_path is None:
            raise ClusterGuardError("cluster access requires a persisted inventory authorization source")
        # Reuse the inventory parser but read every time: a cached target or unchanged stat is not authority.
        persisted = Inventory._read(inventory_path).get(target_id)
        if persisted is None:
            raise ScopeViolation(f"target {target_id!r} is not in the persisted inventory")
        if persisted.get("in_scope") is not True:
            raise ScopeViolation(f"target {target_id!r} is not authorized in the persisted inventory")
        target = self.ctx.inventory.assert_in_scope(target_id)
        binding = self._target_binding(target)
        if binding != self._target_binding(Target.from_dict(persisted)):
            raise ScopeViolation(f"target {target_id!r} connection does not match its persisted authorization")
        return binding

    @staticmethod
    def _target_binding(target: Target) -> _ClusterBinding:
        target_id = target.id
        if target.in_scope is not True:
            raise ScopeViolation(f"target {target_id!r} is not explicitly in scope")
        if target.asset_type != "kubernetes" or target.transport != "kubeconfig" or target.simulated:
            raise ScopeViolation(f"target {target_id!r} must be a Kubernetes kubeconfig target")
        options = target.options
        values = [options.get("kubeconfig"), options.get("context"), options.get("kubectl", "kubectl")]
        if any(not isinstance(v, str) or not v.strip() for v in values):
            raise ScopeViolation(f"target {target_id!r} requires explicit kubeconfig, context and kubectl values")
        kubeconfig, context, kubectl = (v.strip() for v in values)
        return _ClusterBinding(target_id, str(Path(kubeconfig).expanduser().resolve()), context, kubectl)

    def _authorize(self, target_id: str, actor: str, action: str) -> _ClusterBinding:
        try:
            self.ctx.killswitch.guard(action, actor)
            return self._binding(target_id)
        except (ScopeViolation, KillSwitchEngaged):
            raise
        except Exception as exc:  # noqa: BLE001 - fail closed, including transient guard and parser failures
            # Parser/IO exceptions can carry inventory contents; only expose the failure type to audit/API.
            raise ClusterGuardError(f"cannot verify cluster authorization for target {target_id!r} "
                                    f"({type(exc).__name__}); refusing cluster access") from exc

    def _guard(self, binding: _ClusterBinding, actor: str) -> None:
        if self._authorize(binding.target_id, actor, f"cluster.access:{binding.target_id}") != binding:
            raise ScopeViolation(f"target {binding.target_id!r} connection changed during the cluster run; retry")

    @contextmanager
    def _operation(self, action: str, actor: str, target_id: str | None) -> Iterator[tuple[_ClusterBinding, dict]]:
        details = {"run_id": self.ctx.store.new_id("cluster-"), "source": "inventory",
                   "started_at": datetime.now(timezone.utc).isoformat(),
                   "target_id": target_id if target_id is not None else self.ctx.settings.bootstrap_cluster_target_id}
        started = False
        try:
            actor = require_human(actor)
            details["requested_by"] = actor
            binding = self._authorize(details["target_id"], actor, action)
            details.update(asdict(binding))
            self.ctx.audit.append(f"{action}.start", actor, details, subject=details["run_id"])
            started = True
            yield binding, details
        except (PermissionError, KillSwitchEngaged) as exc:
            self.ctx.audit.append(action, normalize_actor(actor) or "?", {**details, "reason": str(exc)},
                                  subject=details["run_id"],
                                  outcome="blocked" if started or isinstance(exc, KillSwitchEngaged) else "rejected")
            raise
        except Exception as exc:  # noqa: BLE001 - record failure, never turn it into a successful baseline
            self.ctx.audit.append(action, actor, {**details, "error": str(exc)},
                                  subject=details["run_id"], outcome="error")
            raise
        else:
            self.ctx.audit.append(action, actor, details, subject=details["run_id"],
                                  outcome="partial" if details.get("errors") else "ok")

    def _kubectl_json(self, binding: _ClusterBinding, actor: str, *args: str, timeout: int = 120) -> dict:
        self._guard(binding, actor)
        try:
            p = subprocess.run([*binding.argv(), *args, "-o", "json"], capture_output=True, text=True,
                               timeout=timeout, encoding="utf-8", errors="replace")
        finally:
            self._guard(binding, actor)
        if p.returncode != 0:
            raise RuntimeError((p.stderr or p.stdout or "kubectl failed").strip()[:500])
        doc = json.loads(p.stdout or "{}")
        if not isinstance(doc, dict) or not isinstance(doc.get("items"), list):
            raise RuntimeError("kubectl supplied no valid resource list")
        return doc

    def survey(self, *, actor: str, target_id: str | None = None) -> dict:
        with self._operation("cluster.survey", actor, target_id) as (binding, details):
            result = self._survey(binding, details["requested_by"])
            details.update(namespaces=len(result["namespaces"]), errors=len(result["errors"]))
            return {**result, "requested_by": details["requested_by"], "target": asdict(binding),
                    "id": details["run_id"]}

    def _survey(self, binding: _ClusterBinding, actor: str) -> dict:
        ns_doc = self._kubectl_json(binding, actor, "get", "namespaces")
        namespaces = []
        for item in ns_doc.get("items") or []:
            md = item.get("metadata") or {}
            namespaces.append({
                "name": md.get("name"),
                "labels": md.get("labels") or {},
                "phase": (item.get("status") or {}).get("phase"),
            })
        workloads: list[WorkloadRef] = []
        errors: list[str] = []
        for _api, kind, resource in WORKLOAD_KINDS:
            try:
                doc = self._kubectl_json(binding, actor, "get", resource, "-A")
            except (ScopeViolation, KillSwitchEngaged):
                raise
            except Exception as e:  # noqa: BLE001
                errors.append(f"{resource}: {e}")
                continue
            for item in doc.get("items") or []:
                if (not isinstance(item, dict) or not isinstance(item.get("metadata"), dict)
                        or not all(isinstance(item["metadata"].get(key), str) and item["metadata"][key]
                                   for key in ("namespace", "name"))):
                    errors.append(f"{resource}: workload identity is missing or malformed")
                    continue
                md = item.get("metadata") or {}
                spec = _pod_spec(item, kind)
                if (not isinstance(spec, dict) or not isinstance(spec.get("containers"), list)
                        or not spec["containers"]):
                    errors.append(f"{resource}: workload container inventory is unavailable")
                    continue
                containers = _containers_from_pod_spec(spec)
                if any(not isinstance(c, dict) or not isinstance(c.get("image"), str) or not c["image"]
                       for c in containers):
                    errors.append(f"{resource}: workload image identity is missing or malformed")
                    continue
                images = sorted({c.get("image") for c in _containers_from_pod_spec(spec) if c.get("image")})
                workloads.append(WorkloadRef(namespace=md.get("namespace") or "default", kind=kind,
                                             name=md.get("name") or "unknown", images=images,
                                             replicas=_replicas(item, kind), labels=md.get("labels") or {},
                                             uid=md.get("uid")))
        namespaces.sort(key=lambda n: n["name"] or "")
        workloads.sort(key=lambda w: (w.namespace, w.kind, w.name))
        self._guard(binding, actor)
        return {"surveyed_at": utcnow(), "namespaces": namespaces, "workloads": [w.to_dict() for w in workloads],
                "errors": errors}

    def scan(self, *, actor: str, target_id: str | None = None, use_openai: bool = False) -> dict:
        with self._operation("cluster.baseline", actor, target_id) as (binding, details):
            try:
                return self._baseline(binding, details, describe=use_openai)
            except (ScopeViolation, KillSwitchEngaged):
                raise
            except Exception as exc:
                # Keep the previous baseline API behavior for fatal collection failures, while
                # making failure visible in the persistent findings view. Never overwrite a run
                # already published if a later file write or optional presentation step failed.
                if self.ctx.store.load_scan_run(details["run_id"]) is None:
                    self._guard(binding, details["requested_by"])
                    error = f"Cluster vulnerability assessment failed ({type(exc).__name__})"
                    findings, _ = normalize_findings(binding.target_id, {"errors": [error]}, {}, None,
                                                     details["run_id"], target_binding=asdict(binding))
                    findings = [f for f in findings if f.rule_id.startswith("cluster-survey:")]
                    self.ctx.store.save_findings(details["run_id"], findings)
                    self._guard(binding, details["requested_by"])
                    self.ctx.store.save_scan_run(self._scan_run(binding, details, findings, status="error",
                                                               errors=[error], assessed=[], database={}))
                raise

    def _baseline(self, binding: _ClusterBinding, details: dict, *, describe: bool) -> dict:
        with ExitStack() as stack:
            self._guard(binding, details["requested_by"])
            snapshot, snapshot_error = None, None
            try:
                snapshot = stack.enter_context(self.ctx.vulnerabilities.scan_context())
                if (not isinstance(snapshot, dict) or not snapshot.get("cache_dir")
                        or not snapshot.get("generation") or snapshot.get("state") not in {"ready", "stale"}):
                    raise ValueError("invalid managed vulnerability snapshot")
            except (ScopeViolation, KillSwitchEngaged):
                raise
            except Exception as exc:  # noqa: BLE001 - missing/invalid managed data is never a clean scan
                snapshot = None
                snapshot_error = f"Managed vulnerability database unavailable ({type(exc).__name__})"
            self._guard(binding, details["requested_by"])
            return self._baseline_snapshot(binding, details, describe=describe, snapshot=snapshot,
                                           snapshot_error=snapshot_error)

    def _baseline_snapshot(self, binding: _ClusterBinding, details: dict, *, describe: bool,
                           snapshot: dict | None, snapshot_error: str | None) -> dict:
        actor = details["requested_by"]
        survey = self._survey(binding, actor)
        images = sorted({img for w in survey["workloads"] for img in w.get("images", [])})
        run_id = details["run_id"]
        run_dir = self.root / "baselines" / run_id
        self._guard(binding, actor)
        run_dir.mkdir(parents=True, exist_ok=True)
        image_reports: dict[str, dict] = {}
        errors: list[str] = list(survey.get("errors") or [])
        if snapshot_error:
            errors.append(snapshot_error)
        if snapshot and is_stale(snapshot):
            errors.append("Managed vulnerability database is stale; negative results cannot clear prior findings")
        for image in images:
            report, err = (self._scan_image(image, run_dir, binding, actor, snapshot=snapshot)
                           if snapshot else (None, snapshot_error or "Managed vulnerability database unavailable"))
            if err:
                errors.append(f"{image}: {err}")
            image_reports[image] = report or {"image": image, "vulnerabilities": [], "error": err,
                                             "complete": False, "failed": True}
            if snapshot and is_stale(snapshot):
                image_reports[image]["complete"] = False
        errors.extend(mark_missing_sections(self.ctx.store.current_findings(), binding.target_id, survey,
                                             image_reports, asdict(binding)))
        profiles = self._profiles(survey, image_reports)
        if describe:
            for profile in profiles:
                if profile.get("assessment_status") != "complete":
                    continue
                self._guard(binding, actor)
                try:
                    generated, err = self._openai_description(profile)
                finally:
                    self._guard(binding, actor)
                if generated:
                    profile["description"] = generated
                    profile["description_source"] = "openai"
                elif err:
                    profile.setdefault("notes", []).append(f"OpenAI summary unavailable: {err}")
        doc = {"id": run_id, "generated_at": utcnow(), "survey": survey, "images": image_reports,
               "namespaces": profiles, "errors": errors, "requested_by": actor, "target": asdict(binding),
               "status": "partial" if errors else "done", "database": database_provenance(snapshot)}
        findings, assessed = normalize_findings(binding.target_id, survey, image_reports, snapshot, run_id,
                                                target_binding=asdict(binding))
        run = self._scan_run(binding, details, findings, status=doc["status"], errors=errors,
                             assessed=assessed, database=doc["database"])
        self._guard(binding, actor)
        self.ctx.store.save_findings(run_id, findings, meta={"trigger": run["trigger"], "database": doc["database"]})
        self._guard(binding, actor)
        self.ctx.store.save_scan_run(run)
        self._guard(binding, actor)
        self.ctx.store.write_json(run_dir / "baseline.json", doc)
        self._guard(binding, actor)
        self.ctx.store.write_json(self.root / "latest.json", doc)
        details.update(namespaces=len(profiles), images=len(images), errors=len(errors))
        return doc

    @staticmethod
    def _scan_run(binding: _ClusterBinding, details: dict, findings: list[Finding], *, status: str,
                  errors: list[str], assessed: list[str], database: dict) -> dict:
        finished = utcnow()
        summary = summarize(findings)
        summary["cluster_vulnerabilities"] = {"assessed_scopes": assessed, "database": database,
                                              "errors": errors}
        result = TargetScanResult(target_id=binding.target_id, status="error" if errors else "done",
                                  started_at=details["started_at"], finished_at=finished, findings=len(findings),
                                  open=sum(f.is_open for f in findings), errors=errors)
        return ScanRun(id=details["run_id"], targets=[binding.target_id], modules=["cve"],
                       trigger="cluster_vulnerabilities", requested_by=details["requested_by"], status=status,
                       started_at=details["started_at"], finished_at=finished, results={binding.target_id: result},
                       findings_count=len(findings), summary=summary, error="; ".join(errors) or None).to_dict()

    def latest(self) -> dict | None:
        return self.ctx.store.read_json(self.root / "latest.json")

    def _scan_image(self, image: str, run_dir: Path, binding: _ClusterBinding,
                    actor: str, *, snapshot: dict) -> tuple[dict | None, str | None]:
        # CLI flags take precedence, and inherited configuration/filters must not silently narrow
        # coverage or enable database updates. Keep ordinary registry/proxy credentials available.
        config_path, ignore_path = run_dir / "trivy-config.yaml", run_dir / "trivy-ignore"
        config_path.write_text("{}\n", encoding="utf-8")
        ignore_path.write_text("", encoding="utf-8")
        args = [self.ctx.settings.trivy_binary, "image", "--quiet", "--format", "json",
                "--config", str(config_path), "--ignorefile", str(ignore_path),
                "--cache-dir", str(snapshot["cache_dir"]), "--cache-backend", "memory",
                "--scanners", "vuln", "--skip-db-update",
                "--skip-java-db-update", "--offline-scan", "--skip-version-check", "--", image]
        env = {key: value for key, value in os.environ.items() if not key.upper().startswith("TRIVY_")}
        t0 = time.monotonic()
        self._guard(binding, actor)
        try:
            try:
                p = subprocess.run(args, capture_output=True, text=True, timeout=self.ctx.settings.trivy_timeout_s,
                                   encoding="utf-8", errors="replace", env=env)
            finally:
                self._guard(binding, actor)
        except (ScopeViolation, KillSwitchEngaged):
            raise
        except FileNotFoundError:
            return None, f"{self.ctx.settings.trivy_binary} not found"
        except subprocess.TimeoutExpired:
            return None, f"timeout after {self.ctx.settings.trivy_timeout_s}s"
        except OSError as exc:
            return None, f"Trivy could not execute ({type(exc).__name__})"
        raw_path = run_dir / f"trivy_{_safe_name(image)}_{hashlib.sha256(image.encode()).hexdigest()[:12]}.json"
        raw_path.write_text(p.stdout or "", encoding="utf-8")
        if p.returncode != 0:
            return None, f"Trivy failed (exit {p.returncode}); image access or vulnerability coverage is unavailable"
        try:
            report = json.loads(p.stdout or "{}")
        except json.JSONDecodeError as e:
            return None, f"Trivy output was not JSON (line {e.lineno}, column {e.colno})"
        parsed = parse_report(report)
        error = "; ".join(parsed.pop("errors")) or None
        return {"image": image, "seconds": round(time.monotonic() - t0, 3), "raw": str(raw_path),
                **parsed, "complete": not error, "error": error}, error

    def _profiles(self, survey: dict, image_reports: dict[str, dict]) -> list[dict]:
        workloads_by_ns: dict[str, list[dict]] = defaultdict(list)
        for workload in survey.get("workloads") or []:
            workloads_by_ns[workload["namespace"]].append(workload)
        namespace_names = {n.get("name") for n in survey.get("namespaces") or []}
        namespace_names.update(workloads_by_ns)
        profiles = []
        for ns in sorted(n for n in namespace_names if n):
            vulns = []
            affected_images = set()
            fixable = 0
            for workload in workloads_by_ns.get(ns, []):
                for image in workload.get("images") or []:
                    for vuln in image_reports.get(image, {}).get("vulnerabilities") or []:
                        row = dict(vuln, image=image, workload=f"{workload['kind']}/{workload['name']}")
                        vulns.append(row)
                        affected_images.add(image)
                        if row.get("fixed_version"):
                            fixable += 1
            counts = {s.lower(): 0 for s in SEVERITY_ORDER}
            max_cvss = 0.0
            for vuln in vulns:
                counts[str(vuln.get("severity") or "UNKNOWN").lower()] += 1
                if vuln.get("cvss") is not None:
                    max_cvss = max(max_cvss, float(vuln["cvss"]))
            workload_count = len(workloads_by_ns.get(ns, []))
            namespace_images = {img for w in workloads_by_ns.get(ns, []) for img in w.get("images", [])}
            incomplete_images = sorted(img for img in namespace_images
                                       if image_reports.get(img, {}).get("complete") is not True)
            incomplete = bool(incomplete_images or survey.get("errors"))
            risk_score = self._risk_score(vulns, workload_count)
            rating = self._rating(risk_score, counts, max_cvss)
            if incomplete and not vulns:
                rating = "unknown"
            top = sorted(vulns, key=lambda v: (SEVERITY_WEIGHT.get(v["severity"], 0), v.get("cvss") or 0),
                         reverse=True)[:10]
            profile = {"namespace": ns, "risk_rating": rating, "risk_score": round(risk_score, 1),
                       "summary": counts, "max_cvss": round(max_cvss, 1), "workloads": workload_count,
                       "images": len({img for w in workloads_by_ns.get(ns, []) for img in w.get("images", [])}),
                       "affected_images": len(affected_images), "fixable_vulnerabilities": fixable,
                       "top_vulnerabilities": top, "description": self._template_description(ns, rating, counts,
                                                                                              max_cvss, fixable,
                                                                                              workload_count),
                       "description_source": "template", "notes": [],
                       "assessment_status": "not_reviewed" if incomplete else "complete",
                       "incomplete_images": incomplete_images}
            if incomplete:
                note = "Image vulnerability assessment is incomplete; missing evidence is not a clean result."
                profile["notes"].append(note)
                profile["description"] = note + (" " + profile["description"] if vulns else "")
            profiles.append(profile)
        return profiles

    @staticmethod
    def _risk_score(vulns: list[dict], workload_count: int) -> float:
        score = sum(SEVERITY_WEIGHT.get(v.get("severity"), 0.25) for v in vulns)
        score += sum(3.0 for v in vulns if v.get("fixed_version"))
        score += sum(8.0 for v in vulns if (v.get("cvss") or 0) >= 9.0)
        return score / max(workload_count, 1)

    @staticmethod
    def _rating(score: float, counts: dict, max_cvss: float) -> str:
        if counts.get("critical", 0) or max_cvss >= 9.0 or score >= 80:
            return "critical"
        if counts.get("high", 0) >= 3 or score >= 35:
            return "high"
        if counts.get("high", 0) or counts.get("medium", 0) >= 5 or score >= 12:
            return "moderate"
        if counts.get("medium", 0) or counts.get("low", 0):
            return "low"
        return "minimal"

    @staticmethod
    def _template_description(ns: str, rating: str, counts: dict, max_cvss: float, fixable: int,
                              workloads: int) -> str:
        severe = counts.get("critical", 0) + counts.get("high", 0)
        if rating in ("critical", "high"):
            action = "prioritize patching or replacing affected images before expanding this namespace's mission use"
        elif rating == "moderate":
            action = "schedule remediation and verify that compensating controls match the namespace's exposure"
        else:
            action = "track during normal maintenance and keep the baseline current"
        return (f"Namespace {ns} has a {rating} workload image risk profile across {workloads} workload(s). "
                f"The baseline found {severe} critical/high issue(s), maximum CVSS {max_cvss:.1f}, and "
                f"{fixable} vulnerability record(s) with a known fixed version; {action}.")

    def _openai_description(self, profile: dict) -> tuple[str | None, str | None]:
        key = self.ctx.settings.openai_api_key
        if not key:
            return None, "OPENAI_API_KEY or CT_OPENAI_API_KEY is not set"
        schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": {"description": {"type": "string"}},
            "required": ["description"],
        }
        body = {
            "model": self.ctx.settings.openai_model,
            "instructions": ("Write one concise paragraph for security professionals and administrative leaders. "
                             "Be plain-spoken, mention the risk rating, operational impact, and remediation priority. "
                             "Do not invent CVEs, counts, or external facts. Return JSON."),
            "input": json.dumps({k: profile[k] for k in ("namespace", "risk_rating", "risk_score", "summary",
                                                         "max_cvss", "workloads", "images",
                                                         "fixable_vulnerabilities", "top_vulnerabilities")}),
            "text": {"format": {"type": "json_schema", "name": "namespace_risk_description",
                                "schema": schema, "strict": True}},
            "store": False,
        }
        req = urllib.request.Request(
            "https://api.openai.com/v1/responses",
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.ctx.settings.openai_timeout_s) as resp:  # noqa: S310
                out = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:300]
            return None, f"OpenAI API HTTP {e.code}: {detail}"
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            return None, str(e)
        text = out.get("output_text")
        if not text:
            chunks = []
            for item in out.get("output") or []:
                for content in item.get("content") or []:
                    if content.get("type") in ("output_text", "text"):
                        chunks.append(content.get("text") or "")
            text = "\n".join(chunks).strip()
        try:
            data = json.loads(text or "{}")
        except json.JSONDecodeError:
            return None, "OpenAI response was not valid JSON"
        desc = " ".join(str(data.get("description") or "").split())
        return (desc[:1200], None) if desc else (None, "OpenAI response omitted description")
