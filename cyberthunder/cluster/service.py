"""Survey the Kubernetes cluster this service runs in and build namespace risk profiles.

The scan path is deliberately read-only. Kubernetes data comes from `kubectl get ... -o json`; image
vulnerabilities come from `trivy image --format json`. OpenAI text generation is optional decoration: the
deterministic profile is always returned and stored even when the API key, network or model is unavailable.
"""
from __future__ import annotations

import json
import logging
import subprocess
import time
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cyberthunder.findings.schema import utcnow

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

    def key(self) -> str:
        return f"{self.namespace}/{self.kind}/{self.name}"

    def to_dict(self) -> dict:
        return asdict(self)


def _safe_name(text: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in text)[:180] or "image"


def _containers_from_pod_spec(spec: dict) -> list[dict]:
    return list(spec.get("initContainers") or []) + list(spec.get("containers") or [])


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


class ClusterBaselineService:
    def __init__(self, ctx: "AppContext"):
        self.ctx = ctx
        self.root = Path(ctx.store.root) / "cluster"
        self.root.mkdir(parents=True, exist_ok=True)

    @property
    def kubectl(self) -> list[str]:
        kubeconfig = str(self.ctx.settings.bootstrap_cluster_kubeconfig)
        argv = ["kubectl"]
        if kubeconfig:
            argv += ["--kubeconfig", kubeconfig]
        return argv

    def _kubectl_json(self, *args: str, timeout: int = 120) -> dict:
        p = subprocess.run([*self.kubectl, *args, "-o", "json"], capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        if p.returncode != 0:
            raise RuntimeError((p.stderr or p.stdout or "kubectl failed").strip()[:500])
        return json.loads(p.stdout or "{}")

    def survey(self) -> dict:
        ns_doc = self._kubectl_json("get", "namespaces")
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
                doc = self._kubectl_json("get", resource, "-A")
            except Exception as e:  # noqa: BLE001
                errors.append(f"{resource}: {e}")
                continue
            for item in doc.get("items") or []:
                md = item.get("metadata") or {}
                spec = _pod_spec(item, kind)
                images = sorted({c.get("image") for c in _containers_from_pod_spec(spec) if c.get("image")})
                workloads.append(WorkloadRef(namespace=md.get("namespace") or "default", kind=kind,
                                             name=md.get("name") or "unknown", images=images,
                                             replicas=_replicas(item, kind), labels=md.get("labels") or {}))
        namespaces.sort(key=lambda n: n["name"] or "")
        workloads.sort(key=lambda w: (w.namespace, w.kind, w.name))
        return {"surveyed_at": utcnow(), "namespaces": namespaces, "workloads": [w.to_dict() for w in workloads],
                "errors": errors}

    def scan(self, *, use_openai: bool = False) -> dict:
        survey = self.survey()
        images = sorted({img for w in survey["workloads"] for img in w.get("images", [])})
        run_id = self.ctx.store.new_id("cluster-")
        run_dir = self.root / "baselines" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        image_reports: dict[str, dict] = {}
        errors: list[str] = list(survey.get("errors") or [])
        for image in images:
            report, err = self._scan_image(image, run_dir)
            if err:
                errors.append(f"{image}: {err}")
            image_reports[image] = report or {"image": image, "vulnerabilities": [], "error": err}
        profiles = self._profiles(survey, image_reports)
        if use_openai:
            for profile in profiles:
                generated, err = self._openai_description(profile)
                if generated:
                    profile["description"] = generated
                    profile["description_source"] = "openai"
                elif err:
                    profile.setdefault("notes", []).append(f"OpenAI summary unavailable: {err}")
        doc = {"id": run_id, "generated_at": utcnow(), "survey": survey, "images": image_reports,
               "namespaces": profiles, "errors": errors}
        self.ctx.store.write_json(run_dir / "baseline.json", doc)
        self.ctx.store.write_json(self.root / "latest.json", doc)
        self.ctx.audit.append("cluster.baseline", "agent", {"run_id": run_id, "namespaces": len(profiles),
                                                            "images": len(images), "errors": len(errors)},
                              subject=run_id, outcome="ok" if not errors else "partial")
        return doc

    def latest(self) -> dict | None:
        return self.ctx.store.read_json(self.root / "latest.json")

    def _scan_image(self, image: str, run_dir: Path) -> tuple[dict | None, str | None]:
        args = [self.ctx.settings.trivy_binary, "image", "--quiet", "--format", "json"]
        if self.ctx.settings.trivy_skip_db_update:
            args.append("--skip-db-update")
        args.append(image)
        t0 = time.monotonic()
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=self.ctx.settings.trivy_timeout_s,
                               encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return None, f"{self.ctx.settings.trivy_binary} not found"
        except subprocess.TimeoutExpired:
            return None, f"timeout after {self.ctx.settings.trivy_timeout_s}s"
        raw_path = run_dir / f"trivy_{_safe_name(image)}.json"
        raw_path.write_text(p.stdout if p.stdout.strip() else json.dumps({"Results": []}), encoding="utf-8")
        if p.returncode != 0:
            return None, (p.stderr or p.stdout or "trivy failed").strip()[:500]
        try:
            report = json.loads(p.stdout or "{}")
        except json.JSONDecodeError as e:
            return None, f"trivy output was not JSON: {e}"
        return {"image": image, "seconds": round(time.monotonic() - t0, 3), "raw": str(raw_path),
                "vulnerabilities": _image_vulns(report)}, None

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
            risk_score = self._risk_score(vulns, workload_count)
            rating = self._rating(risk_score, counts, max_cvss)
            top = sorted(vulns, key=lambda v: (SEVERITY_WEIGHT.get(v["severity"], 0), v.get("cvss") or 0),
                         reverse=True)[:10]
            profile = {"namespace": ns, "risk_rating": rating, "risk_score": round(risk_score, 1),
                       "summary": counts, "max_cvss": round(max_cvss, 1), "workloads": workload_count,
                       "images": len({img for w in workloads_by_ns.get(ns, []) for img in w.get("images", [])}),
                       "affected_images": len(affected_images), "fixable_vulnerabilities": fixable,
                       "top_vulnerabilities": top, "description": self._template_description(ns, rating, counts,
                                                                                              max_cvss, fixable,
                                                                                              workload_count),
                       "description_source": "template", "notes": []}
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
