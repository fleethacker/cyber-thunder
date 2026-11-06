"""Local scan-content preflight and observed coverage; never fetch or probe a target."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import quote

from cyberthunder.adapters.base import MODULES
from cyberthunder.findings.schema import utcnow
from cyberthunder.ingest.content.select import products_for
from cyberthunder.ingest.content.store import ContentStore

VERSION = 1
OBSERVATION_MAX_AGE_S = 86400
CONFIG_OPTIONS = ("benchmark_path", "profile", "scap_datastream", "scap_profile", "cpe_alias")
OBSERVATION_VALUES = {
    "status": {"unknown", "not_requested", "unavailable", "available", "error", "collected", "partial", "not_configured", "no_rules"},
    "content_status": {"unknown", "unavailable", "readable"},
    "applicability": {"unverified", "filename_matched"},
}


def _observation(value) -> dict:
    if not isinstance(value, dict):
        return {}
    if any(not isinstance(value.get(key), str) or value[key] not in allowed
           for key, allowed in OBSERVATION_VALUES.items()):
        return {}
    if not all(isinstance(value.get(key), str) and len(value[key]) <= 80
               for key in ("observed_at", "configuration_sha256", "engine", "location")):
        return {}
    out = {key: value[key] for key in (*OBSERVATION_VALUES, "observed_at", "configuration_sha256", "engine", "location")}
    warnings = value.get("warnings")
    out["warnings"] = [w[:500] for w in warnings[:10] if isinstance(w, str)] if isinstance(warnings, list) else []
    if type(value.get("selected_rules")) is int and 0 <= value["selected_rules"] <= 100000:
        out["selected_rules"] = value["selected_rules"]
    return out


def configuration_sha256(target) -> str:
    """Bind observations to nonsecret scanner declarations, without opening configured paths."""
    options = target.options or {}
    doc = {"target_id": target.id, "asset_type": target.asset_type, "transport": target.transport,
           "address": target.address, "port": target.port, "simulated": target.simulated,
           "options": {key: options.get(key) for key in CONFIG_OPTIONS}}
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def age_seconds(at: str | None) -> int | None:
    try:
        stamp = datetime.fromisoformat(at.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return None
        seconds = (datetime.now(timezone.utc) - stamp).total_seconds()
        return int(seconds) if seconds >= 0 else None
    except (AttributeError, TypeError, ValueError):
        return None


def _link(product: str) -> str:
    return "/content?tab=browse&product=" + quote(product, safe="")


class ScanContentService:
    def __init__(self, ctx):
        self.ctx = ctx

    def _held(self) -> tuple[list[dict] | None, list[str]]:
        try:
            return ContentStore(self.ctx.store).records(), []
        except (OSError, ValueError, TypeError, AttributeError):
            return None, ["The local content index could not be read; holdings are unknown."]

    def _latest(self, target_id: str) -> tuple[dict | None, list[str]]:
        # Do not use scan_dir(): it creates directories even from a GET.
        try:
            for run in self.ctx.store.list_scan_runs():
                if target_id not in run.get("targets", []):
                    continue
                path = self.ctx.store.scans_dir / run["id"] / "raw" / target_id / "collected.json"
                if not path.is_file():
                    continue
                doc = self.ctx.store.read_json(path)
                if not isinstance(doc, dict) or doc.get("target_id") != target_id:
                    return None, ["The most recent stored collection is invalid; coverage is unknown."]
                return doc, []
        except (OSError, ValueError, TypeError, KeyError):
            return None, ["Stored scan observations could not be read; coverage is unknown."]
        return None, []

    def preflight(self, target_ids=None, *, modules=None) -> dict:
        mods = list(MODULES) if modules is None else list(dict.fromkeys(modules))
        if not mods or any(m not in MODULES for m in mods):
            raise ValueError(f"modules must be a non-empty subset of {list(MODULES)}")
        if target_ids is not None:
            targets = []
            for tid in dict.fromkeys(target_ids):
                self.ctx.inventory.get(tid)
                targets.append(self.ctx.inventory.assert_in_scope(tid))
        else:
            targets = [t for t in self.ctx.inventory.all() if t.in_scope]
        held, warnings = self._held()
        rows = []
        for target in targets:
            collected, problems = self._latest(target.id)
            rows.append(self._view(target, mods, collected, held, [*warnings, *problems], observed=False))
        return {"version": VERSION, "generated_at": utcnow(), "local_only": True, "modules": mods,
                "targets": rows, "automatic_downloads": False}

    def observed(self, target, collected, findings) -> dict:
        held, warnings = self._held()
        doc = collected.to_dict()
        row = self._view(target, list(collected.modules), doc, held, warnings, observed=True)
        row["findings_observed"] = len(findings)
        row["unreviewed_findings"] = sum(f.status.value == "not_reviewed" for f in findings)
        if row["unreviewed_findings"]:
            row["warnings"].append("Some evaluated rules remain not reviewed; their results are not passes.")
        if collected.errors:
            row["warnings"].append("Collection reported errors; consult the per-target errors.")
        # Collector observations are evidence of the attempted checks, not proof that every relevant
        # control was assessed. The parent projection overlays these observations instead of erasing history.
        row["complete"] = False
        return row

    def _view(self, target, modules, collected, held, warnings, *, observed):
        collected = collected or {}
        raw = collected.get("raw") or {}
        if not isinstance(raw, dict):
            warnings.append("Stored collector metadata is invalid; scanner capability is unknown.")
            raw = {}
        observation = _observation(raw.get("scanner_coverage"))
        if raw.get("scanner_coverage") and not observation:
            warnings.append("Stored scanner metadata is invalid; capability is unknown.")
        observed_at = observation.get("observed_at")
        age = age_seconds(observed_at)
        binding_matches = observation.get("configuration_sha256") == configuration_sha256(target)
        stale = bool(observation) and (age is None or age > OBSERVATION_MAX_AGE_S or not binding_matches)
        facts_at = collected.get("collected_at") if collected.get("facts") else None
        facts_age = age_seconds(facts_at)
        # Current collection can discover OS facts without optional SCAP. Stored facts need a
        # fresh matching binding; a reused target ID alone does not identify the same host.
        facts_current = (isinstance(collected.get("facts"), dict) and facts_age is not None
                         and facts_age <= OBSERVATION_MAX_AGE_S
                         and collected.get("target_id") == target.id
                         and collected.get("asset_type") == target.asset_type
                         and ((observed and not raw.get("scanner_coverage"))
                              or (bool(observation) and not stale)))
        if collected.get("facts") and not facts_current:
            warnings.append("Stored OS facts are stale or lack a current target/configuration binding; excluded from product applicability.")
        products, reasons, unknown = products_for(target, collected if facts_current else None)
        options = target.options or {}
        explicit_products = bool(options.get("stig_products"))
        configured = explicit_products or (bool(options.get("facts")) and not facts_current)
        current_facts_at = facts_at if facts_current and not explicit_products else None
        applicability = {"status": "unknown" if unknown else "configured" if configured else "inferred",
                         "reasons": reasons, "unknown": unknown, "observed_at": current_facts_at,
                         "age_seconds": age_seconds(current_facts_at)}
        if unknown:
            warnings.append(unknown)
        rows = []
        for product in products:
            entries = [r for r in (held or []) if r.get("product_key") == product]
            manual = [r for r in entries if r.get("kind") in ("manual_stig", "srg")]
            scap = [r for r in entries if r.get("kind") == "scap_benchmark"]
            rows.append({"product_key": product, "library_url": _link(product),
                         "manual": {"status": "unknown" if held is None else "recorded" if manual else "not_downloaded",
                                    "count": len(manual)},
                         "scap": {"status": "unknown" if held is None else "recorded" if scap else "not_downloaded", "count": len(scap)}})
            if held is not None and not manual:
                warnings.append(f"No downloaded manual STIG guide is recorded for {product}.")
            if held is not None and target.asset_type in ("linux", "windows") and not scap:
                warnings.append(f"No downloaded SCAP benchmark is recorded for {product}; scanner content may be separate.")
        if any(r["manual"]["count"] or r["scap"]["count"] for r in rows):
            warnings.append("Local library holdings do not establish executable scanner content or target readiness.")
        check = "check" in modules
        engine = "openscap" if target.asset_type == "linux" else "windows-scap" if target.asset_type == "windows" else None
        location = "target" if target.asset_type == "linux" else "operator" if target.asset_type == "windows" else None
        path_configured = bool(options.get("benchmark_path") if target.asset_type == "linux" else options.get("scap_datastream"))
        scanner = {"engine": engine, "location": location,
                   "status": "not_requested" if not check else "configured_unverified" if path_configured else "unknown",
                   "content_status": "configured_unverified" if path_configured else "unknown",
                   "applicability": "unverified", "observed_at": observed_at, "age_seconds": age,
                   "stale": stale, "configuration_matches": binding_matches if observation else None,
                   "last_observation": observation or None}
        if check and observation and not stale:
            scanner.update({k: observation[k] for k in ("status", "content_status", "applicability") if k in observation})
        if stale:
            warnings.append("Scanner observations are old or their configuration changed; current capability is unverified.")
        if check and engine:
            if not observed and not observation:
                warnings.append("Scanner capability has not been observed. A scan can collect facts; preflight does not contact the target.")
            if target.asset_type == "linux":
                warnings.append("Linux uses oscap and a datastream already on the target. Downloading a ZIP here does not place it there.")
            else:
                warnings.append("Windows SCAP requires options.scap_datastream pointing to an extracted datastream on the operator node.")
            if scanner["applicability"] == "unverified":
                warnings.append("The configured benchmark's applicability has not been verified for this target.")
        warnings.extend(observation.get("warnings", []) if check else [])
        native_data = bool(raw.get("cmd") or raw.get("checks"))
        native = {"status": ("not_requested" if not check else "partial" if observed and collected.get("errors")
                             else "observed" if observed and native_data
                             else "configured_unverified"), "requires_download": False}
        if check:
            warnings.append("Native checks can run without downloaded STIG content; they do not constitute a complete STIG assessment.")
        if target.simulated:
            warnings.append("This is a simulated target; these observations do not establish live-host capability.")
        return {"version": VERSION, "target_id": target.id, "asset_type": target.asset_type,
                "simulated": bool(target.simulated), "phase": "observed" if observed else "preflight",
                "generated_at": utcnow(), "modules": modules, "complete": False,
                "applicability": applicability, "products": rows, "native": native, "scanner": scanner,
                "warnings": list(dict.fromkeys(warnings)),
                "actions": [{"label": "Browse STIG Library", "href": "/content?tab=browse"},
                            {"label": "Download or import content", "href": "/content?tab=transfers"}]}


def scanner_observation(target, collected, *, engine, location, status="unknown", content_status="unknown",
                        applicability="unverified", warnings=()) -> dict:
    """Small allowlisted capability record emitted only during collection."""
    doc = {"engine": engine, "location": location, "status": status, "content_status": content_status,
           "applicability": applicability, "observed_at": collected.collected_at,
           "configuration_sha256": configuration_sha256(target), "warnings": list(warnings)}
    collected.raw["scanner_coverage"] = doc
    return doc
