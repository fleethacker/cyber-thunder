"""Bounded, explicit range-only CPE alias using an additional OpenSCAP dictionary.

The benchmark bytes are preserved. The alias's OVAL checks actual os-release at
evaluation time; no unconditional platform pass or rewritten rule result is used.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

CPE = "cpe:/o:redhat:enterprise_linux:9.0"
BENCHMARK = "xccdf_mil.disa.stig_benchmark_RHEL_9_STIG"
XCCDF = "http://checklists.nist.gov/xccdf/1.2"
MAX_CONTENT = 32 * 1024 * 1024
WARNING = ("Explicit range CPE alias: DISA RHEL 9 platform applicability is overridden for this compatible OS; "
           "vendor applicability and full STIG compliance remain unverified. Rule-level applicability is unchanged.")


def validate(target, facts, security_mode="range") -> dict:
    alias = (target.options or {}).get("cpe_alias")
    if security_mode != "range" or target.asset_type != "linux" or not target.in_scope:
        raise ValueError("CPE alias requires an in-scope Linux target in range mode")
    if target.transport not in ("ssh", "local") or (target.transport == "local" and sys.platform == "win32"):
        raise ValueError("CPE alias requires SSH to Linux or a POSIX local transport")
    if not isinstance(alias, dict) or set(alias) != {"source_os", "source_major", "cpe", "reason"}:
        raise ValueError("cpe_alias requires exactly source_os, source_major, cpe and reason")
    if (alias["source_os"] not in ("rocky", "almalinux") or type(alias["source_major"]) is not int
            or alias["source_major"] != 9 or alias["cpe"] != CPE):
        raise ValueError("only explicit Rocky/AlmaLinux 9 to DISA RHEL 9 CPE aliases are supported")
    reason = alias["reason"]
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 300 or any(ord(c) < 32 for c in reason):
        raise ValueError("CPE alias reason must be 1-300 printable characters")
    if (facts is None or facts.model != alias["source_os"]
            or not re.fullmatch(r"9(?:\.[0-9]+)*", facts.os_version or "")):
        raise ValueError("CPE alias does not match observed OS identity and major release")
    bench = (target.options or {}).get("benchmark_path")
    if not isinstance(bench, str) or not bench.startswith("/") or len(bench) > 4096 or any(ord(c) < 32 for c in bench):
        raise ValueError("CPE alias requires an absolute benchmark_path on the target")
    return dict(alias)


def inspect_content(content: bytes, profile: str | None) -> str:
    if not content or len(content) > MAX_CONTENT or b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
        raise ValueError("CPE alias content is empty, too large or contains a DTD/entity declaration")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeError:
        raise ValueError("CPE alias requires UTF-8 content") from None
    if "\0" in text:
        raise ValueError("CPE alias requires UTF-8 content")
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        raise ValueError("CPE alias content is not valid XML") from None
    if root.tag != "{http://scap.nist.gov/schema/scap/source/1.2}data-stream-collection":
        raise ValueError("CPE alias requires a self-contained DISA RHEL 9 source datastream")
    benchmarks = list(root.iter(f"{{{XCCDF}}}Benchmark"))
    if len(benchmarks) != 1 or benchmarks[0].get("id") != BENCHMARK:
        raise ValueError("CPE alias requires the DISA RHEL 9 benchmark identity")
    benchmark = benchmarks[0]
    if CPE not in [e.get("idref") for e in benchmark.findall(f"{{{XCCDF}}}platform")]:
        raise ValueError("DISA benchmark does not declare the exact requested CPE")
    # Require the catalog and every evaluation reference to resolve inside the
    # captured datastream. A benchmark ID alone does not establish containment.
    ds = "http://scap.nist.gov/schema/scap/source/1.2"
    components = {e.get("id") for e in root.findall(f"{{{ds}}}component")}
    refs = {e.get("id"): e.get("{http://www.w3.org/1999/xlink}href")
            for e in root.iter(f"{{{ds}}}component-ref")}
    names = set()
    for entry in root.iter("{urn:oasis:names:tc:entity:xmlns:xml:catalog}uri"):
        name, uri = entry.get("name", ""), entry.get("uri", "")
        if (not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,250}\.xml", name)
                or not uri.startswith("#") or uri[1:] not in refs):
            raise ValueError("external or invalid datastream catalog reference")
        names.add(name)
    for element in root.iter():
        href = element.get("{http://www.w3.org/1999/xlink}href")
        if href is not None and (not href.startswith("#") or href[1:] not in components):
            raise ValueError("external datastream component references are unsupported")
        if element.tag in (f"{{{XCCDF}}}check-content-ref", "{http://cpe.mitre.org/dictionary/2.0}check"):
            if element.get("href") not in names:
                raise ValueError("unresolved evaluation reference in datastream")
    profiles = [e.get("id") for e in benchmark.findall(f"{{{XCCDF}}}Profile")]
    selected = profile or "xccdf_mil.disa.stig_profile_MAC-1_Classified"
    if selected not in profiles:
        raise ValueError("requested CPE alias profile is absent from the benchmark")
    return selected


def documents(alias: dict) -> dict[str, bytes]:
    distro = alias["source_os"]  # allowlisted by validate; never shell or free-form XML
    dictionary = f'''<?xml version="1.0" encoding="UTF-8"?>
<cpe-list xmlns="http://cpe.mitre.org/dictionary/2.0">
  <cpe-item name="{CPE}">
    <title xml:lang="en-US">Explicit range alias for {distro} 9</title>
    <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5" href="alias-oval.xml">oval:org.cyberthunder.range:def:1</check>
  </cpe-item>
</cpe-list>
'''
    oval = '''<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
 xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
 xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
 <generator><oval:product_name>Cyber Thunder range alias</oval:product_name>
 <oval:schema_version>5.11.2</oval:schema_version><oval:timestamp>2026-11-05T00:00:00</oval:timestamp></generator>
 <definitions><definition id="oval:org.cyberthunder.range:def:1" version="1" class="inventory">
 <metadata><title>Explicit compatible distribution major release</title>
 <description>Requires both distribution ID and major release from the evaluated host.</description></metadata>
 <criteria operator="AND">
 <criterion test_ref="oval:org.cyberthunder.range:tst:1" comment="Observed distribution ID"/>
 <criterion test_ref="oval:org.cyberthunder.range:tst:2" comment="Observed major release"/>
 </criteria></definition></definitions><tests>'''
    for i in (1, 2):
        oval += f'''<ind:textfilecontent54_test id="oval:org.cyberthunder.range:tst:{i}" version="1"
 check="all" check_existence="at_least_one_exists" comment="Match os-release identity">
 <ind:object object_ref="oval:org.cyberthunder.range:obj:{i}"/></ind:textfilecontent54_test>'''
    oval += "</tests><objects>"
    for i, pattern in enumerate((f'''(?m)^ID=["']?{distro}["']?$''', r'''(?m)^VERSION_ID=["']?9(?:\.[0-9]+)*["']?$'''), 1):
        oval += f'''<ind:textfilecontent54_object id="oval:org.cyberthunder.range:obj:{i}" version="1">
 <ind:filepath>/etc/os-release</ind:filepath><ind:pattern operation="pattern match">{pattern}</ind:pattern>
 <ind:instance datatype="int">1</ind:instance></ind:textfilecontent54_object>'''
    oval += "</objects></oval_definitions>\n"
    return {"alias-cpe.xml": dictionary.encode(), "alias-oval.xml": oval.encode()}


def _guard(target):
    from cyberthunder.config import Settings
    from cyberthunder.control.killswitch import KillSwitch
    from cyberthunder.inventory.targets import Inventory
    settings = Settings.from_env()
    KillSwitch(settings.state_dir).guard("scan.cpe_alias")
    current = Inventory.load(Path(settings.state_dir) / "targets.yaml").assert_in_scope(target.id)
    if current.to_dict() != target.to_dict():
        raise ValueError("CPE alias target scope or configuration changed")


def evaluate(target, transport, workdir, collected, rule_filter, observation):
    from cyberthunder.config import Settings
    settings = Settings.from_env()
    stage = None

    def run(command, **kwargs):
        _guard(target)
        return transport.run(command, **kwargs)

    try:
        alias = validate(target, collected.facts, getattr(settings, "security_mode", "range"))
        bench = target.options["benchmark_path"]
        read = run(f"head -c {MAX_CONTENT + 1} -- {shlex.quote(bench)} | base64", sudo=True)
        try:
            content = base64.b64decode("".join(read.stdout.split()), validate=True)
        except ValueError:
            raise ValueError("CPE alias benchmark read failed") from None
        if not read.ok:
            raise ValueError("CPE alias benchmark read failed")
        profile = inspect_content(content, target.options.get("profile"))
        observation["content_status"] = "readable"
        files = {"benchmark.xml": content, **documents(alias)}
        provenance = {"alias": alias, "target_id": target.id, "target_address": target.address, "target_port": target.port,
                      "target_transport": target.transport, "observed_os": collected.facts.to_dict(),
                      "benchmark_path": bench, "benchmark_id": BENCHMARK, "profile": profile,
                      "collected_at": collected.collected_at,
                      "sha256": {name: hashlib.sha256(body).hexdigest() for name, body in files.items()},
                      "warning": WARNING}
        collected.raw["cpe_alias"] = provenance
        observation.setdefault("warnings", []).append(WARNING)
        # scan.target already audits collector diagnostics. Insert first so this
        # override is retained even when the engine bounds diagnostics to twenty.
        collected.errors.insert(0, "CPE alias override (warning): " + json.dumps(provenance, sort_keys=True))
        local = Path(workdir) / "cpe_alias"
        local.mkdir(parents=True, exist_ok=True)
        for name, body in files.items():
            (local / name).write_bytes(body)
        (local / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
        created = run("mktemp -d /tmp/ct-cpe-XXXXXXXXXX")
        if not created.ok or not re.fullmatch(r"/tmp/ct-cpe-[A-Za-z0-9]{10}", created.stdout.strip()):
            raise ValueError("could not create private CPE alias staging directory")
        stage = created.stdout.strip()
        for name, body in files.items():
            _guard(target)
            transport.write_file(f"{stage}/{name}", body, mode=0o600)
        selects = " ".join(f"--rule {shlex.quote(r)}" for r in rule_filter or [] if r.startswith("xccdf_"))
        command = (f"oscap xccdf eval --profile {shlex.quote(profile)} {selects} "
                   f"--cpe {stage}/alias-cpe.xml --results {stage}/results.xml {stage}/benchmark.xml")
        result = run(command, sudo=True, timeout=600)
        if result.exit_code not in (0, 2):
            raise ValueError(f"CPE alias evaluation failed (exit {result.exit_code}); no SCAP results accepted")
        _guard(target)
        output = Path(workdir) / "oscap_results.xml"
        transport.fetch(f"{stage}/results.xml", str(output))
        from cyberthunder.parsers.xccdf import parse_xccdf
        try:
            parsed = parse_xccdf(output, host=target.id)
        except Exception:
            raise ValueError("CPE alias evaluation returned invalid XCCDF results") from None
        if parsed.benchmark_id != BENCHMARK or not parsed.findings:
            raise ValueError("CPE alias evaluation returned no matching benchmark results")
        collected.artifacts["oscap_results"] = str(output)
        collected.artifacts["cpe_alias_provenance"] = str(local / "provenance.json")
        collected.raw["oscap"] = {"datastream": bench, "profile": profile, "source": "benchmark_path",
                                  "cpe_alias": provenance}
        observation["status"] = "collected"
        if not any(f.status.value in ("open", "not_a_finding") for f in parsed.findings):
            observation["status"] = "partial"
            observation["warnings"].append("CPE alias produced no evaluated pass/fail rules; platform acceptance remains open.")
    except Exception as exc:
        observation["status"] = "error"
        # Exceptions from transports can contain raw output or credentialed URLs.
        detail = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        collected.errors.append("oscap CPE alias: " + detail)
    finally:
        if stage:
            # No recursive deletion; only these fixed files inside the validated private directory.
            try:
                cleanup = run(f"rm -f -- {stage}/benchmark.xml {stage}/alias-cpe.xml {stage}/alias-oval.xml "
                              f"{stage}/results.xml && rmdir -- {stage}", sudo=True)
                if not cleanup.ok:
                    collected.errors.append("CPE alias staging cleanup failed")
            except Exception:
                collected.errors.append("CPE alias staging cleanup blocked; private temporary files retained")
