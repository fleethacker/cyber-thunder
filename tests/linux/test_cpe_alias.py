"""Explicit platform aliases preserve content and remain attributable and visibly conditional."""
import base64
import copy
import hashlib
import json
import re
import shlex
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from cyberthunder.adapters.base import AssetFacts, Collected
from cyberthunder.adapters.linux import LinuxAdapter, checks, cpe_alias
from cyberthunder.inventory.targets import Inventory, Target
from cyberthunder.transport.base import CommandResult

CONTENT = Path(__file__).resolve().parents[2] / "STIG/U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.xml"
PROFILE = "xccdf_mil.disa.stig_profile_MAC-1_Classified"
RESULT = f'''<Benchmark xmlns="{cpe_alias.XCCDF}" id="{cpe_alias.BENCHMARK}">
 <title>DISA RHEL 9</title><Rule id="xccdf_test_rule_1" severity="medium"><title>Test rule</title></Rule>
 <TestResult id="xccdf_test_result_1" end-time="2026-11-05T12:00:00Z"><target>range</target>
 <rule-result idref="xccdf_test_rule_1"><result>fail</result><message>Original scanner message</message></rule-result>
 </TestResult></Benchmark>'''


def declaration():
    return {"source_os": "rocky", "source_major": 9, "cpe": cpe_alias.CPE, "reason": "Isolated compatible OS range"}


def target():
    return Target(id="rocky-range", name="range", address="127.0.0.1", asset_type="linux",
                  options={"benchmark_path": "/var/lib/scap/disa.xml", "cpe_alias": declaration()})


def facts():
    return AssetFacts(hostname="range", model="rocky", os_version="9.4", os_name="Rocky Linux")


@pytest.mark.parametrize("change", [None, {}, {"cpe": "cpe:/o:redhat:enterprise_linux:8.0"}, {"source_os": "rhel"},
                                    {"source_os": "ubuntu"}, {"source_major": "9"}, {"source_major": True},
                                    {"source_major": 8}, {"reason": ""}, {"reason": "x" * 301},
                                    {"reason": "line\nbreak"}, {"command": "id"}])
def test_invalid_alias_is_rejected(change):
    t = target()
    if change is None or change == {}:
        t.options["cpe_alias"] = change
    else:
        t.options["cpe_alias"].update(change)
    with pytest.raises(ValueError):
        cpe_alias.validate(t, facts())


@pytest.mark.parametrize("os_id,version", [("ubuntu", "9"), ("almalinux", "9.4"), ("rocky", "8.10"),
                                           ("rocky", "9;id"), ("rocky", None), (None, "9")])
def test_declared_alias_must_match_observed_os(os_id, version):
    with pytest.raises(ValueError):
        cpe_alias.validate(target(), AssetFacts(model=os_id, os_version=version))


@pytest.mark.parametrize("mode", ["fleet", "unknown"])
def test_alias_refused_outside_range(mode):
    with pytest.raises(ValueError):
        cpe_alias.validate(target(), facts(), mode)


def test_exact_disa_content_accepted_unchanged():
    raw = CONTENT.read_bytes()
    original = hashlib.sha256(raw).hexdigest()
    assert cpe_alias.inspect_content(raw, None) == PROFILE
    assert hashlib.sha256(CONTENT.read_bytes()).hexdigest() == original
    with pytest.raises(ValueError):
        cpe_alias.inspect_content(raw, "--remediate")
    with pytest.raises(ValueError):
        cpe_alias.inspect_content(raw.replace(b"benchmark_RHEL_9_STIG", b"benchmark_RHEL_8_STIG"), None)
    with pytest.raises(ValueError):
        cpe_alias.inspect_content(raw.replace(cpe_alias.CPE.encode(), b"cpe:/o:redhat:enterprise_linux:8.0"), None)


@pytest.mark.parametrize("raw", [b"", b"<broken", b'<!DOCTYPE x><x/>', b'<!ENTITY x "y"><x/>',
                                  b'<Benchmark/>', b"x" * (cpe_alias.MAX_CONTENT + 1)])
def test_invalid_or_oversized_content_refused(raw):
    with pytest.raises(ValueError):
        cpe_alias.inspect_content(raw, None)


def test_external_component_rejected():
    raw = CONTENT.read_bytes()
    raw = re.sub(rb'(xlink:href=")[^"]+', rb'\1https://untrusted.example/content.xml', raw, count=1)
    with pytest.raises(ValueError):
        cpe_alias.inspect_content(raw, None)


@pytest.mark.parametrize("kind", ["external-catalog", "traversal", "unresolved-check"])
def test_catalog_and_evaluation_references_must_be_contained(kind):
    root = ET.fromstring(CONTENT.read_bytes())
    if kind == "unresolved-check":
        element = next(root.iter(f"{{{cpe_alias.XCCDF}}}check-content-ref"))
        element.set("href", "unresolved.xml")
    else:
        element = next(root.iter("{urn:oasis:names:tc:entity:xmlns:xml:catalog}uri"))
        element.set("uri" if kind == "external-catalog" else "name",
                    "https://untrusted.example/oval.xml" if kind == "external-catalog" else "../escape.xml")
    raw = ET.tostring(root)
    with pytest.raises(ValueError):
        cpe_alias.inspect_content(raw, None)


def test_alias_oval_requires_actual_identity_and_major():
    files = cpe_alias.documents(declaration())
    dictionary = ET.fromstring(files["alias-cpe.xml"])
    assert next(iter(dictionary)).get("name") == cpe_alias.CPE
    oval = ET.fromstring(files["alias-oval.xml"])
    patterns = [e.text for e in oval.iter() if e.tag.endswith("}pattern")]
    assert len(patterns) == 2
    for text in ['ID=rocky\nVERSION_ID="9.4"\n', 'ID="rocky"\nVERSION_ID="9"\n']:
        assert all(re.search(pattern, text) for pattern in patterns)
    for text in ['ID=rocky\nVERSION_ID="8.10"\n', 'ID=ubuntu\nVERSION_ID="9"\n', 'ID=rocky\n',
                 'ID=rocky\nVERSION_ID="90.4"\n', 'ID=rocky\nVERSION_ID="9;id"\n']:
        assert not all(re.search(pattern, text) for pattern in patterns)
    criteria = next(e for e in oval.iter() if e.tag.endswith("}criteria"))
    assert criteria.get("operator") == "AND"
    assert len(list(criteria)) == 2


class FakeTransport:
    def __init__(self, *, code=2, result=RESULT, stage="/tmp/ct-cpe-Ab01234567", on_eval=None, bad_write=False):
        self.code, self.result, self.stage = code, result, stage
        self.on_eval, self.bad_write = on_eval, bad_write
        self.calls, self.writes = [], {}
    def run(self, command, **kwargs):
        self.calls.append(command)
        if command == "command -v oscap":
            return CommandResult(command, 0)
        if command.startswith("head -c"):
            return CommandResult(command, 0, base64.b64encode(CONTENT.read_bytes()).decode())
        if command.startswith("mktemp"):
            return CommandResult(command, 0, self.stage + "\n")
        if command.startswith("oscap xccdf"):
            if self.on_eval:
                self.on_eval()
            return CommandResult(command, self.code)
        if command.startswith("rm -f"):
            assert "-r" not in command
            return CommandResult(command, 0)
        raise AssertionError(command)
    def write_file(self, path, data, **kwargs):
        if self.bad_write:
            raise OSError("SECRET")
        assert path.startswith(self.stage + "/") and kwargs["mode"] == 0o600
        self.writes[path] = data
    def fetch(self, remote, local):
        self.calls.append("fetch " + remote)
        Path(local).write_text(self.result, encoding="utf-8")


@pytest.fixture
def registered(state_dir, monkeypatch):
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    t = target()
    Inventory(targets=[t]).save(state_dir / "targets.yaml")
    return t


def collect(t, transport, tmp_path, rule_filter=None):
    col = Collected(t.id, "linux", str(tmp_path), facts=facts(), modules=["check"])
    LinuxAdapter()._maybe_oscap(t, transport, tmp_path, col, rule_filter)
    return col


def test_alias_eval_preserves_content_and_exact_result_provenance(registered, tmp_path):
    transport = FakeTransport()
    col = collect(registered, transport, tmp_path)
    assert col.raw["scanner_coverage"]["status"] == "collected", col.errors
    assert col.raw["scanner_coverage"]["applicability"] == "unverified"
    assert cpe_alias.WARNING in col.raw["scanner_coverage"]["warnings"]
    assert transport.writes[transport.stage + "/benchmark.xml"] == CONTENT.read_bytes()
    provenance = col.raw["cpe_alias"]
    assert provenance["alias"] == declaration()
    assert provenance["target_id"] == registered.id
    assert provenance["sha256"]["benchmark.xml"] == hashlib.sha256(CONTENT.read_bytes()).hexdigest()
    assert provenance["profile"] == PROFILE
    assert provenance["observed_os"]["model"] == "rocky"
    assert json.loads(col.errors[0].split(": ", 1)[1]) == provenance  # scan.target audit diagnostic
    assert json.loads(Path(col.artifacts["cpe_alias_provenance"]).read_text()) == provenance
    findings = checks.oscap_findings(registered, col)
    assert len(findings) == 1 and findings[0].status == "open"
    assert findings[0].collection_provenance["cpe_alias"] == provenance
    assert "platform:cpe-alias" in findings[0].tags
    assert "Original scanner message" in findings[0].evidence
    assert cpe_alias.WARNING in findings[0].evidence


def test_alias_warning_and_provenance_survive_native_merge(registered, tmp_path):
    col = collect(registered, FakeTransport(), tmp_path)
    findings = checks.oscap_findings(registered, col)
    original = findings[0]
    original.rule_version = "RHEL-09-TEST"
    native = copy.deepcopy(original)
    native.id = "native"
    native.status = type(original.status).NOT_A_FINDING
    native.evidence = "native result"
    merged = checks.merge([native], findings)[0]
    assert merged.status == "not_a_finding"
    assert cpe_alias.WARNING in merged.evidence
    assert merged.collection_provenance["cpe_alias"] == col.raw["cpe_alias"]


def test_alias_does_not_rewrite_notapplicable(registered, tmp_path):
    col = collect(registered, FakeTransport(result=RESULT.replace(">fail<", ">notapplicable<")), tmp_path)
    findings = checks.oscap_findings(registered, col)
    assert findings[0].status == "not_applicable"
    assert cpe_alias.WARNING in findings[0].evidence
    assert col.raw["scanner_coverage"]["status"] == "partial"


@pytest.mark.parametrize("kind", ["exit", "write", "stage"])
def test_alias_failures_never_accept_results(kind, registered, tmp_path):
    transport = FakeTransport(**{"exit": {"code": 1}, "write": {"bad_write": True},
                                 "stage": {"stage": "/tmp/else;id"}}[kind])
    col = collect(registered, transport, tmp_path)
    assert col.raw["scanner_coverage"]["status"] == "error"
    assert "oscap_results" not in col.artifacts
    assert "SECRET" not in json.dumps(col.to_dict())
    assert not any(cmd.startswith("fetch") for cmd in transport.calls)


@pytest.mark.parametrize("kind", ["kill", "scope", "changed"])
def test_alias_rechecks_scope_and_kill_before_io(kind, registered, tmp_path, state_dir, monkeypatch):
    if kind == "kill":
        monkeypatch.setenv("CT_KILL", "1")
    else:
        inv = Inventory.load(state_dir / "targets.yaml")
        inv.update(registered.id, **({"in_scope": False} if kind == "scope" else {"address": "other"}))
        inv.save()
    transport = FakeTransport()
    col = collect(registered, transport, tmp_path)
    assert col.raw["scanner_coverage"]["status"] == "error"
    assert transport.calls == ["command -v oscap"]
    assert transport.writes == {}


def test_kill_mid_eval_stops_fetch_and_cleanup(registered, tmp_path, monkeypatch):
    transport = FakeTransport(on_eval=lambda: monkeypatch.setenv("CT_KILL", "1"))
    col = collect(registered, transport, tmp_path)
    assert col.raw["scanner_coverage"]["status"] == "error"
    assert not any(cmd.startswith(("fetch", "rm")) for cmd in transport.calls)
    assert any("cleanup blocked" in error for error in col.errors)


def test_shell_and_argv_injection_payload_is_one_rule_argument(registered, tmp_path, state_dir):
    registered.options["benchmark_path"] = "/var/lib/scap/x'; touch INJECTED; echo '.xml"
    Inventory(targets=[registered]).save(state_dir / "targets.yaml")
    rule = "xccdf_test'; touch INJECTED; echo '"
    transport = FakeTransport()
    col = collect(registered, transport, tmp_path, [rule])
    assert col.raw["scanner_coverage"]["status"] == "collected"
    read = next(cmd for cmd in transport.calls if cmd.startswith("head"))
    assert shlex.split(read)[4] == registered.options["benchmark_path"]
    command = next(cmd for cmd in transport.calls if cmd.startswith("oscap xccdf"))
    argv = shlex.split(command)
    assert argv[argv.index("--rule") + 1] == rule
    assert "--remediate" not in argv


def test_no_alias_without_explicit_option(tmp_path):
    t = target()
    del t.options["cpe_alias"]
    from tests.scan_content.test_collectors import Transport
    col = collect(t, Transport(), tmp_path)
    assert "cpe_alias" not in col.raw


def test_utf16_entity_document_refused():
    with pytest.raises(ValueError):
        cpe_alias.inspect_content('<!DOCTYPE x [<!ENTITY y "expanded">]><x>&y;</x>'.encode("utf-16"), None)


@pytest.mark.parametrize("result", ["<broken", "<results/>", RESULT.replace(cpe_alias.BENCHMARK, "wrong")])
def test_missing_or_wrong_benchmark_results_not_accepted(result, registered, tmp_path):
    col = collect(registered, FakeTransport(result=result), tmp_path)
    assert col.raw["scanner_coverage"]["status"] == "error"
    assert "oscap_results" not in col.artifacts


def test_local_windows_shell_rejected():
    t = target()
    t.transport = "local"
    from unittest.mock import patch
    with patch.object(cpe_alias.sys, "platform", "win32"), pytest.raises(ValueError):
        cpe_alias.validate(t, facts())


def test_scanner_hash_chained_audit_persists_override(registered, tmp_path, state_dir, monkeypatch):
    from cyberthunder.context import AppContext
    from cyberthunder.config import Settings
    ctx = AppContext(Settings.from_env(state_dir=state_dir, explain_precompute=False, auto_propose=False))
    adapter = LinuxAdapter()
    transport = FakeTransport()
    transport.close = lambda: None
    monkeypatch.setattr(ctx, "adapter_for", lambda t: adapter)
    monkeypatch.setattr(ctx, "transport_for", lambda t: transport)
    monkeypatch.setattr(adapter, "discover", lambda t, tr: facts())
    def collected(t, tr, workdir, **kwargs):
        col = collect(t, tr, workdir)
        col.errors.extend(["additional diagnostic"] * 25)
        return col
    monkeypatch.setattr(adapter, "collect", collected)
    run = ctx.scanner.start([registered.id], modules=["check"], background=False, requested_by="range-operator")
    assert run.results[registered.id].status == "done"
    records = [r for r in ctx.audit.records() if r["action"] == "scan.target"]
    assert len(records) == 1
    record = records[0]
    # Existing engine intentionally bounds audit diagnostics; the alias must survive it.
    detail = record["details"]["errors"][0]
    provenance = json.loads(detail.split(": ", 1)[1])
    assert provenance["alias"] == declaration()
    assert provenance["target_id"] == registered.id
    assert provenance["sha256"]["benchmark.xml"] == hashlib.sha256(CONTENT.read_bytes()).hexdigest()
    assert ctx.audit.verify().ok
    saved = ctx.store.load_findings(run.id)
    assert any(f.collection_provenance.get("cpe_alias") == provenance for f in saved)
