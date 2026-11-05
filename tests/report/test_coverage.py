"""Coverage is an inventory, not a scan score; missing content never means 100 percent."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from cyberthunder.adapters import load_all
from cyberthunder.api.app import create_app
from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.findings.schema import Severity
from cyberthunder.remediation.library import FixEntry
from cyberthunder.report import coverage
from cyberthunder.report.render import ReportError
from cyberthunder.scap.datastream import Benchmark, Datastream, Rule, load

ROOT = Path(__file__).resolve().parents[2]
DS = ROOT / "tests/fixtures/scap/w11_subset-ds.xml"


def node_at(path):
    return SimpleNamespace(adapters=load_all(), store=SimpleNamespace(root=path))


def test_native_inventory_counts_checks_not_catalog_descriptions():
    catalogs = coverage.native_catalogs()
    linux = next(c for c in catalogs if c.asset_type == "linux" and c.release == "V2R9")
    kube = next(c for c in catalogs if c.benchmark == "Kubernetes STIG")
    assert linux.catalog_entries == 29
    assert len(linux.rules) == 20
    assert kube.catalog_entries == 20
    assert len(kube.rules) == 17
    assert "CNTR-K8-001360" not in kube.rules
    assert "CNTR-K8-002001" not in kube.rules
    assert set(c.asset_type for c in catalogs) == set(coverage.EXECUTABLE_KINDS)


def test_fix_rules_are_unique_runbook_only_and_do_not_match_shared_ccis():
    rules = {"one": {"RHEL-09-000001"}, "two": {"RHEL-09-000002"}, "three": {"RHEL-09-000003"}}
    entries = [
        FixEntry("a", "a", "linux", ["RHEL-09-000001"], payload="true", citations=["CCI-000366"]),
        FixEntry("b", "b", "linux", ["RHEL-09-000001"], payload="true"),
        FixEntry("c", "c", "linux", ["RHEL-09-000001", "RHEL-09-000002"], kind="runbook", steps=["review"]),
        FixEntry("d", "d", "linux", ["CCI-000366"], payload="true"),
        FixEntry("e", "e", "linux", ["RHEL-09-000003"], payload=""),
    ]
    result = coverage.fix_counts(rules, entries)
    assert result["executable_rule_ids"] == ["one"]
    assert result["runbook_only_rule_ids"] == ["two"]
    assert result["executable_fixes"] == result["runbook_only"] == 1
    entries[-1].payload = "true"
    assert coverage.fix_counts(rules, entries)["executable_fixes"] == 2
    entries[-1].rollback_kind = "manual"
    assert coverage.fix_counts(rules, entries)["executable_fixes"] == 1


def test_every_library_entry_is_accounted_for_once(tmp_path):
    ctx = node_at(tmp_path)
    expected = {a.asset_type: {f.fix_ref for f in a.fixes()} for a in ctx.adapters.all()}
    result = coverage.build_coverage(ctx, str(tmp_path))
    actual = {r["asset_type"]: set(r["fix_refs"]) for r in result["fix_library"]}
    assert actual == expected
    assert result["library_entries"] == sum(len(v) for v in expected.values()) == 209
    for row in result["fix_library"]:
        assert row["entries"] == sum(row["by_kind"].values()) == sum(row["by_source"].values())
    assert result["errors"] == []


def test_empty_and_invalid_content_are_not_reported_as_zero_gaps(tmp_path):
    ctx = node_at(tmp_path)
    result = coverage.build_coverage(ctx, str(tmp_path))
    assert result["benchmarks"] == []
    assert all(r["published_rules"] is None and r["not_covered"] is None for r in result["native_catalogs"])
    for fmt in ("md", "html"):
        text = coverage.render("coverage", fmt, r=result)
        assert "unknown" in text and "not a compliance score" in text
    (tmp_path / "broken.xml").write_text("<broken", encoding="utf-8")
    result = coverage.build_coverage(ctx, str(tmp_path))
    assert "broken.xml" in result["errors"][0]
    with pytest.raises(ReportError):
        coverage.build_coverage(ctx, str(tmp_path / "absent"))


def test_benchmark_totals_are_from_xml_and_duplicates_do_not_inflate_them(tmp_path):
    shutil.copy(DS, tmp_path / "one.xml")
    shutil.copy(DS, tmp_path / "two.xml")
    result = coverage.build_coverage(node_at(tmp_path), str(tmp_path))
    assert len(result["benchmarks"]) == 1
    row = result["benchmarks"][0]
    ds = load(DS)
    from cyberthunder.scap.oval.windows_probes import SUPPORTED
    expected = {r.id for r in ds.benchmark.rules.values() if ds.support(r, SUPPORTED).supported}
    assert row["published_rules"] == len(ds.benchmark.rules)
    assert row["scap_eligible"] == len(expected)
    assert set(row["scap_rule_ids"]) == expected
    assert row["scap_eligible"] < row["published_rules"]  # unsupported probes are not credited
    assert row["not_covered"] == len(set(ds.benchmark.rules) - expected - set(row["native_rule_ids"]))
    assert len(row["sha256"]) == 64


def test_matching_manual_and_scap_requires_same_release():
    ds = load(DS)
    b = ds.benchmark
    family, version, release = coverage._family(b)
    manual = Benchmark(family, "Manual", version, f"Version {version} (Release: {release})", rules=b.rules)
    old = Benchmark(family, "Old manual", version, "Release: 999", rules=b.rules)
    records = [(ds, "a"), (Datastream("manual.xml", "xccdf", [manual]), "b"),
               (Datastream("old.xml", "xccdf", [old]), "c")]
    rows = coverage.benchmark_rows(records, [], [])
    assert rows[0]["scap_eligible"] > 0
    assert rows[1]["scap_eligible"] == rows[0]["scap_eligible"]
    assert rows[2]["scap_eligible"] == 0


def test_manual_fix_text_and_foreign_adapter_fixes_are_not_executable_coverage():
    rule = Rule("rule1", "RHEL-09-000001", "<script>bad</script>", Severity.LOW, fix_text="Run a command")
    benchmark = Benchmark("RHEL_9_STIG", "<script>bad</script>", "2", "Release: 10", rules={rule.id: rule})
    ds = Datastream("manual.xml", "xccdf", [benchmark])
    foreign = FixEntry("wrong", "wrong", "windows", [rule.version], kind="powershell", payload="noop")
    row = coverage.benchmark_rows([(ds, "a")], [], [foreign])[0]
    assert row["executable_fixes"] == row["runbook_only"] == row["scap_eligible"] == 0
    assert row["not_covered"] == 1
    html = coverage.render("coverage", "html", r={"benchmarks": [row], "limitations": coverage.LIMITATIONS})
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_shipped_rhel_manual_and_datastream_have_distinct_denominators(tmp_path):
    result = coverage.build_coverage(node_at(tmp_path))
    rows = {r["source"]: r for r in result["benchmarks"]}
    manual = rows["U_RHEL_9_STIG_V2R10_Manual-xccdf.xml"]
    scap = rows["U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.xml"]
    assert manual["published_rules"] == 445
    assert scap["published_rules"] == manual["scap_eligible"] == 393
    assert manual["not_covered"] == 52
    assert manual["scap_engine"] == "external OpenSCAP"


def test_imported_content_is_found_without_repo_files(tmp_path, monkeypatch):
    root = tmp_path / "state"
    destination = root / "content/scap/windows"
    destination.mkdir(parents=True)
    shutil.copy(DS, destination / "import.xml")
    monkeypatch.setattr(coverage, "__file__", str(tmp_path / "installed/package/report/coverage.py"))
    result = coverage.build_coverage(node_at(root))
    assert [r["source"] for r in result["benchmarks"]] == ["import.xml"]


def test_report_api_and_cli_work_without_scanning(state_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    ctx = AppContext(Settings.from_env(state_dir=state_dir))
    def forbidden(*args, **kwargs):
        pytest.fail("coverage must not collect from or change a target")
    monkeypatch.setattr(ctx, "transport_for", forbidden)
    monkeypatch.setattr(ctx.scanner, "run", forbidden)
    head = ctx.audit.head
    with TestClient(create_app(ctx)) as client:
        response = client.get("/api/v1/reports/coverage?format=json")
        assert response.status_code == 200
        assert response.json()["audit_head"] == head
        for fmt in ("html", "md"):
            response = client.get(f"/api/v1/reports/coverage?format={fmt}")
            assert response.status_code == 200
            assert "Check and fix coverage" in response.text
        assert client.get("/api/v1/reports/coverage?format=bad").status_code == 400
    assert ctx.audit.verify().ok
    assert list(ctx.audit.records())[-1]["details"]["kind"] == "coverage"
    empty = tmp_path / "empty"
    empty.mkdir()
    result = subprocess.run([sys.executable, "-m", "cyberthunder", "--state-dir", str(state_dir),
                             "report", "coverage", "--format", "json", "--benchmark-dir", str(empty)],
                            cwd=ROOT, text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["benchmarks"] == []


def test_commander_includes_coverage_limits_and_counts(node):
    for fmt in ("html", "md"):
        text = node.reports.commander(fmt=fmt)
        assert "whole benchmark" in text and "445" in text and "393" in text
        assert "not checks completed in this scan" in text


def test_generated_validation_matrix_and_readme_agree():
    result = subprocess.run([sys.executable, "scripts/validation_status.py", "--check"],
                            cwd=ROOT, text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


def test_custom_content_is_not_silently_replaced_when_queueing(tmp_path):
    state = tmp_path / "state"
    result = subprocess.run([sys.executable, "-m", "cyberthunder", "--state-dir", str(state),
                             "report", "coverage", "--queue", "--benchmark-dir", str(tmp_path)],
                            cwd=ROOT, text=True, capture_output=True, timeout=60)
    assert result.returncode == 2
    assert "use --out" in result.stderr
    assert not (state / "outbox").exists()


def split_fixture(destination):
    destination.mkdir(parents=True, exist_ok=True)
    root = ET.parse(DS).getroot()
    local = lambda tag: tag.rsplit("}", 1)[-1]
    benchmark = next(el for el in root.iter() if local(el.tag) == "Benchmark")
    path = destination / "benchmark.xml"
    path.write_bytes(ET.tostring(benchmark))
    ds = load(DS)
    refs = {c.component: Path(c.href).name for r in ds.benchmark.rules.values() for c in r.checks
            if c.is_oval and c.component}
    companions = []
    for component in root:
        name = refs.get(component.get("id"))
        if name:
            oval = next(el for el in component if local(el.tag) == "oval_definitions")
            companion = destination / name
            companion.write_bytes(ET.tostring(oval))
            companions.append(companion)
    return path, companions


def test_split_content_dedup_preserves_complete_pair_after_incomplete_copy(tmp_path):
    complete, companions = split_fixture(tmp_path / "z-complete")
    assert companions
    incomplete = tmp_path / "a-incomplete"
    incomplete.mkdir()
    shutil.copy(complete, incomplete / complete.name)
    result = coverage.build_coverage(node_at(tmp_path), str(tmp_path))
    assert result["errors"] == []
    rows = result["benchmarks"]
    assert len(rows) == 2
    assert len({r["sha256"] for r in rows}) == 1
    assert len({r["content_sha256"] for r in rows}) == 2
    assert max(r["scap_eligible"] for r in rows) > 0
    assert any(None in r["oval_dependencies"].values() for r in rows)


def test_split_oval_changes_and_removal_refresh_counts(tmp_path):
    xccdf, companions = split_fixture(tmp_path)
    ctx = node_at(tmp_path)
    first = coverage.build_coverage(ctx, str(tmp_path))["benchmarks"][0]
    assert first["scap_eligible"] > 0
    unchanged_xccdf = xccdf.stat()
    originals = {p: p.read_bytes() for p in companions}
    for p in companions:
        root = ET.fromstring(originals[p])
        for child in root:
            if child.tag.rsplit("}", 1)[-1] == "definitions":
                child.clear()
        p.write_bytes(ET.tostring(root))
    changed = coverage.build_coverage(ctx, str(tmp_path))["benchmarks"][0]
    assert changed["scap_eligible"] == 0
    assert changed["sha256"] == first["sha256"]
    assert changed["content_sha256"] != first["content_sha256"]
    assert xccdf.stat().st_mtime_ns == unchanged_xccdf.st_mtime_ns
    for p in companions:
        p.unlink()
    missing = coverage.build_coverage(ctx, str(tmp_path))["benchmarks"][0]
    assert missing["scap_eligible"] == 0
    for p, data in originals.items():
        p.write_bytes(data)
    restored = coverage.build_coverage(ctx, str(tmp_path))["benchmarks"][0]
    assert restored["content_sha256"] == first["content_sha256"]
    assert restored["scap_eligible"] == first["scap_eligible"]


def test_unavailable_native_catalog_does_not_break_other_reports(node, tmp_path, monkeypatch):
    from cyberthunder.adapters.windows import checks as win
    def missing_catalog():
        raise FileNotFoundError("catalog unavailable")
    monkeypatch.setattr(win, "catalog", missing_catalog)
    result = coverage.build_coverage(node, str(tmp_path))
    assert any("windows: native catalog unavailable" in error for error in result["errors"])
    assert any(row["asset_type"] == "linux" for row in result["native_catalogs"])
    assert not any(row["asset_type"] == "windows" for row in result["native_catalogs"])
    assert "445" in node.reports.commander()
    available = [a for a in node.adapters.all() if a.asset_type != "windows"]
    node.adapters = SimpleNamespace(all=lambda: available)
    result = coverage.build_coverage(node, str(tmp_path))
    assert any("windows: adapter not loaded" in error for error in result["errors"])
    assert not any("native catalog unavailable" in error for error in result["errors"])
