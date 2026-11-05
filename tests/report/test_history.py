"""Search and retrieval preserve the contents of a report after live state changes."""
from datetime import date

import pytest
from fastapi.testclient import TestClient

from cyberthunder.api.app import create_app
from cyberthunder.inventory.targets import Target
from cyberthunder.report import history
from cyberthunder.report.service import ReportService
from tests.report.conftest import SCAN


def test_exports_are_saved_and_do_not_change_with_live_state(node):
    service = ReportService(node)
    original = service.commander(SCAN, "html")
    service.poam_csv(SCAN)
    service.checklist_cklb(SCAN, "rhel-01")
    rows = history.search(node)["reports"]
    assert {row["kind"] for row in rows} == {"commander", "poam", "checklist"}
    saved = next(row for row in rows if row["kind"] == "commander")
    assert "content" not in saved
    node.store.save_findings(SCAN, [])
    service.commander(SCAN, "html")
    assert history.get(node, saved["id"])["content"] == original
    assert len(history.search(node, kind="commander")["reports"]) == 2


def test_search_content_metadata_dates_filters_and_pagination(node):
    node.inventory.add(Target(id="ship-01", name="Engineering cluster", asset_type="kubernetes"))
    a = history.save(node, "commander", "SSH root access CVE-2026-1111", "html", scan_id="scan-old",
                     targets=["ship-01"], actor="Rivera", generated_at="2026-11-01T23:59:59+00:00")
    b = history.save(node, "poam", "Open findings CVE-2026-1111", "csv", targets=["ship-01"],
                     actor="Hale", generated_at="2026-11-02T00:00:00+00:00")
    history.save(node, "target", {"status": "complete"}, "json", targets=["other"],
                 generated_at="2026-11-03T00:00:00+00:00")
    assert [row["id"] for row in history.search(node, q="engineering RIVERA cve-2026-1111")["reports"]] == [a["id"]]
    assert history.search(node, q="scan-old")["total"] == 1
    assert history.search(node, q="unmatched")["total"] == 0
    assert history.search(node, q="CVE-2026-1111", kind="poam", target="ship-01")["reports"][0]["id"] == b["id"]
    result = history.search(node, from_date=date(2026, 11, 2), to_date=date(2026, 11, 2))
    assert [row["id"] for row in result["reports"]] == [b["id"]]
    page = history.search(node, limit=1, offset=1)
    assert page["total"] == 3 and page["reports"][0]["id"] == b["id"]
    assert history.search(node, offset=20)["reports"] == []
    with pytest.raises(ValueError, match="from_date"):
        history.search(node, from_date=date(2026, 11, 3), to_date=date(2026, 11, 1))


def test_existing_target_and_outbox_reports_import_once_and_survive_sync(node):
    node.store.write_json(node.store.root / "reports/old-host.json", {
        "target": {"id": "old-host", "name": "Old host"}, "generated_at": "2026-10-01T00:00:00+00:00",
        "generated_by": "Rivera", "findings": 8,
    })
    payload = "Host,Issue\r\nold-host,SSH access\r\n"
    node.ingest.outbox.enqueue("report.poam", "previous.csv", payload,
                              {"host": "old-host"}, actor="Hale")
    first = history.search(node)
    assert first["total"] == 2
    assert {row["generated_by"] for row in first["reports"]} == {"Rivera", "Hale"}
    ids = {row["id"] for row in first["reports"]}
    saved = next(row for row in first["reports"] if row["kind"] == "poam")
    assert history.get(node, saved["id"])["content"] == payload
    node.ingest.outbox.sync(force=True, actor="Hale")
    assert {row["id"] for row in history.search(node)["reports"]} == ids
    assert history.search(node, q="SSH access")["total"] == 1


def test_queue_does_not_duplicate_new_report_in_history(node):
    ReportService(node).queue("poam", SCAN, actor="Rivera")
    assert history.search(node)["total"] == 1


def test_history_api_returns_exact_content_without_new_render(node):
    text = ReportService(node).commander(SCAN, "html")
    with TestClient(create_app(node)) as client:
        page = client.get("/api/v1/reports/history", params={"kind": "commander"}).json()
        saved = page["reports"][0]
        before = len(node.audit)
        response = client.get(f'/api/v1/reports/history/{saved["id"]}')
        assert response.status_code == 200 and response.json()["content"] == text
        download = client.get(f'/api/v1/reports/history/{saved["id"]}/download')
        assert download.text == text
        assert "attachment" in download.headers["content-disposition"]
        assert download.headers["content-type"].startswith("text/html")
        assert len(node.audit) == before
        assert client.get("/api/v1/reports/history/no-such-report").status_code == 404
        assert client.get("/api/v1/reports/history", params={"limit": 101}).status_code == 400
        assert client.get("/api/v1/reports/history", params={"offset": -1}).status_code == 400
        assert client.get("/api/v1/reports/history", params={"from_date": "invalid"}).status_code == 400
        assert client.get("/api/v1/reports/history", params={"kind": "fleet"}).status_code == 400


@pytest.mark.parametrize("report_id", ["../audit", "/tmp/report", "a/b", "..", "", "a" * 129])
def test_history_ids_cannot_escape_archive(node, report_id):
    with pytest.raises(ValueError):
        history.get(node, report_id)
