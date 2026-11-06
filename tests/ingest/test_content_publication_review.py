"""Independent regressions for release ambiguity and incomplete activation ledgers."""
from pathlib import Path
from dataclasses import replace

import pytest

from cyberthunder.control.principal import principal_scope
from cyberthunder.ingest import delta
from cyberthunder.ingest.content import publication as pub
from tests.ingest.test_content_publication import accept, candidate
from tests.ingest.test_content_signatures import key_directory, signing, verified
from tests.ingest.test_content_uploads import benchmark


@pytest.mark.parametrize("version", ["V2R13", "002.013"])
@pytest.mark.parametrize("entrypoint", ["upload", "directory", "direct"])
def test_conflicting_internal_release_claims_never_activate(verified, tmp_path, version, entrypoint):
    ctx, human = verified
    first = accept(verified, candidate(tmp_path, 12))
    media = tmp_path / "media"
    media.mkdir()
    path = media / "candidate.xml"
    path.write_bytes(benchmark(version=version, release="11"))
    before = pub.index(ctx.store)
    with principal_scope(human):
        if entrypoint == "directory":
            result = ctx.ingest.content.import_dir(media, human.actor, override_reason="Reviewed media")
            assert not result["imported"], "contradictory releases must not activate"
            assert result["refused"]
        else:
            with pytest.raises(ValueError, match="release"):
                if entrypoint == "upload":
                    ctx.ingest.content.import_upload(path.read_bytes(), path.name, human.actor,
                                                     override_reason="Reviewed media")
                else:
                    ctx.ingest.content.import_stig(path, human.actor, override_reason="Reviewed media")
    assert pub.index(ctx.store) == before
    assert ctx.ingest.content.store.generation() == first["generation"]


def test_missing_active_lineage_refuses_read_and_publication(verified, tmp_path):
    ctx, _ = verified
    first = accept(verified, candidate(tmp_path))
    legacy = delta.catalog_dir(ctx.store) / "Microsoft_Windows_11_STIG.xml"
    legacy.write_bytes(benchmark(release="10"))
    doc = pub.index(ctx.store)
    doc["active"].clear()
    ctx.store.write_json(ctx.ingest.content.store.index_path, doc)
    with pytest.raises(pub.PublicationError, match="active"):
        delta.catalog_path(ctx.store, "Microsoft_Windows_11_STIG")
    with pytest.raises(pub.PublicationError, match="active"):
        accept(verified, candidate(tmp_path, 12))
    assert Path(first["ingest"]["catalog_path"]).read_bytes() == benchmark()
    assert ctx.store.read_json(ctx.ingest.content.store.index_path) == doc


@pytest.mark.parametrize("version", ["2", "V2R13", "002.013"])
def test_consistent_release_spellings_still_upgrade(verified, tmp_path, version):
    ctx, human = verified
    accept(verified, candidate(tmp_path, 12))
    with principal_scope(human):
        result = ctx.ingest.content.import_upload(benchmark(version=version, release="13"),
            "candidate.xml", human.actor, override_reason="Reviewed media")
    assert result["active"]
    assert next(iter(pub.index(ctx.store)["floors"].values()))["release"] == [2, 13]


def test_partial_active_scap_generation_requires_recovery(verified, tmp_path):
    ctx, _ = verified
    def package(release):
        data = (b'<data-stream-collection xmlns="http://scap.nist.gov/schema/scap/source/1.2">'
                + b''.join(b'<component>' + benchmark(bid=bid, release=str(release)) + b'</component>'
                           for bid in ("first", "second")) + b'</data-stream-collection>')
        path, entry = candidate(tmp_path, data=data, name="collection.xml")
        return path, replace(entry, kind="scap_benchmark", version=None, version_label=None)
    first = accept(verified, package(11))
    second = accept(verified, package(12))
    doc = pub.index(ctx.store)
    key = next(iter(doc["active"]))
    doc["active"][key] = first["generation"]
    ctx.store.write_json(ctx.ingest.content.store.index_path, doc)
    with pytest.raises(pub.PublicationError, match="active multi-benchmark"):
        ctx.ingest.content.content()
    assert ctx.store.read_json(ctx.ingest.content.store.index_path)["generation"] == second["generation"]
