import hashlib

import pytest

from reprise.artifacts import ArtifactStore, ArtifactStoreError
from reprise.fixture import load_fixture
from reprise.report import build_evidence_package


def test_content_addressed_store_round_trip(tmp_path):
    store = ArtifactStore(tmp_path / "store")
    artifact = store.put_bytes("audit-event", b"metadata-only", source="unit-test")

    assert artifact.artifact_id.startswith("artifact:audit-event:")
    assert store.verify(artifact) is True
    assert store.read_bytes(artifact) == b"metadata-only"
    assert (tmp_path / "store" / "audit-event").exists()


def test_content_addressed_store_detects_tampering(tmp_path):
    store = ArtifactStore(tmp_path / "store")
    artifact = store.put_bytes("audit-event", b"metadata-only", source="unit-test")
    data_path = store._data_path(artifact.kind, artifact.sha256)
    data_path.write_bytes(b"tampered")

    with pytest.raises(ArtifactStoreError, match="integrity"):
        store.verify(artifact)


def test_store_rejects_path_traversal_kind(tmp_path):
    store = ArtifactStore(tmp_path / "store")
    with pytest.raises(ArtifactStoreError):
        store.put_bytes("../outside", b"x", source="unit-test")


def test_cli_style_package_persists_source_artifact(fixture_file, tmp_path):
    fixture = load_fixture(fixture_file())
    package = build_evidence_package(fixture, artifact_store=ArtifactStore(tmp_path / "store"))
    source_artifact_id = package["source"]["source_artifact_id"]
    artifact_ids = {artifact["artifact_id"] for artifact in package["artifacts"]}

    assert source_artifact_id in artifact_ids
    assert package["source"]["source_sha256"] == hashlib.sha256(fixture.source_bytes).hexdigest()
