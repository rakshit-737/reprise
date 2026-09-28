"""Small content-addressed artifact store for local replay evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from .fixture import canonical_json
from .models import EvidenceArtifact, Fixture

_KIND_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class ArtifactStoreError(ValueError):
    """Raised when an artifact cannot be safely stored or verified."""


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
            temporary_path = handle.name
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            Path(temporary_path).unlink(missing_ok=True)


class ArtifactStore:
    """Persist immutable bytes beneath a caller-selected local root.

    The store is intentionally filesystem-backed for the replay milestone. A
    later object store adapter can preserve this content-addressed interface.
    """

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _validate_kind(kind: str) -> None:
        if not isinstance(kind, str) or not _KIND_PATTERN.fullmatch(kind):
            raise ArtifactStoreError("artifact kind must be a short lowercase path-safe identifier")

    def _data_path(self, kind: str, sha256: str) -> Path:
        self._validate_kind(kind)
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise ArtifactStoreError("artifact digest must be a lowercase SHA-256 hex string")
        return self.root / kind / sha256[:2] / sha256

    def _metadata_path(self, kind: str, sha256: str) -> Path:
        return self._data_path(kind, sha256).with_suffix(".json")

    def put_bytes(self, kind: str, payload: bytes, *, source: str) -> EvidenceArtifact:
        self._validate_kind(kind)
        if not isinstance(payload, bytes):
            raise ArtifactStoreError("artifact payload must be bytes")
        if not isinstance(source, str) or not source.strip():
            raise ArtifactStoreError("artifact source must be a non-empty string")
        sha256 = hashlib.sha256(payload).hexdigest()
        data_path = self._data_path(kind, sha256)
        metadata_path = self._metadata_path(kind, sha256)
        if data_path.exists():
            existing = data_path.read_bytes()
            if existing != payload:
                raise ArtifactStoreError("content-addressed artifact changed under the same digest")
        else:
            _atomic_write(data_path, payload)

        artifact = EvidenceArtifact(
            artifact_id=f"artifact:{kind}:{sha256[:20]}",
            kind=kind,
            sha256=sha256,
            source=source,
            byte_length=len(payload),
        )
        if not metadata_path.exists():
            _atomic_write(
                metadata_path,
                (json.dumps(artifact.to_dict(), indent=2, sort_keys=True) + "\n").encode("utf-8"),
            )
        return artifact

    def put_json(self, kind: str, value: Any, *, source: str) -> EvidenceArtifact:
        return self.put_bytes(kind, canonical_json(value), source=source)

    def read_bytes(self, artifact: EvidenceArtifact) -> bytes:
        data_path = self._data_path(artifact.kind, artifact.sha256)
        if not data_path.exists():
            raise ArtifactStoreError(f"artifact bytes are missing: {artifact.artifact_id}")
        payload = data_path.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        if digest != artifact.sha256 or len(payload) != artifact.byte_length:
            raise ArtifactStoreError(f"artifact integrity check failed: {artifact.artifact_id}")
        return payload

    def verify(self, artifact: EvidenceArtifact) -> bool:
        self.read_bytes(artifact)
        return True

    def persist_fixture(self, fixture: Fixture) -> dict[str, EvidenceArtifact]:
        """Persist the accepted source and normalized RBAC snapshot bytes."""

        source = self.put_bytes("fixture-source", fixture.source_bytes, source=fixture.environment["id"])
        snapshot_payload = {
            "environment": fixture.environment,
            "service_accounts": [item.to_dict() for item in fixture.service_accounts],
            "roles": [role.to_dict() for role in fixture.roles],
            "role_bindings": [binding.to_dict() for binding in fixture.role_bindings],
        }
        snapshot = self.put_json("rbac-snapshot", snapshot_payload, source=fixture.environment["id"])
        if snapshot.sha256[:20] != fixture.snapshot_artifact_id.rsplit(":", 1)[-1]:
            raise ArtifactStoreError("normalized RBAC snapshot digest does not match fixture metadata")
        return {"source": source, "snapshot": snapshot}
