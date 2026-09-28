"""Bounded replay of Kubernetes RBAC watch events with gap detection."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .fixture import canonical_json

MAX_HISTORY_BYTES = 10_000_000
MAX_HISTORY_EVENTS = 5_000
SUPPORTED_KINDS = {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "ServiceAccount"}
EVENT_TYPES = {"ADDED", "MODIFIED", "DELETED"}


class ResourceHistoryError(ValueError):
    """Raised when a resource watch replay is unsafe or malformed."""


@dataclass(frozen=True)
class ResourceObservation:
    event_type: str
    kind: str
    name: str
    namespace: str | None
    uid: str
    resource_version: str
    observed_at: str | None
    spec_sha256: str
    artifact_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "kind": self.kind,
            "name": self.name,
            "namespace": self.namespace,
            "uid": self.uid,
            "resource_version": self.resource_version,
            "observed_at": self.observed_at,
            "spec_sha256": self.spec_sha256,
            "artifact_id": self.artifact_id,
        }


@dataclass(frozen=True)
class ResourceHistory:
    observations: tuple[ResourceObservation, ...]
    bookmarks: tuple[str, ...]
    gaps: tuple[str, ...]

    @property
    def continuity_complete(self) -> bool:
        return not self.gaps

    def latest(self) -> dict[tuple[str, str | None, str], ResourceObservation]:
        """Return latest non-deleted observations by object identity.

        This is an ordered replay result, not a proof of complete cluster state;
        callers must inspect ``continuity_complete`` before using it as a full
        snapshot.
        """

        latest: dict[tuple[str, str | None, str], ResourceObservation] = {}
        for observation in self.observations:
            key = (observation.kind, observation.namespace, observation.name)
            if observation.event_type == "DELETED":
                latest.pop(key, None)
            else:
                latest[key] = observation
        return latest

    def to_dict(self) -> dict[str, Any]:
        return {
            "observations": [item.to_dict() for item in self.observations],
            "bookmarks": list(self.bookmarks),
            "gaps": list(self.gaps),
            "continuity_complete": self.continuity_complete,
        }


def _safe_metadata(value: Any, source: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("_", "")
            if normalized in {
                "data",
                "stringdata",
                "token",
                "requestobject",
                "responseobject",
                "requestobjectraw",
                "responseobjectraw",
            }:
                raise ResourceHistoryError(f"{source} contains forbidden field {key}")
            _safe_metadata(child, source)
    elif isinstance(value, list):
        for child in value:
            _safe_metadata(child, source)


def _json_line(line: str, source: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ResourceHistoryError(f"{source} contains duplicate JSON key {key}")
            result[key] = value
        return result

    try:
        value = json.loads(line, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as exc:
        raise ResourceHistoryError(f"{source} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ResourceHistoryError(f"{source} must be an object")
    _safe_metadata(value, source)
    return value


def _required(value: Any, field: str, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ResourceHistoryError(f"{source}.{field} must be a non-empty string")
    return value


def _optional(value: Any, field: str, source: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ResourceHistoryError(f"{source}.{field} must be a string or null")
    return value


def _normalize_role(obj: dict[str, Any], kind: str, source: str) -> dict[str, Any]:
    metadata = obj.get("metadata")
    if not isinstance(metadata, dict):
        raise ResourceHistoryError(f"{source}.object.metadata must be an object")
    namespace = _optional(metadata.get("namespace"), "metadata.namespace", source)
    if kind == "Role" and namespace is None:
        raise ResourceHistoryError(f"{source}.object.metadata.namespace is required for Role")
    if kind == "ClusterRole":
        namespace = None
    raw_rules = obj.get("rules") or []
    if not isinstance(raw_rules, list):
        raise ResourceHistoryError(f"{source}.object.rules must be a list")
    rules: list[dict[str, Any]] = []
    for index, rule in enumerate(raw_rules):
        if not isinstance(rule, dict):
            raise ResourceHistoryError(f"{source}.object.rules[{index}] must be an object")
        resources = list(rule.get("resources") or [])
        verbs = list(rule.get("verbs") or [])
        if not resources or not verbs:
            # Non-resource URL rules are intentionally not part of this model.
            if rule.get("nonResourceURLs") or rule.get("non_resource_urls"):
                continue
            raise ResourceHistoryError(f"{source}.object.rules[{index}] lacks resources or verbs")
        rules.append(
            {
                "api_groups": list(rule.get("apiGroups", rule.get("api_groups", [""])) or [""]),
                "resources": resources,
                "verbs": verbs,
                "resource_names": list(rule.get("resourceNames", rule.get("resource_names", [])) or []),
            }
        )
    return {
        "kind": kind,
        "name": _required(metadata.get("name"), "metadata.name", source),
        "namespace": namespace,
        "uid": _required(metadata.get("uid"), "metadata.uid", source),
        "resource_version": _required(
            metadata.get("resourceVersion", metadata.get("resource_version")),
            "metadata.resourceVersion",
            source,
        ),
        "rules": rules,
        "aggregated": bool(obj.get("aggregationRule", obj.get("aggregation_rule"))),
    }


def _normalize_binding(obj: dict[str, Any], kind: str, source: str) -> dict[str, Any]:
    metadata = obj.get("metadata")
    if not isinstance(metadata, dict):
        raise ResourceHistoryError(f"{source}.object.metadata must be an object")
    namespace = _optional(metadata.get("namespace"), "metadata.namespace", source)
    if kind == "RoleBinding" and namespace is None:
        raise ResourceHistoryError(f"{source}.object.metadata.namespace is required for RoleBinding")
    if kind == "ClusterRoleBinding":
        namespace = None
    raw_subjects = obj.get("subjects") or []
    if not isinstance(raw_subjects, list):
        raise ResourceHistoryError(f"{source}.object.subjects must be a list")
    subjects = []
    for index, subject in enumerate(raw_subjects):
        if not isinstance(subject, dict):
            raise ResourceHistoryError(f"{source}.object.subjects[{index}] must be an object")
        subjects.append(
            {
                "kind": _required(subject.get("kind"), f"subjects[{index}].kind", source),
                "name": _required(subject.get("name"), f"subjects[{index}].name", source),
                "namespace": _optional(subject.get("namespace"), f"subjects[{index}].namespace", source),
            }
        )
    role_ref = obj.get("roleRef", obj.get("role_ref"))
    if not isinstance(role_ref, dict):
        raise ResourceHistoryError(f"{source}.object.roleRef must be an object")
    return {
        "kind": kind,
        "name": _required(metadata.get("name"), "metadata.name", source),
        "namespace": namespace,
        "uid": _required(metadata.get("uid"), "metadata.uid", source),
        "resource_version": _required(
            metadata.get("resourceVersion", metadata.get("resource_version")),
            "metadata.resourceVersion",
            source,
        ),
        "subjects": subjects,
        "role_ref": {
            "kind": _required(role_ref.get("kind"), "roleRef.kind", source),
            "name": _required(role_ref.get("name"), "roleRef.name", source),
            "api_group": _required(
                role_ref.get("apiGroup", role_ref.get("api_group")),
                "roleRef.apiGroup",
                source,
            ),
        },
    }


def _normalize_service_account(obj: dict[str, Any], source: str) -> dict[str, Any]:
    metadata = obj.get("metadata")
    if not isinstance(metadata, dict):
        raise ResourceHistoryError(f"{source}.object.metadata must be an object")
    return {
        "name": _required(metadata.get("name"), "metadata.name", source),
        "namespace": _required(metadata.get("namespace"), "metadata.namespace", source),
        "uid": _required(metadata.get("uid"), "metadata.uid", source),
        "resource_version": _required(
            metadata.get("resourceVersion", metadata.get("resource_version")),
            "metadata.resourceVersion",
            source,
        ),
    }


def _observation(event_type: str, obj: dict[str, Any], source: str) -> ResourceObservation:
    kind = _required(obj.get("kind"), "object.kind", source)
    if kind not in SUPPORTED_KINDS:
        raise ResourceHistoryError(f"{source} contains unsupported kind {kind}")
    if kind in {"Role", "ClusterRole"}:
        normalized = _normalize_role(obj, kind, source)
    elif kind in {"RoleBinding", "ClusterRoleBinding"}:
        normalized = _normalize_binding(obj, kind, source)
    else:
        normalized = _normalize_service_account(obj, source)
    observed_at = obj.get("observedAt", obj.get("observed_at"))
    if observed_at is not None and not isinstance(observed_at, str):
        raise ResourceHistoryError(f"{source}.observedAt must be a string or null")
    normalized_bytes = canonical_json({"kind": kind, "object": normalized})
    spec_sha256 = hashlib.sha256(normalized_bytes).hexdigest()
    return ResourceObservation(
        event_type=event_type,
        kind=kind,
        name=normalized["name"],
        namespace=normalized["namespace"],
        uid=normalized["uid"],
        resource_version=normalized["resource_version"],
        observed_at=observed_at,
        spec_sha256=spec_sha256,
        artifact_id=f"artifact:resource-version:{spec_sha256[:20]}",
    )


def parse_watch_jsonl(
    payload: bytes,
    *,
    max_bytes: int = MAX_HISTORY_BYTES,
    max_events: int = MAX_HISTORY_EVENTS,
) -> ResourceHistory:
    """Parse watch events and preserve explicit continuity gaps."""

    if not isinstance(payload, bytes):
        raise ResourceHistoryError("watch payload must be bytes")
    if len(payload) > max_bytes:
        raise ResourceHistoryError(f"watch payload exceeds the limit of {max_bytes} bytes")
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ResourceHistoryError("watch payload must be UTF-8") from exc
    observations: list[ResourceObservation] = []
    bookmarks: list[str] = []
    gaps: list[str] = []
    seen: dict[tuple[str, str, str | None, str, str], str] = {}
    event_count = 0
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        event_count += 1
        if event_count > max_events:
            raise ResourceHistoryError(f"watch event count exceeds the limit of {max_events}")
        source = f"watch line {line_number}"
        envelope = _json_line(line, source)
        event_type = _required(envelope.get("type"), "type", source)
        obj = envelope.get("object")
        if not isinstance(obj, dict):
            raise ResourceHistoryError(f"{source}.object must be an object")
        if event_type == "BOOKMARK":
            metadata = obj.get("metadata")
            if not isinstance(metadata, dict):
                raise ResourceHistoryError(f"{source}.object.metadata must be an object")
            bookmarks.append(
                _required(
                    metadata.get("resourceVersion", metadata.get("resource_version")),
                    "object.metadata.resourceVersion",
                    source,
                )
            )
            continue
        if event_type == "ERROR":
            code = obj.get("code")
            if code == 410:
                gaps.append("watch resource version expired (HTTP 410); a relist is required")
            else:
                gaps.append(f"watch error received with code {code!r}")
            continue
        if event_type not in EVENT_TYPES:
            raise ResourceHistoryError(f"{source} uses unsupported watch event type {event_type}")
        observation = _observation(event_type, obj, source)
        key = (
            observation.kind,
            observation.uid,
            observation.namespace,
            observation.name,
            observation.resource_version,
        )
        prior_digest = seen.get(key)
        if prior_digest is not None:
            if prior_digest != observation.spec_sha256:
                raise ResourceHistoryError(f"{source} changed an existing resource version")
            continue
        seen[key] = observation.spec_sha256
        observations.append(observation)
    return ResourceHistory(
        observations=tuple(observations),
        bookmarks=tuple(bookmarks),
        gaps=tuple(dict.fromkeys(gaps)),
    )


def parse_watch_file(path: str | Path, **kwargs: int) -> ResourceHistory:
    return parse_watch_jsonl(Path(path).read_bytes(), **kwargs)
