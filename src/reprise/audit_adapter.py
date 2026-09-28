"""Bounded Kubernetes Metadata-level audit-event adapter.

The adapter accepts JSON Lines exported from an audit sink. It keeps only the
fields needed by the first detector and rejects request/response bodies and
other secret-bearing fields before normalization.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .fixture import FixtureError, canonical_json, load_fixture_bytes
from .models import Fixture

MAX_AUDIT_LOG_BYTES = 10_000_000
MAX_AUDIT_EVENTS = 5_000


class AuditAdapterError(ValueError):
    """Raised when an audit log is malformed, unsafe, or exceeds its budget."""


def _duplicate_rejecting_json(payload: str, source: str) -> Any:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AuditAdapterError(f"{source} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(payload, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise AuditAdapterError(f"{source} is not valid JSON: {exc}") from exc


def _check_safe_metadata(value: Any, source: str) -> None:
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
                raise AuditAdapterError(f"{source} contains {key}; Metadata-level audit input must not contain bodies or Secret data")
            _check_safe_metadata(child, source)
    elif isinstance(value, list):
        for child in value:
            _check_safe_metadata(child, source)


def _required_string(value: Any, field: str, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AuditAdapterError(f"{source}.{field} must be a non-empty string")
    return value


def _optional_string(value: Any, field: str, source: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise AuditAdapterError(f"{source}.{field} must be a string or null")
    return value


def _timestamp(value: Any, field: str, source: str) -> str:
    timestamp = _required_string(value, field, source)
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuditAdapterError(f"{source}.{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise AuditAdapterError(f"{source}.{field} must include a timezone")
    return timestamp


def normalize_audit_event(raw: Any, *, source: str) -> dict[str, Any]:
    """Normalize one Kubernetes AuditEvent without preserving untrusted extras."""

    if not isinstance(raw, dict):
        raise AuditAdapterError(f"{source} must be a JSON object")
    _check_safe_metadata(raw, source)
    user = raw.get("user")
    object_ref = raw.get("objectRef", raw.get("object_ref"))
    if not isinstance(user, dict):
        raise AuditAdapterError(f"{source}.user must be an object")
    if not isinstance(object_ref, dict):
        raise AuditAdapterError(f"{source}.objectRef must be an object")
    response_status = raw.get("responseStatus", raw.get("response_status"))
    response_code = response_status.get("code") if isinstance(response_status, dict) else None
    if response_code is not None and (not isinstance(response_code, int) or response_code < 100 or response_code > 599):
        raise AuditAdapterError(f"{source}.responseStatus.code must be an HTTP-like integer")
    timestamp = raw.get("stageTimestamp") or raw.get("stage_timestamp")
    if timestamp is None:
        timestamp = raw.get("requestReceivedTimestamp") or raw.get("request_received_timestamp")
    api_group = object_ref.get("apiGroup", object_ref.get("api_group", ""))
    if api_group is None:
        api_group = ""
    if not isinstance(api_group, str):
        raise AuditAdapterError(f"{source}.objectRef.apiGroup must be a string")
    return {
        "audit_id": _required_string(raw.get("auditID", raw.get("audit_id")), "auditID", source),
        "stage": _required_string(raw.get("stage"), "stage", source),
        "stage_timestamp": _timestamp(timestamp, "stageTimestamp", source),
        "verb": _required_string(raw.get("verb"), "verb", source),
        "user": {"username": _required_string(user.get("username"), "user.username", source)},
        "object_ref": {
            "api_group": api_group,
            "resource": _required_string(object_ref.get("resource"), "objectRef.resource", source),
            "namespace": _optional_string(object_ref.get("namespace"), "objectRef.namespace", source),
            "name": _optional_string(object_ref.get("name"), "objectRef.name", source),
        },
        "response_code": response_code,
    }


def parse_audit_jsonl(
    payload: bytes,
    *,
    max_bytes: int = MAX_AUDIT_LOG_BYTES,
    max_events: int = MAX_AUDIT_EVENTS,
) -> list[dict[str, Any]]:
    """Parse bounded JSON Lines and return normalized metadata-only events."""

    if not isinstance(payload, bytes):
        raise AuditAdapterError("audit payload must be bytes")
    if len(payload) > max_bytes:
        raise AuditAdapterError(f"audit payload exceeds the limit of {max_bytes} bytes")
    events: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise AuditAdapterError("audit payload must be UTF-8") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        if len(events) >= max_events:
            raise AuditAdapterError(f"audit event count exceeds the limit of {max_events}")
        source = f"audit line {line_number}"
        raw = _duplicate_rejecting_json(line, source)
        event = normalize_audit_event(raw, source=source)
        identity = (event["audit_id"], event["stage"])
        if identity in identities:
            raise AuditAdapterError(f"duplicate audit_id/stage identity: {identity[0]}/{identity[1]}")
        identities.add(identity)
        events.append(event)
    return events


def merge_audit_events(fixture: Fixture, events: list[dict[str, Any]]) -> Fixture:
    """Return a new fixture with normalized events attached to the same snapshot."""

    try:
        raw_fixture = json.loads(fixture.source_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditAdapterError("base fixture source bytes are not valid JSON") from exc
    if not isinstance(raw_fixture, dict):
        raise AuditAdapterError("base fixture root must be an object")
    raw_fixture["audit_events"] = events
    try:
        return load_fixture_bytes(canonical_json(raw_fixture))
    except FixtureError as exc:
        raise AuditAdapterError(f"merged audit fixture failed validation: {exc}") from exc


def parse_audit_file(path: str | Path, **kwargs: int) -> list[dict[str, Any]]:
    return parse_audit_jsonl(Path(path).read_bytes(), **kwargs)
