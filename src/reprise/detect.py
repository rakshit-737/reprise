"""Deterministic detection for the first REPRISE incident family."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

from .models import AuditEvent, Finding, Fixture

DEFAULT_CHANGE_WINDOW = timedelta(minutes=30)
SUCCESS_CODES = range(200, 300)
RBAC_API_GROUP = "rbac.authorization.k8s.io"


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed


def _is_role_binding_change(event: AuditEvent) -> bool:
    return event.api_group == RBAC_API_GROUP and event.resource == "rolebindings" and event.verb in {"create", "update", "patch"}


def _is_successful_named_secret_read(event: AuditEvent) -> bool:
    return event.verb == "get" and event.api_group == "" and event.resource == "secrets" and event.resource_name is not None and event.response_code in SUCCESS_CODES


def _finding_id(environment_id: str, access: AuditEvent) -> str:
    value = f"{environment_id}|{access.audit_id}|{access.stage}|{access.resource_name}"
    return f"finding:{hashlib.sha256(value.encode('utf-8')).hexdigest()[:20]}"


def detect_findings(
    fixture: Fixture,
    *,
    change_window: timedelta = DEFAULT_CHANGE_WINDOW,
) -> tuple[Finding, ...]:
    """Find successful named Secret reads following a RoleBinding change.

    This rule identifies a reproducible sequence; it does not attribute intent,
    prove compromise, or assert that the binding caused the access.
    """

    changes = [event for event in fixture.audit_events if _is_role_binding_change(event)]
    accesses = [event for event in fixture.audit_events if _is_successful_named_secret_read(event)]
    findings: list[Finding] = []

    for access in accesses:
        access_time = parse_timestamp(access.stage_timestamp)
        relevant_changes = []
        for change in changes:
            change_time = parse_timestamp(change.stage_timestamp)
            if timedelta(0) <= access_time - change_time <= change_window:
                relevant_changes.append(change)
        if not relevant_changes:
            continue
        relevant_changes.sort(key=lambda event: parse_timestamp(event.stage_timestamp))
        findings.append(
            Finding(
                finding_id=_finding_id(fixture.environment["id"], access),
                finding_type="rolebinding_change_followed_by_named_secret_read",
                environment_id=fixture.environment["id"],
                principal=access.username,
                action=access.action,
                access_event_id=access.audit_id,
                access_artifact_id=access.artifact_id,
                change_event_ids=tuple(event.audit_id for event in relevant_changes),
                change_artifact_ids=tuple(event.artifact_id for event in relevant_changes),
                observed_at=access.stage_timestamp,
            )
        )

    return tuple(findings)
