"""Bounded, metadata-only fixture loading and artifact hashing."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import (
    Action,
    AuditEvent,
    EvidenceArtifact,
    Fixture,
    Role,
    RoleBinding,
    Rule,
    ServiceAccountMetadata,
    Subject,
    WorkflowContract,
)

MAX_FIXTURE_BYTES = 1_000_000
MAX_AUDIT_EVENTS = 5_000
MAX_ROLES = 2_000
MAX_BINDINGS = 5_000
MAX_SERVICE_ACCOUNTS = 5_000
MAX_RULES_PER_ROLE = 200

SENSITIVE_KEYS = {
    "data",
    "stringdata",
    "token",
    "requestobject",
    "responseobject",
    "requestobjectraw",
    "responseobjectraw",
}


class FixtureError(ValueError):
    """Raised when a fixture is malformed or violates safety limits."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _artifact(kind: str, source: str, payload: Any) -> EvidenceArtifact:
    encoded = canonical_json(payload)
    digest = hashlib.sha256(encoded).hexdigest()
    return EvidenceArtifact(
        artifact_id=f"artifact:{kind}:{digest[:20]}",
        kind=kind,
        sha256=digest,
        source=source,
        byte_length=len(encoded),
    )


def _check_sensitive_keys(value: Any, path: str = "fixture") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = str(key).lower().replace("_", "")
            if normalized_key in SENSITIVE_KEYS:
                raise FixtureError(f"sensitive field {path}.{key} is not accepted; use metadata-only fixtures")
            _check_sensitive_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_sensitive_keys(child, f"{path}[{index}]")


def _required_str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FixtureError(f"{field} must be a non-empty string")
    return value


def _optional_str(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise FixtureError(f"{field} must be a string or null")
    return value


def _timestamp(value: Any, field: str) -> str:
    timestamp = _required_str(value, field)
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FixtureError(f"{field} must be an ISO-8601 timestamp with timezone") from exc
    if parsed.tzinfo is None:
        raise FixtureError(f"{field} must include a timezone")
    return timestamp


def _string_tuple(
    value: Any,
    field: str,
    *,
    allow_empty: bool = True,
    allow_blank_items: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise FixtureError(f"{field} must be a list")
    result_items: list[str] = []
    for index, item in enumerate(value):
        if allow_blank_items and item == "":
            result_items.append(item)
        else:
            result_items.append(_required_str(item, f"{field}[{index}]"))
    result = tuple(result_items)
    if not allow_empty and not result:
        raise FixtureError(f"{field} must not be empty")
    return result


def _parse_action(raw: Any, field: str) -> Action:
    if not isinstance(raw, dict):
        raise FixtureError(f"{field} must be an object")
    api_group = raw.get("api_group", "")
    if not isinstance(api_group, str):
        raise FixtureError(f"{field}.api_group must be a string")
    return Action(
        verb=_required_str(raw.get("verb"), f"{field}.verb"),
        api_group=api_group,
        resource=_required_str(raw.get("resource"), f"{field}.resource"),
        namespace=_optional_str(raw.get("namespace"), f"{field}.namespace"),
        resource_name=_optional_str(raw.get("resource_name"), f"{field}.resource_name"),
    )


def _parse_audit_event(raw: Any, index: int) -> tuple[AuditEvent, EvidenceArtifact]:
    field = f"audit_events[{index}]"
    if not isinstance(raw, dict):
        raise FixtureError(f"{field} must be an object")
    user = raw.get("user")
    object_ref = raw.get("object_ref")
    if not isinstance(user, dict) or not isinstance(object_ref, dict):
        raise FixtureError(f"{field}.user and {field}.object_ref must be objects")
    response_code = raw.get("response_code")
    if response_code is None and isinstance(raw.get("response_status"), dict):
        response_code = raw["response_status"].get("code")
    if response_code is not None and (not isinstance(response_code, int) or response_code < 100 or response_code > 599):
        raise FixtureError(f"{field}.response_code must be an HTTP-like integer")
    normalized = {
        "audit_id": _required_str(raw.get("audit_id"), f"{field}.audit_id"),
        "stage": _required_str(raw.get("stage"), f"{field}.stage"),
        "stage_timestamp": _timestamp(raw.get("stage_timestamp"), f"{field}.stage_timestamp"),
        "verb": _required_str(raw.get("verb"), f"{field}.verb"),
        "user": {"username": _required_str(user.get("username"), f"{field}.user.username")},
        "object_ref": {
            "api_group": object_ref.get("api_group", ""),
            "resource": _required_str(object_ref.get("resource"), f"{field}.object_ref.resource"),
            "namespace": _optional_str(object_ref.get("namespace"), f"{field}.object_ref.namespace"),
            "name": _optional_str(object_ref.get("name"), f"{field}.object_ref.name"),
        },
        "response_code": response_code,
    }
    if not isinstance(normalized["object_ref"]["api_group"], str):
        raise FixtureError(f"{field}.object_ref.api_group must be a string")
    artifact = _artifact("audit-event", normalized["audit_id"], normalized)
    event = AuditEvent(
        audit_id=normalized["audit_id"],
        stage=normalized["stage"],
        stage_timestamp=normalized["stage_timestamp"],
        verb=normalized["verb"],
        username=normalized["user"]["username"],
        api_group=normalized["object_ref"]["api_group"],
        resource=normalized["object_ref"]["resource"],
        namespace=normalized["object_ref"]["namespace"],
        resource_name=normalized["object_ref"]["name"],
        response_code=response_code,
        artifact_id=artifact.artifact_id,
    )
    return event, artifact


def _parse_rule(raw: Any, field: str) -> Rule:
    if not isinstance(raw, dict):
        raise FixtureError(f"{field} must be an object")
    return Rule(
        api_groups=_string_tuple(
            raw.get("api_groups", [""]),
            f"{field}.api_groups",
            allow_empty=False,
            allow_blank_items=True,
        ),
        resources=_string_tuple(raw.get("resources"), f"{field}.resources", allow_empty=False),
        verbs=_string_tuple(raw.get("verbs"), f"{field}.verbs", allow_empty=False),
        resource_names=_string_tuple(raw.get("resource_names", []), f"{field}.resource_names"),
    )


def _parse_role(raw: Any, index: int) -> Role:
    field = f"roles[{index}]"
    if not isinstance(raw, dict):
        raise FixtureError(f"{field} must be an object")
    kind = _required_str(raw.get("kind"), f"{field}.kind")
    if kind not in {"Role", "ClusterRole"}:
        raise FixtureError(f"{field}.kind must be Role or ClusterRole")
    namespace = _optional_str(raw.get("namespace"), f"{field}.namespace")
    if kind == "Role" and namespace is None:
        raise FixtureError(f"{field}.namespace is required for Role")
    if kind == "ClusterRole" and namespace is not None:
        raise FixtureError(f"{field}.namespace must be null for ClusterRole")
    raw_rules = raw.get("rules")
    if not isinstance(raw_rules, list):
        raise FixtureError(f"{field}.rules must be a list")
    if len(raw_rules) > MAX_RULES_PER_ROLE:
        raise FixtureError(f"{field}.rules exceeds the limit")
    return Role(
        kind=kind,
        name=_required_str(raw.get("name"), f"{field}.name"),
        namespace=namespace,
        uid=_required_str(raw.get("uid"), f"{field}.uid"),
        resource_version=_optional_str(raw.get("resource_version"), f"{field}.resource_version"),
        rules=tuple(_parse_rule(rule, f"{field}.rules[{rule_index}]") for rule_index, rule in enumerate(raw_rules)),
        aggregated=bool(raw.get("aggregated", False)),
    )


def _parse_subject(raw: Any, field: str) -> Subject:
    if not isinstance(raw, dict):
        raise FixtureError(f"{field} must be an object")
    kind = _required_str(raw.get("kind"), f"{field}.kind")
    return Subject(
        kind=kind,
        name=_required_str(raw.get("name"), f"{field}.name"),
        namespace=_optional_str(raw.get("namespace"), f"{field}.namespace"),
    )


def _parse_binding(raw: Any, index: int) -> RoleBinding:
    field = f"role_bindings[{index}]"
    if not isinstance(raw, dict):
        raise FixtureError(f"{field} must be an object")
    kind = _required_str(raw.get("kind"), f"{field}.kind")
    if kind not in {"RoleBinding", "ClusterRoleBinding"}:
        raise FixtureError(f"{field}.kind must be RoleBinding or ClusterRoleBinding")
    namespace = _optional_str(raw.get("namespace"), f"{field}.namespace")
    if kind == "RoleBinding" and namespace is None:
        raise FixtureError(f"{field}.namespace is required for RoleBinding")
    if kind == "ClusterRoleBinding" and namespace is not None:
        raise FixtureError(f"{field}.namespace must be null for ClusterRoleBinding")
    raw_subjects = raw.get("subjects")
    role_ref = raw.get("role_ref")
    if not isinstance(raw_subjects, list):
        raise FixtureError(f"{field}.subjects must be a list")
    if not isinstance(role_ref, dict):
        raise FixtureError(f"{field}.role_ref must be an object")
    return RoleBinding(
        kind=kind,
        name=_required_str(raw.get("name"), f"{field}.name"),
        namespace=namespace,
        uid=_required_str(raw.get("uid"), f"{field}.uid"),
        resource_version=_optional_str(raw.get("resource_version"), f"{field}.resource_version"),
        subjects=tuple(_parse_subject(subject, f"{field}.subjects[{subject_index}]") for subject_index, subject in enumerate(raw_subjects)),
        role_ref_kind=_required_str(role_ref.get("kind"), f"{field}.role_ref.kind"),
        role_ref_name=_required_str(role_ref.get("name"), f"{field}.role_ref.name"),
        role_ref_api_group=_required_str(
            role_ref.get("api_group", "rbac.authorization.k8s.io"),
            f"{field}.role_ref.api_group",
        ),
    )


def _parse_workflow(raw: Any, index: int) -> WorkflowContract:
    field = f"workflow_contracts[{index}]"
    if not isinstance(raw, dict):
        raise FixtureError(f"{field} must be an object")
    return WorkflowContract(
        name=_required_str(raw.get("name"), f"{field}.name"),
        principal=_required_str(raw.get("principal"), f"{field}.principal"),
        action=_parse_action(raw.get("action"), f"{field}.action"),
        expected=_required_str(raw.get("expected"), f"{field}.expected"),
    )


def _parse_service_account(raw: Any, index: int) -> ServiceAccountMetadata:
    field = f"service_accounts[{index}]"
    if not isinstance(raw, dict):
        raise FixtureError(f"{field} must be an object")
    namespace = _required_str(raw.get("namespace"), f"{field}.namespace")
    return ServiceAccountMetadata(
        name=_required_str(raw.get("name"), f"{field}.name"),
        namespace=namespace,
        uid=_required_str(raw.get("uid"), f"{field}.uid"),
        resource_version=_optional_str(raw.get("resource_version"), f"{field}.resource_version"),
    )


def load_fixture_bytes(payload: bytes, *, max_bytes: int = MAX_FIXTURE_BYTES) -> Fixture:
    """Load and validate a metadata-only JSON payload."""

    if not isinstance(payload, bytes):
        raise FixtureError("fixture payload must be bytes")
    if len(payload) > max_bytes:
        raise FixtureError(f"fixture is {len(payload)} bytes; limit is {max_bytes}")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise FixtureError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        raw = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FixtureError(f"fixture is not valid UTF-8 JSON: {exc}") from exc
    _check_sensitive_keys(raw)
    if not isinstance(raw, dict):
        raise FixtureError("fixture root must be an object")

    environment = raw.get("environment")
    if not isinstance(environment, dict):
        raise FixtureError("environment must be an object")
    environment_id = _required_str(environment.get("id"), "environment.id")
    environment = dict(environment)
    environment["id"] = environment_id

    raw_events = raw.get("audit_events", [])
    raw_roles = raw.get("roles", [])
    raw_bindings = raw.get("role_bindings", [])
    raw_workflows = raw.get("workflow_contracts", [])
    raw_service_accounts = raw.get("service_accounts", [])
    for name, value, limit in (
        ("audit_events", raw_events, MAX_AUDIT_EVENTS),
        ("roles", raw_roles, MAX_ROLES),
        ("role_bindings", raw_bindings, MAX_BINDINGS),
    ):
        if not isinstance(value, list):
            raise FixtureError(f"{name} must be a list")
        if len(value) > limit:
            raise FixtureError(f"{name} exceeds the limit of {limit}")
    if not isinstance(raw_workflows, list):
        raise FixtureError("workflow_contracts must be a list")
    if not isinstance(raw_service_accounts, list):
        raise FixtureError("service_accounts must be a list")
    if len(raw_service_accounts) > MAX_SERVICE_ACCOUNTS:
        raise FixtureError(f"service_accounts exceeds the limit of {MAX_SERVICE_ACCOUNTS}")

    parsed_events: list[AuditEvent] = []
    artifacts: list[EvidenceArtifact] = []
    for index, event in enumerate(raw_events):
        parsed_event, artifact = _parse_audit_event(event, index)
        parsed_events.append(parsed_event)
        artifacts.append(artifact)
    event_keys = [(event.audit_id, event.stage) for event in parsed_events]
    if len(event_keys) != len(set(event_keys)):
        raise FixtureError("audit_events contains duplicate audit_id/stage identities")

    roles = tuple(_parse_role(role, index) for index, role in enumerate(raw_roles))
    bindings = tuple(_parse_binding(binding, index) for index, binding in enumerate(raw_bindings))
    workflows = tuple(_parse_workflow(workflow, index) for index, workflow in enumerate(raw_workflows))
    service_accounts = tuple(_parse_service_account(service_account, index) for index, service_account in enumerate(raw_service_accounts))

    role_keys = [(role.kind, role.namespace, role.name) for role in roles]
    if len(role_keys) != len(set(role_keys)):
        raise FixtureError("roles contains duplicate kind/namespace/name identities")
    binding_keys = [(binding.kind, binding.namespace, binding.name) for binding in bindings]
    if len(binding_keys) != len(set(binding_keys)):
        raise FixtureError("role_bindings contains duplicate kind/namespace/name identities")
    service_account_keys = [(item.namespace, item.name) for item in service_accounts]
    if len(service_account_keys) != len(set(service_account_keys)):
        raise FixtureError("service_accounts contains duplicate namespace/name identities")

    snapshot_payload = {
        "environment": environment,
        "service_accounts": [item.to_dict() for item in service_accounts],
        "roles": [role.to_dict() for role in roles],
        "role_bindings": [binding.to_dict() for binding in bindings],
    }
    snapshot_artifact = _artifact("rbac-snapshot", environment_id, snapshot_payload)
    artifacts.append(snapshot_artifact)

    return Fixture(
        schema_version=_required_str(raw.get("schema_version", "0.1"), "schema_version"),
        environment=environment,
        audit_events=tuple(parsed_events),
        roles=roles,
        role_bindings=bindings,
        workflow_contracts=workflows,
        service_accounts=service_accounts,
        artifacts=tuple(artifacts),
        snapshot_artifact_id=snapshot_artifact.artifact_id,
        source_bytes=payload,
    )


def load_fixture(path: str | Path, *, max_bytes: int = MAX_FIXTURE_BYTES) -> Fixture:
    """Load a metadata-only fixture from a filesystem path."""

    return load_fixture_bytes(Path(path).read_bytes(), max_bytes=max_bytes)
