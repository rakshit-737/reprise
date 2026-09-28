"""Small, explicit data contracts for the offline REPRISE slice."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Action:
    verb: str
    api_group: str
    resource: str
    namespace: str | None
    resource_name: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "verb": self.verb,
            "api_group": self.api_group,
            "resource": self.resource,
            "namespace": self.namespace,
            "resource_name": self.resource_name,
        }


@dataclass(frozen=True)
class AuditEvent:
    audit_id: str
    stage: str
    stage_timestamp: str
    verb: str
    username: str
    api_group: str
    resource: str
    namespace: str | None
    resource_name: str | None
    response_code: int | None
    artifact_id: str

    @property
    def action(self) -> Action:
        return Action(
            verb=self.verb,
            api_group=self.api_group,
            resource=self.resource,
            namespace=self.namespace,
            resource_name=self.resource_name,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "stage": self.stage,
            "stage_timestamp": self.stage_timestamp,
            "verb": self.verb,
            "username": self.username,
            "object_ref": {
                "api_group": self.api_group,
                "resource": self.resource,
                "namespace": self.namespace,
                "name": self.resource_name,
            },
            "response_code": self.response_code,
            "artifact_id": self.artifact_id,
        }


@dataclass(frozen=True)
class Rule:
    api_groups: tuple[str, ...]
    resources: tuple[str, ...]
    verbs: tuple[str, ...]
    resource_names: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "api_groups": list(self.api_groups),
            "resources": list(self.resources),
            "verbs": list(self.verbs),
            "resource_names": list(self.resource_names),
        }


@dataclass(frozen=True)
class Role:
    kind: str
    name: str
    namespace: str | None
    uid: str
    resource_version: str | None
    rules: tuple[Rule, ...]
    aggregated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "namespace": self.namespace,
            "uid": self.uid,
            "resource_version": self.resource_version,
            "rules": [rule.to_dict() for rule in self.rules],
            "aggregated": self.aggregated,
        }


@dataclass(frozen=True)
class Subject:
    kind: str
    name: str
    namespace: str | None

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "name": self.name, "namespace": self.namespace}


@dataclass(frozen=True)
class RoleBinding:
    kind: str
    name: str
    namespace: str | None
    uid: str
    resource_version: str | None
    subjects: tuple[Subject, ...]
    role_ref_kind: str
    role_ref_name: str
    role_ref_api_group: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "namespace": self.namespace,
            "uid": self.uid,
            "resource_version": self.resource_version,
            "subjects": [subject.to_dict() for subject in self.subjects],
            "role_ref": {
                "kind": self.role_ref_kind,
                "name": self.role_ref_name,
                "api_group": self.role_ref_api_group,
            },
        }


@dataclass(frozen=True)
class WorkflowContract:
    name: str
    principal: str
    action: Action
    expected: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "principal": self.principal,
            "action": self.action.to_dict(),
            "expected": self.expected,
        }


@dataclass(frozen=True)
class ServiceAccountMetadata:
    name: str
    namespace: str
    uid: str
    resource_version: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "namespace": self.namespace,
            "uid": self.uid,
            "resource_version": self.resource_version,
        }


@dataclass(frozen=True)
class EvidenceArtifact:
    artifact_id: str
    kind: str
    sha256: str
    source: str
    byte_length: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "sha256": self.sha256,
            "source": self.source,
            "byte_length": self.byte_length,
        }


@dataclass(frozen=True)
class Finding:
    finding_id: str
    finding_type: str
    environment_id: str
    principal: str
    action: Action
    access_event_id: str
    access_artifact_id: str
    change_event_ids: tuple[str, ...]
    change_artifact_ids: tuple[str, ...]
    observed_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "environment_id": self.environment_id,
            "principal": self.principal,
            "action": self.action.to_dict(),
            "access_event_id": self.access_event_id,
            "access_artifact_id": self.access_artifact_id,
            "change_event_ids": list(self.change_event_ids),
            "change_artifact_ids": list(self.change_artifact_ids),
            "observed_at": self.observed_at,
        }


@dataclass(frozen=True)
class AuthorizationPath:
    binding_kind: str
    binding_name: str
    binding_namespace: str | None
    binding_uid: str
    role_kind: str
    role_name: str
    role_namespace: str | None
    role_uid: str
    rule_index: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding": {
                "kind": self.binding_kind,
                "name": self.binding_name,
                "namespace": self.binding_namespace,
                "uid": self.binding_uid,
            },
            "role": {
                "kind": self.role_kind,
                "name": self.role_name,
                "namespace": self.role_namespace,
                "uid": self.role_uid,
            },
            "rule_index": self.rule_index,
        }


@dataclass(frozen=True)
class Claim:
    claim_type: str
    epistemic_status: str
    statement: str
    support: tuple[str, ...]
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_type": self.claim_type,
            "epistemic_status": self.epistemic_status,
            "statement": self.statement,
            "support": list(self.support),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class Fixture:
    schema_version: str
    environment: dict[str, Any]
    audit_events: tuple[AuditEvent, ...]
    roles: tuple[Role, ...]
    role_bindings: tuple[RoleBinding, ...]
    workflow_contracts: tuple[WorkflowContract, ...]
    service_accounts: tuple[ServiceAccountMetadata, ...]
    artifacts: tuple[EvidenceArtifact, ...]
    snapshot_artifact_id: str
    source_bytes: bytes
