"""Strict evidence and remediation contracts.

These models are the boundary between deterministic analysis and any future
agent, API, approval, or execution layer. A model may propose data, but it does
not get to relax these contracts.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = "0.1"
SUPPORTED_MODEL_COVERAGE = (
    "ServiceAccount subjects",
    "RoleBinding to Role",
    "RoleBinding to ClusterRole",
    "ClusterRoleBinding to ClusterRole",
    "explicit API group/resource/verb matching",
    "named resourceNames matching",
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ActionContract(ContractModel):
    verb: str = Field(min_length=1)
    api_group: str
    resource: str = Field(min_length=1)
    namespace: str | None
    resource_name: str | None


class EvidenceArtifactContract(ContractModel):
    artifact_id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    sha256: str = Field(min_length=64, max_length=64)
    source: str = Field(min_length=1)
    byte_length: int = Field(ge=0)


EpistemicStatus = Literal[
    "observed",
    "derived_under_supported_model",
    "hypothesis",
    "contradicted",
    "unknown",
]


class ClaimContract(ContractModel):
    claim_type: str = Field(min_length=1)
    epistemic_status: EpistemicStatus
    statement: str = Field(min_length=1)
    support: list[str] = Field(min_length=1)
    limitations: list[str] = Field(min_length=1)

    @field_validator("support", "limitations")
    @classmethod
    def non_empty_strings(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("contract references and limitations must be non-empty strings")
        return values


class ProposalTargetContract(ContractModel):
    kind: Literal["RoleBinding"]
    name: str = Field(min_length=1)
    namespace: str = Field(min_length=1)
    uid: str = Field(min_length=1)
    resource_version: str = Field(min_length=1)


class ProposalMutationContract(ContractModel):
    action: Literal["delete_role_binding"]
    target: ProposalTargetContract


class SecurityObjectiveContract(ContractModel):
    principal: str = Field(min_length=1)
    action: ActionContract
    expected: Literal["blocked"]


class BenignInvariantContract(ContractModel):
    name: str = Field(min_length=1)
    principal: str = Field(min_length=1)
    action: ActionContract
    expected: Literal["allowed"]


class ValidationContract(ContractModel):
    status: Literal["not_validated", "passed", "failed"]
    artifact_id: str | None = None
    fidelity_notes: list[str] = Field(min_length=1)


class RemediationProposalContract(ContractModel):
    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    proposal_id: str = Field(min_length=1)
    environment_id: str = Field(min_length=1)
    snapshot_artifact_id: str = Field(min_length=1)
    state_fingerprint: str = Field(min_length=64, max_length=64)
    action_class: Literal["delete_role_binding"]
    mutations: list[ProposalMutationContract] = Field(min_length=1)
    security_objective: SecurityObjectiveContract
    benign_invariants: list[BenignInvariantContract]
    model_coverage: list[str] = Field(min_length=1)
    validation: ValidationContract
    execution_status: Literal["not_executed", "approved", "executed", "rejected"]

    @field_validator("mutations")
    @classmethod
    def unique_targets(cls, mutations: list[ProposalMutationContract]) -> list[ProposalMutationContract]:
        identities = [(mutation.target.kind, mutation.target.namespace, mutation.target.name, mutation.target.uid) for mutation in mutations]
        if len(identities) != len(set(identities)):
            raise ValueError("proposal mutations must target unique RoleBindings")
        return mutations

    @field_validator("model_coverage")
    @classmethod
    def non_empty_coverage(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("model coverage entries must be non-empty")
        return values

    @model_validator(mode="after")
    def validate_objective_and_environment(self) -> RemediationProposalContract:
        if self.security_objective.expected != "blocked":
            raise ValueError("the first mutation primitive only supports a blocked objective")
        if self.security_objective.principal == "":
            raise ValueError("security objective principal is required")
        return self

    def canonical_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)

    def digest(self) -> str:
        return hashlib.sha256(_canonical_json(self.canonical_payload())).hexdigest()


class AuthorizationContract(ContractModel):
    principal: str = Field(min_length=1)
    action: ActionContract
    allowed: bool
    paths: list[dict[str, Any]]
    coverage_warnings: list[str]


class CandidateProposalContract(ContractModel):
    label: str = Field(min_length=1)
    proposal: RemediationProposalContract
    proposal_digest: str = Field(min_length=64, max_length=64)
    remaining_paths: list[dict[str, Any]]
    tested_action_blocked_under_supported_model: bool
    coverage_warnings: list[str]

    @model_validator(mode="after")
    def digest_and_effect_match(self) -> CandidateProposalContract:
        if self.proposal_digest != self.proposal.digest():
            raise ValueError("proposal_digest does not match the canonical proposal payload")
        if self.tested_action_blocked_under_supported_model != (not self.remaining_paths):
            raise ValueError("proposal effect does not match its remaining supported paths")
        return self


class BehaviorValidationContract(ContractModel):
    before_allowed: bool
    after_allowed: bool
    expected_after: Literal["blocked", "allowed"]
    passed: bool
    paths_after: list[dict[str, Any]]
    coverage_warnings: list[str]

    @model_validator(mode="after")
    def validate_behavior(self) -> BehaviorValidationContract:
        expected_allowed = self.expected_after == "allowed"
        if self.passed:
            if not self.before_allowed:
                raise ValueError("a passed behavior requires an allowed baseline")
            if self.after_allowed != expected_allowed:
                raise ValueError("passed behavior does not meet its expected after-state")
            if bool(self.paths_after) != self.after_allowed:
                raise ValueError("passed behavior paths do not match its after-state")
            if self.coverage_warnings:
                raise ValueError("passed behavior cannot contain coverage warnings")
        return self


class BenignWorkflowValidationContract(BehaviorValidationContract):
    name: str = Field(min_length=1)


class ShadowValidationContract(ContractModel):
    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    environment_id: str = Field(min_length=1)
    proposal_id: str = Field(min_length=1)
    proposal_digest: str = Field(min_length=64, max_length=64)
    status: Literal["passed", "failed", "incomplete"]
    snapshot_match: bool
    target_state_match: bool
    claim_evidence_complete: bool
    attack: BehaviorValidationContract
    benign_workflows: list[BenignWorkflowValidationContract]
    coverage_warnings: list[str]
    counterexamples: list[str]
    limitations: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_status(self) -> ShadowValidationContract:
        all_behaviors_passed = self.attack.passed and all(workflow.passed for workflow in self.benign_workflows)
        if self.status == "passed" and not (self.snapshot_match and self.target_state_match and self.claim_evidence_complete and all_behaviors_passed):
            raise ValueError("passed validation requires matching snapshot, target state, evidence, and behaviors")
        if self.status == "passed" and (self.coverage_warnings or self.counterexamples):
            raise ValueError("passed validation cannot contain warnings or counterexamples")
        return self


class ApprovalContract(ContractModel):
    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    approval_id: str = Field(min_length=1)
    environment_id: str = Field(min_length=1)
    proposal_digest: str = Field(min_length=64, max_length=64)
    validation_digest: str = Field(min_length=64, max_length=64)
    approver: str = Field(min_length=1)
    nonce: str = Field(min_length=20)
    created_at: str = Field(min_length=1)
    expires_at: str = Field(min_length=1)
    consumed_at: str | None = None


class FindingContract(ContractModel):
    finding_id: str = Field(min_length=1)
    finding_type: str = Field(min_length=1)
    environment_id: str = Field(min_length=1)
    principal: str = Field(min_length=1)
    action: ActionContract
    access_event_id: str = Field(min_length=1)
    access_artifact_id: str = Field(min_length=1)
    change_event_ids: list[str]
    change_artifact_ids: list[str]
    observed_at: str = Field(min_length=1)
    claims: list[ClaimContract] = Field(min_length=1)
    authorization: AuthorizationContract
    candidate_proposals: list[CandidateProposalContract]
    workflow_prechecks: list[dict[str, Any]]
    claim_evidence_complete: bool


class EvidencePackageContract(ContractModel):
    schema_version: Literal[SCHEMA_VERSION] = SCHEMA_VERSION
    package_type: Literal["reprise_incident_evidence"]
    environment: dict[str, Any]
    source: dict[str, Any]
    findings: list[FindingContract]
    artifacts: list[EvidenceArtifactContract]
    limitations: list[str] = Field(min_length=1)


def validate_evidence_package(package: dict[str, Any]) -> EvidencePackageContract:
    """Validate structure, evidence references, and proposal digests."""

    model = EvidencePackageContract.model_validate(package)
    artifact_ids = {artifact.artifact_id for artifact in model.artifacts}
    for finding in model.findings:
        if finding.environment_id != model.environment.get("id"):
            raise ValueError(f"finding {finding.finding_id} crosses the package environment boundary")
        for claim in finding.claims:
            if not set(claim.support).issubset(artifact_ids):
                raise ValueError(f"claim {claim.claim_type} references an unknown artifact")
        for candidate in finding.candidate_proposals:
            proposal = candidate.proposal
            if proposal.environment_id != finding.environment_id:
                raise ValueError(f"proposal {proposal.proposal_id} crosses the finding environment boundary")
            if proposal.security_objective.principal != finding.principal:
                raise ValueError(f"proposal {proposal.proposal_id} is not bound to the finding principal")
            if proposal.security_objective.action != finding.action:
                raise ValueError(f"proposal {proposal.proposal_id} is not bound to the finding action")
            if proposal.snapshot_artifact_id not in artifact_ids:
                raise ValueError(f"proposal {proposal.proposal_id} references an unknown snapshot artifact")
    return model
