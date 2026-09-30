"""Deterministic paired shadow validation for remediation proposals."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .contracts import (
    BehaviorValidationContract,
    BenignWorkflowValidationContract,
    CandidateProposalContract,
    ShadowValidationContract,
    validate_evidence_package,
)
from .fixture import canonical_json
from .models import Fixture
from .rbac import enumerate_paths


def _binding_target(binding: Any) -> dict[str, Any]:
    return {
        "kind": binding.kind,
        "name": binding.name,
        "namespace": binding.namespace,
        "uid": binding.uid,
        "resource_version": binding.resource_version,
    }


def _candidate(
    package: dict[str, Any],
    *,
    finding_index: int,
    label: str,
) -> tuple[dict[str, Any], dict[str, Any], CandidateProposalContract]:
    validate_evidence_package(package)
    try:
        finding = package["findings"][finding_index]
    except IndexError as exc:
        raise ValueError(f"finding index is out of range: {finding_index}") from exc
    for candidate in finding["candidate_proposals"]:
        if candidate["label"] == label:
            return finding, candidate, CandidateProposalContract.model_validate(candidate)
    raise ValueError(f"proposal candidate not found: {label}")


def validate_candidate(
    fixture: Fixture,
    package: dict[str, Any],
    *,
    label: str,
    finding_index: int = 0,
) -> ShadowValidationContract:
    """Run attack and benign workflow checks against a virtual binding deletion."""

    finding, candidate_raw, candidate = _candidate(package, finding_index=finding_index, label=label)
    proposal = candidate.proposal
    package_environment_id = package["environment"].get("id")
    fixture_environment_id = fixture.environment.get("id")
    if package_environment_id != fixture_environment_id or finding["environment_id"] != fixture_environment_id:
        raise ValueError("fixture, package, and finding environments do not match")
    snapshot_match = proposal.snapshot_artifact_id == fixture.snapshot_artifact_id
    target_dicts = [mutation.target.model_dump(mode="json") for mutation in proposal.mutations]
    bindings_by_uid = {binding.uid: binding for binding in fixture.role_bindings}
    actual_targets = [_binding_target(bindings_by_uid[target["uid"]]) for target in target_dicts if target["uid"] in bindings_by_uid]
    target_state_match = actual_targets == target_dicts and (hashlib.sha256(canonical_json(actual_targets)).hexdigest() == proposal.state_fingerprint)
    excluded_uids = frozenset(target["uid"] for target in target_dicts)

    principal = finding["principal"]
    action = candidate.proposal.security_objective.action
    action_value = action.model_dump(mode="python")
    from .models import Action

    attack_action = Action(**action_value)
    before_attack = enumerate_paths(fixture, principal, attack_action)
    after_attack = enumerate_paths(
        fixture,
        principal,
        attack_action,
        excluded_binding_uids=excluded_uids,
    )
    counterexamples: list[str] = []
    if not before_attack.allowed:
        counterexamples.append("baseline attack action was not allowed under the supported model")
    if after_attack.allowed:
        counterexamples.extend("surviving authorization path: " + json.dumps(path.to_dict(), sort_keys=True) for path in after_attack.paths)
    attack_passed = before_attack.allowed and not after_attack.allowed and not after_attack.coverage_warnings
    attack = BehaviorValidationContract(
        before_allowed=before_attack.allowed,
        after_allowed=after_attack.allowed,
        expected_after="blocked",
        passed=attack_passed,
        paths_after=[path.to_dict() for path in after_attack.paths],
        coverage_warnings=list(after_attack.coverage_warnings),
    )

    benign_results: list[BenignWorkflowValidationContract] = []
    coverage_warnings = list(after_attack.coverage_warnings)
    for contract in fixture.workflow_contracts:
        if contract.expected != "allowed":
            coverage_warnings.append(f"workflow {contract.name!r} has unsupported expected outcome {contract.expected!r}")
            continue
        before = enumerate_paths(fixture, contract.principal, contract.action)
        after = enumerate_paths(
            fixture,
            contract.principal,
            contract.action,
            excluded_binding_uids=excluded_uids,
        )
        if not before.allowed:
            counterexamples.append(f"benign workflow baseline was not allowed: {contract.name}")
        if not after.allowed:
            counterexamples.append(f"benign workflow would be blocked: {contract.name}")
        coverage_warnings.extend(after.coverage_warnings)
        benign_results.append(
            BenignWorkflowValidationContract(
                name=contract.name,
                before_allowed=before.allowed,
                after_allowed=after.allowed,
                expected_after="allowed",
                passed=before.allowed and after.allowed and not after.coverage_warnings,
                paths_after=[path.to_dict() for path in after.paths],
                coverage_warnings=list(after.coverage_warnings),
            )
        )

    claim_evidence_complete = bool(finding["claim_evidence_complete"])
    if not claim_evidence_complete:
        counterexamples.append("material finding claims do not have complete evidence references")
    if not snapshot_match:
        counterexamples.append("proposal snapshot artifact does not match the supplied fixture snapshot")
    incomplete = bool(coverage_warnings) or not snapshot_match or not target_state_match or not claim_evidence_complete
    behavior_failed = not attack.passed or any(not item.passed for item in benign_results)
    status = "incomplete" if incomplete else ("failed" if behavior_failed else "passed")
    result = {
        "environment_id": package["environment"]["id"],
        "proposal_id": proposal.proposal_id,
        "proposal_digest": candidate.proposal_digest,
        "status": status,
        "snapshot_match": snapshot_match,
        "target_state_match": target_state_match,
        "claim_evidence_complete": claim_evidence_complete,
        "attack": attack.model_dump(mode="json"),
        "benign_workflows": [item.model_dump(mode="json") for item in benign_results],
        "coverage_warnings": list(dict.fromkeys(coverage_warnings)),
        "counterexamples": list(dict.fromkeys(counterexamples)),
        "limitations": [
            "This is deterministic shadow validation against the supplied RBAC fixture; no Kubernetes API request or cluster mutation was executed.",
            "Passing supplied benign workflows does not prove that undisclosed application behavior is preserved.",
            "The result is limited to the supported native-RBAC model and the exact target preconditions in the proposal.",
        ],
    }
    return ShadowValidationContract.model_validate(result)
