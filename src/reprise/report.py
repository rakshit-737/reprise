"""Evidence-linked package and readable report generation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .artifacts import ArtifactStore
from .contracts import (
    SUPPORTED_MODEL_COVERAGE,
    ActionContract,
    BenignInvariantContract,
    CandidateProposalContract,
    ProposalMutationContract,
    ProposalTargetContract,
    RemediationProposalContract,
    SecurityObjectiveContract,
    ValidationContract,
    validate_evidence_package,
)
from .detect import detect_findings
from .fixture import canonical_json
from .models import Fixture, RoleBinding
from .rbac import PathAnalysis, enumerate_paths


def _binding_dict(binding: RoleBinding) -> dict[str, Any]:
    return {
        "kind": binding.kind,
        "name": binding.name,
        "namespace": binding.namespace,
        "uid": binding.uid,
        "resource_version": binding.resource_version,
    }


def _proposal(
    fixture: Fixture,
    path_analysis: PathAnalysis,
    binding_uids: tuple[str, ...],
    *,
    label: str,
) -> dict[str, Any]:
    remaining = enumerate_paths(
        fixture,
        path_analysis.principal,
        path_analysis.action,
        excluded_binding_uids=frozenset(binding_uids),
    )
    binding_by_uid = {binding.uid: binding for binding in fixture.role_bindings}
    targets = [_binding_dict(binding_by_uid[uid]) for uid in binding_uids if uid in binding_by_uid]
    target_models = [ProposalTargetContract.model_validate(target) for target in targets]
    mutations = [ProposalMutationContract(action="delete_role_binding", target=target) for target in target_models]
    benign_invariants = [
        BenignInvariantContract(
            name=contract.name,
            principal=contract.principal,
            action=ActionContract.model_validate(contract.action.to_dict()),
            expected="allowed",
        )
        for contract in fixture.workflow_contracts
        if contract.expected == "allowed"
    ]
    state_fingerprint = hashlib.sha256(canonical_json(targets)).hexdigest()
    proposal_seed = {
        "environment_id": fixture.environment["id"],
        "label": label,
        "action": path_analysis.action.to_dict(),
        "target_uids": list(binding_uids),
    }
    proposal_id = f"proposal:{hashlib.sha256(canonical_json(proposal_seed)).hexdigest()[:20]}"
    proposal = RemediationProposalContract(
        proposal_id=proposal_id,
        environment_id=fixture.environment["id"],
        snapshot_artifact_id=fixture.snapshot_artifact_id,
        state_fingerprint=state_fingerprint,
        action_class="delete_role_binding",
        mutations=mutations,
        security_objective=SecurityObjectiveContract(
            principal=path_analysis.principal,
            action=ActionContract.model_validate(path_analysis.action.to_dict()),
            expected="blocked",
        ),
        benign_invariants=benign_invariants,
        model_coverage=list(SUPPORTED_MODEL_COVERAGE),
        validation=ValidationContract(
            status="not_validated",
            artifact_id=None,
            fidelity_notes=[
                "This proposal was checked against the offline RBAC snapshot only.",
                "No live API request, SubjectAccessReview, or isolated lab run occurred.",
            ],
        ),
        execution_status="not_executed",
    )
    candidate = CandidateProposalContract(
        label=label,
        proposal=proposal,
        proposal_digest=proposal.digest(),
        remaining_paths=[path.to_dict() for path in remaining.paths],
        tested_action_blocked_under_supported_model=not remaining.allowed,
        coverage_warnings=list(remaining.coverage_warnings),
    )
    return candidate.model_dump(mode="json")


def _claim_support_is_valid(claims: list[dict[str, Any]], artifact_ids: set[str]) -> bool:
    return all(claim.get("support") and all(ref in artifact_ids for ref in claim["support"]) for claim in claims)


def build_evidence_package(
    fixture: Fixture,
    *,
    artifact_store: ArtifactStore | None = None,
    source_mode: str = "offline_fixture",
    package_limitations: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    findings = detect_findings(fixture)
    artifact_ids = {artifact.artifact_id for artifact in fixture.artifacts}
    finding_reports: list[dict[str, Any]] = []

    for finding in findings:
        path_analysis = enumerate_paths(fixture, finding.principal, finding.action)
        claims: list[dict[str, Any]] = [
            {
                "claim_type": "observed_api_action",
                "epistemic_status": "observed",
                "statement": (
                    f"{finding.principal} successfully performed {finding.action.verb} "
                    f"on {finding.action.resource}/{finding.action.resource_name} in "
                    f"namespace {finding.action.namespace}."
                ),
                "support": [finding.access_artifact_id],
                "limitations": [
                    "A successful Kubernetes API response establishes observed API access, not external exfiltration.",
                    "The service-account identity does not identify the human or workload controller behind the credential.",
                ],
            },
            {
                "claim_type": "observed_permission_change",
                "epistemic_status": "observed",
                "statement": (f"{len(finding.change_event_ids)} RoleBinding change event(s) preceded the observed access within the configured detection window."),
                "support": list(finding.change_artifact_ids),
                "limitations": [
                    "Temporal correlation does not by itself prove that a change caused the access.",
                    "No claim about authorization intent is made by this detector.",
                ],
            },
        ]
        if path_analysis.paths:
            claims.append(
                {
                    "claim_type": "supported_authorization_paths",
                    "epistemic_status": "derived_under_supported_model",
                    "statement": (f"The supplied RBAC snapshot contains {len(path_analysis.paths)} independent supported grant path(s) for the observed action."),
                    "support": [fixture.snapshot_artifact_id],
                    "limitations": [
                        "This is a snapshot analysis, not proof of historical authorization at the exact event instant.",
                        "Unsupported authorizers and indirect privilege paths are not modeled.",
                        *path_analysis.coverage_warnings,
                    ],
                }
            )
        else:
            claims.append(
                {
                    "claim_type": "authorization_coverage_gap",
                    "epistemic_status": "unknown",
                    "statement": "The supplied snapshot did not yield a supported matching grant path.",
                    "support": [fixture.snapshot_artifact_id],
                    "limitations": [
                        "This does not establish that the API action was unauthorized; the snapshot may be incomplete or use unsupported semantics.",
                        *path_analysis.coverage_warnings,
                    ],
                }
            )

        path_uids = tuple(dict.fromkeys(path.binding_uid for path in path_analysis.paths))
        proposals: list[dict[str, Any]] = []
        binding_by_uid = {binding.uid: binding for binding in fixture.role_bindings}
        proposal_targets_are_complete = all(
            binding_by_uid[uid].kind == "RoleBinding" and binding_by_uid[uid].namespace is not None and binding_by_uid[uid].resource_version is not None
            for uid in path_uids
            if uid in binding_by_uid
        )
        if path_uids and proposal_targets_are_complete:
            proposals.append(_proposal(fixture, path_analysis, (path_uids[0],), label="naive_first_path_only"))
            if len(path_uids) > 1:
                proposals.append(_proposal(fixture, path_analysis, path_uids, label="all_supported_paths"))

        workflow_prechecks = []
        for contract in fixture.workflow_contracts:
            precheck = enumerate_paths(fixture, contract.principal, contract.action)
            workflow_prechecks.append(
                {
                    **contract.to_dict(),
                    "static_rbac_precheck": "allowed" if precheck.allowed else "not_allowed_under_supported_model",
                    "paths": [path.to_dict() for path in precheck.paths],
                    "coverage_warnings": list(precheck.coverage_warnings),
                    "execution_status": "not_executed",
                }
            )

        finding_report = finding.to_dict()
        finding_report.update(
            {
                "claims": claims,
                "authorization": path_analysis.to_dict(),
                "candidate_proposals": proposals,
                "workflow_prechecks": workflow_prechecks,
                "claim_evidence_complete": _claim_support_is_valid(claims, artifact_ids),
            }
        )
        finding_reports.append(finding_report)

    source = {
        "mode": source_mode,
        "schema_version": fixture.schema_version,
        "source_sha256": hashlib.sha256(fixture.source_bytes).hexdigest(),
    }
    artifacts = list(fixture.artifacts)
    if artifact_store is not None:
        persisted = artifact_store.persist_fixture(fixture)
        source["source_artifact_id"] = persisted["source"].artifact_id
        if persisted["source"].artifact_id not in artifact_ids:
            artifacts.append(persisted["source"])

    package = {
        "schema_version": "0.1",
        "package_type": "reprise_incident_evidence",
        "environment": fixture.environment,
        "source": source,
        "findings": finding_reports,
        "artifacts": [artifact.to_dict() for artifact in artifacts],
        "limitations": list(
            package_limitations
            or (
                "No live Kubernetes SubjectAccessReview or API request was executed.",
                "No Secret contents were ingested; the named object is synthetic.",
                "Candidate proposals are analysis outputs only and were not approved or executed.",
            )
        ),
    }
    validate_evidence_package(package)
    return package


def render_markdown(package: dict[str, Any]) -> str:
    environment = package["environment"]
    lines = [
        "# REPRISE incident evidence package",
        "",
        f"- **Environment:** `{environment['id']}`",
        f"- **Mode:** `{package['source']['mode']}`",
        f"- **Findings:** {len(package['findings'])}",
        "",
        "> This report distinguishes observed activity from derived authorization paths. It does not claim compromise or complete cluster security.",
        "",
    ]
    for index, finding in enumerate(package["findings"], start=1):
        lines.extend(
            [
                f"## Finding {index}: `{finding['finding_type']}`",
                "",
                f"- **Principal:** `{finding['principal']}`",
                f"- **Observed at:** `{finding['observed_at']}`",
                f"- **Action:** `{finding['action']['verb']}` `{finding['action']['resource']}/{finding['action']['resource_name']}` in `{finding['action']['namespace']}`",
                f"- **Claim evidence complete:** `{finding['claim_evidence_complete']}`",
                "",
                "### Claims",
                "",
                "| Status | Type | Statement | Evidence |",
                "|---|---|---|---|",
            ]
        )
        for claim in finding["claims"]:
            statement = claim["statement"].replace("|", "\\|")
            evidence = ", ".join(f"`{ref}`" for ref in claim["support"])
            lines.append(f"| `{claim['epistemic_status']}` | `{claim['claim_type']}` | {statement} | {evidence} |")
        lines.extend(["", "### Supported authorization paths", ""])
        paths = finding["authorization"]["paths"]
        if paths:
            lines.append("| Binding | Role | Rule |")
            lines.append("|---|---|---|")
            for path in paths:
                binding = path["binding"]
                role = path["role"]
                lines.append(f"| `{binding['kind']}/{binding['name']}` | `{role['kind']}/{role['name']}` | `{path['rule_index']}` |")
        else:
            lines.append("No supported path was found; this is an incomplete result, not a denial proof.")
        lines.extend(["", "### Candidate proposal comparison", ""])
        if finding["candidate_proposals"]:
            lines.append("| Candidate | Mutations | Remaining paths | Tested action |")
            lines.append("|---|---:|---:|---|")
            for proposal in finding["candidate_proposals"]:
                lines.append(
                    f"| `{proposal['label']}` | {len(proposal['proposal']['mutations'])} | {len(proposal['remaining_paths'])} | "
                    f"`{'blocked' if proposal['tested_action_blocked_under_supported_model'] else 'still allowed'}` |"
                )
        else:
            lines.append("No candidate was generated because no supported path was available.")
        lines.extend(["", "### Benign workflow prechecks", ""])
        if finding["workflow_prechecks"]:
            lines.append("| Contract | Expected | Static precheck | Execution |")
            lines.append("|---|---|---|---|")
            for contract in finding["workflow_prechecks"]:
                lines.append(f"| `{contract['name']}` | `{contract['expected']}` | `{contract['static_rbac_precheck']}` | `{contract['execution_status']}` |")
        else:
            lines.append("No benign workflow contracts were supplied.")
        lines.extend(["", "### Coverage warnings", ""])
        warnings = finding["authorization"]["coverage_warnings"]
        if warnings:
            lines.extend(f"- {warning}" for warning in warnings)
        else:
            lines.append("- None recorded.")
        lines.append("")

    lines.extend(["## Package limitations", ""])
    lines.extend(f"- {limitation}" for limitation in package["limitations"])
    lines.append("")
    return "\n".join(lines)


def write_outputs(package: dict[str, Any], output_dir: str | Path) -> tuple[Path, Path]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / "evidence-package.json"
    markdown_path = directory / "report.md"
    json_path.write_text(json.dumps(package, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(package), encoding="utf-8")
    return json_path, markdown_path
