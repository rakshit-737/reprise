import copy

import pytest
from pydantic import ValidationError

from reprise.contracts import (
    CandidateProposalContract,
    ClaimContract,
    validate_evidence_package,
)
from reprise.fixture import load_fixture
from reprise.report import build_evidence_package


def test_claim_contract_requires_limitations_and_support():
    with pytest.raises(ValidationError):
        ClaimContract(
            claim_type="unsupported",
            epistemic_status="derived_under_supported_model",
            statement="a statement",
            support=[],
            limitations=[],
        )


def test_package_contract_validates_proposal_digest(fixture_file):
    package = build_evidence_package(load_fixture(fixture_file()))
    validate_evidence_package(package)
    tampered = copy.deepcopy(package)
    tampered["findings"][0]["candidate_proposals"][0]["proposal_digest"] = "0" * 64
    with pytest.raises((ValidationError, ValueError)):
        validate_evidence_package(tampered)


def test_package_contract_rejects_cross_environment_finding(fixture_file):
    package = build_evidence_package(load_fixture(fixture_file()))
    tampered = copy.deepcopy(package)
    tampered["findings"][0]["environment_id"] = "other-environment"
    with pytest.raises(ValueError):
        validate_evidence_package(tampered)


def test_candidate_contract_rejects_effect_mismatch(fixture_file):
    package = build_evidence_package(load_fixture(fixture_file()))
    candidate = copy.deepcopy(package["findings"][0]["candidate_proposals"][0])
    candidate["tested_action_blocked_under_supported_model"] = True
    with pytest.raises(ValidationError):
        CandidateProposalContract.model_validate(candidate)
