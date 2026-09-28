from dataclasses import replace

import pytest

from reprise.fixture import load_fixture
from reprise.report import build_evidence_package
from reprise.validator import validate_candidate


def package_and_fixture(fixture_file):
    fixture = load_fixture(fixture_file())
    return fixture, build_evidence_package(fixture)


def test_naive_proposal_fails_with_surviving_path(fixture_file):
    fixture, package = package_and_fixture(fixture_file)
    result = validate_candidate(fixture, package, label="naive_first_path_only")

    assert result.status == "failed"
    assert result.attack.passed is False
    assert result.attack.after_allowed is True
    assert any("surviving authorization path" in item for item in result.counterexamples)


def test_corrected_proposal_passes_attack_and_benign_workflow(fixture_file):
    fixture, package = package_and_fixture(fixture_file)
    result = validate_candidate(fixture, package, label="all_supported_paths")

    assert result.status == "passed"
    assert result.target_state_match is True
    assert result.claim_evidence_complete is True
    assert result.attack.passed is True
    assert [workflow.passed for workflow in result.benign_workflows] == [True]


def test_state_drift_makes_validation_incomplete(fixture_file):
    fixture, package = package_and_fixture(fixture_file)
    drifted_binding = replace(fixture.role_bindings[0], resource_version="999")
    drifted = replace(
        fixture,
        role_bindings=(drifted_binding, *fixture.role_bindings[1:]),
    )
    result = validate_candidate(drifted, package, label="all_supported_paths")
    assert result.status == "incomplete"
    assert result.target_state_match is False


def test_validation_rejects_unknown_candidate(fixture_file):
    fixture, package = package_and_fixture(fixture_file)
    with pytest.raises(ValueError, match="not found"):
        validate_candidate(fixture, package, label="does-not-exist")
