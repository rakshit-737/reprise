from datetime import UTC, datetime

import pytest

from reprise.approval import ApprovalError, ApprovalGateway, validation_digest
from reprise.fixture import load_fixture
from reprise.report import build_evidence_package
from reprise.validator import validate_candidate


def passed_validation(fixture_file):
    fixture = load_fixture(fixture_file())
    package = build_evidence_package(fixture)
    return validate_candidate(fixture, package, label="all_supported_paths")


def test_approval_binds_exact_digests_and_persists(tmp_path, fixture_file):
    validation = passed_validation(fixture_file)
    gateway = ApprovalGateway(tmp_path / "approvals.db")
    created_at = datetime(2026, 9, 28, 9, 0, tzinfo=UTC)
    approval = gateway.create(
        environment_id="owned-demo-replay",
        proposal_digest=validation.proposal_digest,
        validation=validation,
        approver="operator",
        ttl_seconds=300,
        now=created_at,
    )

    assert approval.validation_digest == validation_digest(validation)
    reopened = ApprovalGateway(tmp_path / "approvals.db")
    assert reopened.get(approval.approval_id) == approval


def test_only_exact_single_use_consumption_succeeds(tmp_path, fixture_file):
    validation = passed_validation(fixture_file)
    gateway = ApprovalGateway(tmp_path / "approvals.db")
    approval = gateway.create(
        environment_id=validation.environment_id,
        proposal_digest=validation.proposal_digest,
        validation=validation,
        approver="operator",
        now=datetime(2026, 9, 28, 9, 0, tzinfo=UTC),
    )
    with pytest.raises(ApprovalError, match="nonce"):
        gateway.consume(
            approval_id=approval.approval_id,
            nonce="wrong-nonce",
            environment_id=approval.environment_id,
            proposal_digest=approval.proposal_digest,
            validation_digest_value=approval.validation_digest,
            now=datetime(2026, 9, 28, 9, 1, tzinfo=UTC),
        )
    consumed = gateway.consume(
        approval_id=approval.approval_id,
        nonce=approval.nonce,
        environment_id=approval.environment_id,
        proposal_digest=approval.proposal_digest,
        validation_digest_value=approval.validation_digest,
        now=datetime(2026, 9, 28, 9, 1, tzinfo=UTC),
    )
    assert consumed.consumed_at == "2026-09-28T09:01:00Z"
    with pytest.raises(ApprovalError, match="already"):
        gateway.consume(
            approval_id=approval.approval_id,
            nonce=approval.nonce,
            environment_id=approval.environment_id,
            proposal_digest=approval.proposal_digest,
            validation_digest_value=approval.validation_digest,
            now=datetime(2026, 9, 28, 9, 2, tzinfo=UTC),
        )


def test_expiry_and_cross_environment_are_fail_closed(tmp_path, fixture_file):
    validation = passed_validation(fixture_file)
    gateway = ApprovalGateway(tmp_path / "approvals.db")
    approval = gateway.create(
        environment_id=validation.environment_id,
        proposal_digest=validation.proposal_digest,
        validation=validation,
        approver="operator",
        ttl_seconds=1,
        now=datetime(2026, 9, 28, 9, 0, tzinfo=UTC),
    )
    with pytest.raises(ApprovalError, match="environment"):
        gateway.consume(
            approval_id=approval.approval_id,
            nonce=approval.nonce,
            environment_id="other-environment",
            proposal_digest=approval.proposal_digest,
            validation_digest_value=approval.validation_digest,
            now=datetime(2026, 9, 28, 9, 0, tzinfo=UTC),
        )
    with pytest.raises(ApprovalError, match="expired"):
        gateway.consume(
            approval_id=approval.approval_id,
            nonce=approval.nonce,
            environment_id=approval.environment_id,
            proposal_digest=approval.proposal_digest,
            validation_digest_value=approval.validation_digest,
            now=datetime(2026, 9, 28, 9, 0, 1, tzinfo=UTC),
        )


def test_failed_validation_cannot_be_approved(tmp_path, fixture_file):
    fixture = load_fixture(fixture_file())
    package = build_evidence_package(fixture)
    validation = validate_candidate(fixture, package, label="naive_first_path_only")
    with pytest.raises(ApprovalError, match="passed"):
        ApprovalGateway(tmp_path / "approvals.db").create(
            environment_id=validation.environment_id,
            proposal_digest=validation.proposal_digest,
            validation=validation,
            approver="operator",
        )


def test_digest_mismatch_is_rejected_without_consuming(tmp_path, fixture_file):
    validation = passed_validation(fixture_file)
    gateway = ApprovalGateway(tmp_path / "approvals.db")
    approval = gateway.create(
        environment_id=validation.environment_id,
        proposal_digest=validation.proposal_digest,
        validation=validation,
        approver="operator",
    )
    with pytest.raises(ApprovalError, match="proposal digest"):
        gateway.consume(
            approval_id=approval.approval_id,
            nonce=approval.nonce,
            environment_id=approval.environment_id,
            proposal_digest="0" * 64,
            validation_digest_value=approval.validation_digest,
        )
    assert gateway.get(approval.approval_id).consumed_at is None
