import sqlite3

import pytest

from reprise.case_store import (
    CaseIntegrityError,
    CaseStore,
    CaseStoreError,
    ConcurrentCaseUpdateError,
    InvalidTransitionError,
)


def make_store(tmp_path):
    return CaseStore(tmp_path / "cases.db")


def create(store):
    return store.create_case(
        case_id="case:demo-1",
        environment_id="owned-demo",
        finding_id="finding:demo-1",
        metadata={"evidence_package_sha256": "a" * 64, "finding_ids": ["finding:demo-1"]},
    )


def test_case_creation_is_durable_and_chain_verifies(tmp_path):
    store = make_store(tmp_path)
    created = create(store)

    assert created.state == "detected"
    assert created.version == 0
    assert store.verify_chain(created.case_id) is True
    reopened = CaseStore(tmp_path / "cases.db")
    assert reopened.get_case(created.case_id) == created
    assert len(reopened.list_events(created.case_id)) == 1


def test_state_machine_and_compare_and_swap(tmp_path):
    store = make_store(tmp_path)
    case = create(store)
    case = store.transition(
        case_id=case.case_id,
        expected_version=0,
        to_state="investigating",
        actor="operator",
        reason="open bounded investigation",
        idempotency_key="transition:1",
    )
    assert case.state == "investigating"
    assert case.version == 1
    with pytest.raises(ConcurrentCaseUpdateError):
        store.transition(
            case_id=case.case_id,
            expected_version=0,
            to_state="supported",
            actor="operator",
            reason="stale update",
            idempotency_key="transition:stale",
        )
    with pytest.raises(InvalidTransitionError):
        store.transition(
            case_id=case.case_id,
            expected_version=1,
            to_state="verified",
            actor="operator",
            reason="skip required validation",
            idempotency_key="transition:invalid",
        )


def test_idempotency_replays_without_duplicate_event(tmp_path):
    store = make_store(tmp_path)
    case = create(store)
    first = store.transition(
        case_id=case.case_id,
        expected_version=0,
        to_state="investigating",
        actor="operator",
        reason="open investigation",
        idempotency_key="transition:same",
    )
    second = store.transition(
        case_id=case.case_id,
        expected_version=0,
        to_state="investigating",
        actor="operator",
        reason="open investigation",
        idempotency_key="transition:same",
    )
    assert second == first
    assert len(store.list_events(case.case_id)) == 2
    with pytest.raises(CaseStoreError, match="reused"):
        store.transition(
            case_id=case.case_id,
            expected_version=1,
            to_state="supported",
            actor="operator",
            reason="different request",
            idempotency_key="transition:same",
        )


def test_terminal_states_cannot_be_reopened(tmp_path):
    store = make_store(tmp_path)
    case = create(store)
    for version, _state, next_state in [
        (0, "detected", "investigating"),
        (1, "investigating", "insufficient_evidence"),
    ]:
        case = store.transition(
            case_id=case.case_id,
            expected_version=version,
            to_state=next_state,
            actor="system",
            reason=f"move to {next_state}",
            idempotency_key=f"transition:{next_state}",
        )
    assert case.state == "insufficient_evidence"
    with pytest.raises(InvalidTransitionError):
        store.transition(
            case_id=case.case_id,
            expected_version=2,
            to_state="investigating",
            actor="operator",
            reason="reopen without new evidence",
            idempotency_key="transition:reopen",
        )


def test_sensitive_metadata_is_rejected(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(CaseStoreError, match="forbidden"):
        store.create_case(
            case_id="case:secret",
            environment_id="owned-demo",
            finding_id="finding:secret",
            metadata={"requestObject": {"data": "no"}},
        )


def test_tampering_with_event_payload_is_detected(tmp_path):
    store = make_store(tmp_path)
    case = create(store)
    case = store.transition(
        case_id=case.case_id,
        expected_version=0,
        to_state="investigating",
        actor="operator",
        reason="open investigation",
        idempotency_key="transition:tamper",
    )
    connection = sqlite3.connect(tmp_path / "cases.db")
    connection.execute(
        "UPDATE case_events SET reason = ? WHERE case_id = ? AND sequence = 1",
        ("changed after append", case.case_id),
    )
    connection.commit()
    connection.close()
    with pytest.raises(CaseIntegrityError):
        store.verify_chain(case.case_id)
