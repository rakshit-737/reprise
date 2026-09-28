"""Durable local case state with guarded transitions and a hash-linked trail."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .fixture import canonical_json

MAX_METADATA_BYTES = 100_000
MAX_REASON_LENGTH = 2_000
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}$")

CASE_STATES = frozenset(
    {
        "detected",
        "investigating",
        "insufficient_evidence",
        "supported",
        "budget_exhausted",
        "proposed",
        "validating",
        "proposal_failed",
        "awaiting_approval",
        "rejected",
        "expired",
        "approved",
        "stale",
        "executing",
        "verified",
        "execution_failed",
    }
)

ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "detected": frozenset({"investigating"}),
    "investigating": frozenset({"insufficient_evidence", "supported", "budget_exhausted"}),
    "supported": frozenset({"proposed"}),
    "proposed": frozenset({"validating"}),
    "validating": frozenset({"proposal_failed", "awaiting_approval"}),
    "proposal_failed": frozenset({"investigating"}),
    "awaiting_approval": frozenset({"rejected", "expired", "approved"}),
    "approved": frozenset({"stale", "executing"}),
    "stale": frozenset({"investigating"}),
    "executing": frozenset({"verified", "execution_failed"}),
    "insufficient_evidence": frozenset(),
    "budget_exhausted": frozenset(),
    "rejected": frozenset(),
    "expired": frozenset(),
    "verified": frozenset(),
    "execution_failed": frozenset(),
}

SENSITIVE_KEYS = {
    "data",
    "stringdata",
    "token",
    "requestobject",
    "responseobject",
    "requestobjectraw",
    "responseobjectraw",
}


class CaseStoreError(RuntimeError):
    """Base error for durable case operations."""


class CaseNotFoundError(CaseStoreError):
    """Raised when a case identifier does not exist."""


class InvalidTransitionError(CaseStoreError):
    """Raised when a state transition is not allowed by the state machine."""


class ConcurrentCaseUpdateError(CaseStoreError):
    """Raised when a compare-and-swap version is stale."""


class CaseIntegrityError(CaseStoreError):
    """Raised when the append-only event chain does not verify."""


@dataclass(frozen=True)
class CaseRecord:
    case_id: str
    environment_id: str
    finding_id: str
    state: str
    version: int
    metadata: dict[str, Any]
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "environment_id": self.environment_id,
            "finding_id": self.finding_id,
            "state": self.state,
            "version": self.version,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True)
class CaseEvent:
    case_id: str
    sequence: int
    event_type: str
    from_state: str | None
    to_state: str
    actor: str
    reason: str
    idempotency_key: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "sequence": self.sequence,
            "event_type": self.event_type,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "actor": self.actor,
            "reason": self.reason,
            "idempotency_key": self.idempotency_key,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
            "created_at": self.created_at,
        }


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise CaseStoreError(f"{field} must be a short path-safe identifier")
    return value


def _safe_json(value: Any, field: str) -> str:
    def scan(item: Any, path: str) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if str(key).lower().replace("_", "") in SENSITIVE_KEYS:
                    raise CaseStoreError(f"{field} contains forbidden field {path}.{key}")
                scan(child, f"{path}.{key}")
        elif isinstance(item, list):
            for index, child in enumerate(item):
                scan(child, f"{path}[{index}]")

    scan(value, field)
    encoded = canonical_json(value)
    if len(encoded) > MAX_METADATA_BYTES:
        raise CaseStoreError(f"{field} exceeds the {MAX_METADATA_BYTES}-byte limit")
    return encoded.decode("utf-8")


def _row_to_case(row: sqlite3.Row) -> CaseRecord:
    return CaseRecord(
        case_id=row["case_id"],
        environment_id=row["environment_id"],
        finding_id=row["finding_id"],
        state=row["state"],
        version=row["version"],
        metadata=json.loads(row["metadata_json"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_event(row: sqlite3.Row) -> CaseEvent:
    return CaseEvent(
        case_id=row["case_id"],
        sequence=row["sequence"],
        event_type=row["event_type"],
        from_state=row["from_state"],
        to_state=row["to_state"],
        actor=row["actor"],
        reason=row["reason"],
        idempotency_key=row["idempotency_key"],
        payload=json.loads(row["payload_json"]),
        previous_hash=row["previous_hash"],
        event_hash=row["event_hash"],
        created_at=row["created_at"],
    )


class CaseStore:
    """SQLite-backed local case store with transactional state changes."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        if self.path != ":memory:":
            connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    environment_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    version INTEGER NOT NULL CHECK (version >= 0),
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS case_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                    sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    from_state TEXT,
                    to_state TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    request_json TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(case_id, sequence)
                );
                CREATE INDEX IF NOT EXISTS case_events_case_sequence
                    ON case_events(case_id, sequence);
                """
            )

    def create_case(
        self,
        *,
        case_id: str,
        environment_id: str,
        finding_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> CaseRecord:
        case_id = _identifier(case_id, "case_id")
        environment_id = _identifier(environment_id, "environment_id")
        finding_id = _identifier(finding_id, "finding_id")
        metadata_json = _safe_json(metadata or {}, "metadata")
        now = _now()
        request = {
            "case_id": case_id,
            "environment_id": environment_id,
            "finding_id": finding_id,
            "metadata": json.loads(metadata_json),
        }
        request_json = _safe_json(request, "case creation")
        event_payload = {
            "case_id": case_id,
            "sequence": 0,
            "event_type": "case.created",
            "from_state": None,
            "to_state": "detected",
            "actor": "system",
            "reason": "case created",
            "idempotency_key": f"case.create:{case_id}",
            "request": request,
            "previous_hash": "",
            "created_at": now,
        }
        payload_json = _safe_json(event_payload, "case event")
        event_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if existing is not None:
                if existing["environment_id"] == environment_id and existing["finding_id"] == finding_id and existing["metadata_json"] == metadata_json:
                    connection.commit()
                    return _row_to_case(existing)
                connection.rollback()
                raise CaseStoreError(f"case already exists with different immutable identity: {case_id}")
            connection.execute(
                "INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (case_id, environment_id, finding_id, "detected", 0, metadata_json, now, now),
            )
            connection.execute(
                """
                INSERT INTO case_events
                (case_id, sequence, event_type, from_state, to_state, actor, reason,
                 idempotency_key, request_json, payload_json, previous_hash, event_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    0,
                    "case.created",
                    None,
                    "detected",
                    "system",
                    "case created",
                    f"case.create:{case_id}",
                    request_json,
                    payload_json,
                    "",
                    event_hash,
                    now,
                ),
            )
            connection.commit()
        return self.get_case(case_id)

    def get_case(self, case_id: str) -> CaseRecord:
        case_id = _identifier(case_id, "case_id")
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        if row is None:
            raise CaseNotFoundError(case_id)
        return _row_to_case(row)

    def transition(
        self,
        *,
        case_id: str,
        expected_version: int,
        to_state: str,
        actor: str,
        reason: str,
        idempotency_key: str,
        payload: dict[str, Any] | None = None,
    ) -> CaseRecord:
        case_id = _identifier(case_id, "case_id")
        actor = _identifier(actor, "actor")
        idempotency_key = _identifier(idempotency_key, "idempotency_key")
        if to_state not in CASE_STATES:
            raise InvalidTransitionError(f"unknown case state: {to_state}")
        if not isinstance(expected_version, int) or expected_version < 0:
            raise ConcurrentCaseUpdateError("expected_version must be a non-negative integer")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > MAX_REASON_LENGTH:
            raise CaseStoreError("reason must be non-empty and within the length limit")
        payload_json_value = json.loads(_safe_json(payload or {}, "transition payload"))
        request = {
            "case_id": case_id,
            "to_state": to_state,
            "actor": actor,
            "reason": reason,
            "payload": payload_json_value,
        }
        request_json = _safe_json(request, "transition request")
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing_event = connection.execute("SELECT * FROM case_events WHERE idempotency_key = ?", (idempotency_key,)).fetchone()
            if existing_event is not None:
                if existing_event["request_json"] != request_json:
                    connection.rollback()
                    raise CaseStoreError("idempotency key was reused with a different request")
                existing_case = connection.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
                if existing_case is None:
                    connection.rollback()
                    raise CaseIntegrityError("idempotent event refers to a missing case")
                connection.commit()
                return _row_to_case(existing_case)

            row = connection.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if row is None:
                connection.rollback()
                raise CaseNotFoundError(case_id)
            current_state = row["state"]
            current_version = row["version"]
            if expected_version != current_version:
                connection.rollback()
                raise ConcurrentCaseUpdateError(f"case {case_id} is at version {current_version}, expected {expected_version}")
            if to_state not in ALLOWED_TRANSITIONS[current_state]:
                connection.rollback()
                raise InvalidTransitionError(f"cannot transition {current_state} -> {to_state}")
            previous = connection.execute(
                "SELECT event_hash FROM case_events WHERE case_id = ? AND sequence = ?",
                (case_id, current_version),
            ).fetchone()
            if previous is None:
                connection.rollback()
                raise CaseIntegrityError("case event chain is missing the current version")
            previous_hash = previous["event_hash"]
            new_version = current_version + 1
            event_payload = {
                "case_id": case_id,
                "sequence": new_version,
                "event_type": "case.transitioned",
                "from_state": current_state,
                "to_state": to_state,
                "actor": actor,
                "reason": reason,
                "idempotency_key": idempotency_key,
                "request": request,
                "previous_hash": previous_hash,
                "created_at": now,
            }
            event_payload_json = _safe_json(event_payload, "case event")
            event_hash = hashlib.sha256(event_payload_json.encode("utf-8")).hexdigest()
            connection.execute(
                "UPDATE cases SET state = ?, version = ?, updated_at = ? WHERE case_id = ? AND version = ?",
                (to_state, new_version, now, case_id, current_version),
            )
            connection.execute(
                """
                INSERT INTO case_events
                (case_id, sequence, event_type, from_state, to_state, actor, reason,
                 idempotency_key, request_json, payload_json, previous_hash, event_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    new_version,
                    "case.transitioned",
                    current_state,
                    to_state,
                    actor,
                    reason,
                    idempotency_key,
                    request_json,
                    event_payload_json,
                    previous_hash,
                    event_hash,
                    now,
                ),
            )
            connection.commit()
        return self.get_case(case_id)

    def list_events(self, case_id: str) -> tuple[CaseEvent, ...]:
        case_id = _identifier(case_id, "case_id")
        with self._connect() as connection:
            if connection.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone() is None:
                raise CaseNotFoundError(case_id)
            rows = connection.execute("SELECT * FROM case_events WHERE case_id = ? ORDER BY sequence", (case_id,)).fetchall()
        return tuple(_row_to_event(row) for row in rows)

    def verify_chain(self, case_id: str) -> bool:
        case = self.get_case(case_id)
        events = self.list_events(case_id)
        previous_hash = ""
        for expected_sequence, event in enumerate(events):
            if event.sequence != expected_sequence:
                raise CaseIntegrityError(f"case {case_id} has a sequence gap at {expected_sequence}")
            if event.previous_hash != previous_hash:
                raise CaseIntegrityError(f"case {case_id} has a previous-hash mismatch at {event.sequence}")
            payload = {
                "case_id": event.case_id,
                "sequence": event.sequence,
                "event_type": event.event_type,
                "from_state": event.from_state,
                "to_state": event.to_state,
                "actor": event.actor,
                "reason": event.reason,
                "idempotency_key": event.idempotency_key,
                "request": json.loads(next(row["request_json"] for row in self._raw_event_rows(case_id) if row["sequence"] == event.sequence)),
                "previous_hash": event.previous_hash,
                "created_at": event.created_at,
            }
            expected_hash = hashlib.sha256(_safe_json(payload, "case event").encode("utf-8")).hexdigest()
            if expected_hash != event.event_hash:
                raise CaseIntegrityError(f"case {case_id} event {event.sequence} hash mismatch")
            previous_hash = event.event_hash
        if case.version != (len(events) - 1):
            raise CaseIntegrityError(f"case {case_id} version does not match event chain")
        return True

    def _raw_event_rows(self, case_id: str) -> list[sqlite3.Row]:
        with self._connect() as connection:
            return connection.execute("SELECT * FROM case_events WHERE case_id = ? ORDER BY sequence", (case_id,)).fetchall()
