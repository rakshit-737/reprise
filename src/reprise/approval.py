"""Local exact-digest approval gateway.

This module records an approval capability; it does not authenticate a person
or execute a Kubernetes action. A production gateway must place identity,
authorization, storage, and executor credentials behind separate services.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .contracts import ApprovalContract, ShadowValidationContract
from .fixture import canonical_json

MAX_TTL_SECONDS = 3_600
HEX_DIGEST_LENGTH = 64


class ApprovalError(RuntimeError):
    """Raised when an approval cannot be created or consumed safely."""


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApprovalError(f"invalid approval timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise ApprovalError("approval timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _digest(value: str, field: str) -> str:
    if not isinstance(value, str) or len(value) != HEX_DIGEST_LENGTH:
        raise ApprovalError(f"{field} must be a 64-character SHA-256 digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ApprovalError(f"{field} must be lowercase hexadecimal") from exc
    if value != value.lower():
        raise ApprovalError(f"{field} must be lowercase hexadecimal")
    return value


def validation_digest(validation: ShadowValidationContract) -> str:
    """Digest the canonical validation artifact, excluding no decision fields."""

    return hashlib.sha256(canonical_json(validation.model_dump(mode="json"))).hexdigest()


def _row_to_approval(row: sqlite3.Row) -> ApprovalContract:
    return ApprovalContract(
        approval_id=row["approval_id"],
        environment_id=row["environment_id"],
        proposal_digest=row["proposal_digest"],
        validation_digest=row["validation_digest"],
        approver=row["approver"],
        nonce=row["nonce"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        consumed_at=row["consumed_at"],
    )


class ApprovalGateway:
    """SQLite-backed, expiring, single-use approval records."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    environment_id TEXT NOT NULL,
                    proposal_digest TEXT NOT NULL,
                    validation_digest TEXT NOT NULL,
                    approver TEXT NOT NULL,
                    nonce TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        if self.path != ":memory:":
            connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def create(
        self,
        *,
        environment_id: str,
        proposal_digest: str,
        validation: ShadowValidationContract,
        approver: str,
        ttl_seconds: int = 300,
        now: datetime | None = None,
    ) -> ApprovalContract:
        if not environment_id.strip() or not approver.strip():
            raise ApprovalError("environment_id and approver are required")
        if validation.status != "passed":
            raise ApprovalError("only passed shadow validation may be approved")
        if validation.environment_id != environment_id:
            raise ApprovalError("validation and approval environments do not match")
        proposal_digest = _digest(proposal_digest, "proposal_digest")
        if validation.proposal_digest != proposal_digest:
            raise ApprovalError("proposal digest does not match validation")
        if not isinstance(ttl_seconds, int) or ttl_seconds < 1 or ttl_seconds > MAX_TTL_SECONDS:
            raise ApprovalError(f"ttl_seconds must be between 1 and {MAX_TTL_SECONDS}")
        created = now or _now()
        expires = created + timedelta(seconds=ttl_seconds)
        record = ApprovalContract(
            approval_id=f"approval:{uuid.uuid4().hex}",
            environment_id=environment_id,
            proposal_digest=proposal_digest,
            validation_digest=validation_digest(validation),
            approver=approver,
            nonce=secrets.token_urlsafe(32),
            created_at=_iso(created),
            expires_at=_iso(expires),
        )
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO approvals VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.approval_id,
                    record.environment_id,
                    record.proposal_digest,
                    record.validation_digest,
                    record.approver,
                    record.nonce,
                    record.created_at,
                    record.expires_at,
                    None,
                ),
            )
        return record

    def get(self, approval_id: str) -> ApprovalContract:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone()
        if row is None:
            raise ApprovalError(f"approval not found: {approval_id}")
        return _row_to_approval(row)

    def consume(
        self,
        *,
        approval_id: str,
        nonce: str,
        environment_id: str,
        proposal_digest: str,
        validation_digest_value: str,
        now: datetime | None = None,
    ) -> ApprovalContract:
        proposal_digest = _digest(proposal_digest, "proposal_digest")
        validation_digest_value = _digest(validation_digest_value, "validation_digest")
        current_time = now or _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone()
            if row is None:
                connection.rollback()
                raise ApprovalError(f"approval not found: {approval_id}")
            if row["nonce"] != nonce:
                connection.rollback()
                raise ApprovalError("approval nonce does not match")
            if row["environment_id"] != environment_id:
                connection.rollback()
                raise ApprovalError("approval environment does not match")
            if row["proposal_digest"] != proposal_digest:
                connection.rollback()
                raise ApprovalError("approval proposal digest does not match")
            if row["validation_digest"] != validation_digest_value:
                connection.rollback()
                raise ApprovalError("approval validation digest does not match")
            if row["consumed_at"] is not None:
                connection.rollback()
                raise ApprovalError("approval has already been consumed")
            if current_time >= _parse_iso(row["expires_at"]):
                connection.rollback()
                raise ApprovalError("approval has expired")
            consumed_at = _iso(current_time)
            connection.execute(
                "UPDATE approvals SET consumed_at = ? WHERE approval_id = ? AND consumed_at IS NULL",
                (consumed_at, approval_id),
            )
            connection.commit()
            updated = connection.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone()
        if updated is None:
            raise ApprovalError("approval disappeared after consumption")
        return _row_to_approval(updated)


def load_validation(path: str | Path) -> tuple[ShadowValidationContract, str]:
    source = Path(path).read_bytes()
    try:
        validation = ShadowValidationContract.model_validate(json.loads(source.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ApprovalError(f"invalid validation artifact: {path}") from exc
    return validation, validation_digest(validation)
