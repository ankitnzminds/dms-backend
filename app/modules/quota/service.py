"""Quota accounting: an append-only idempotent ledger plus counters on the organization row.

Concurrency: every mutation first locks the organization row (SELECT ... FOR UPDATE), so two
simultaneous reservations can never both pass the limit check. Each ledger entry carries a
unique idempotency key, making retried operations a no-op instead of a double charge.

Policy (ADR-0007): all stored version bytes count toward quota - including trashed documents
and quarantined content - until they are purged.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.errors import QuotaExceededError
from app.db.enums import LedgerEntryType, UploadState
from app.db.models import DocumentVersion, Organization, QuotaLedgerEntry, UploadSession


def _lock_org(db: Session, organization_id: uuid.UUID) -> Organization:
    org = db.scalar(
        select(Organization).where(Organization.id == organization_id).with_for_update()
    )
    if org is None:
        raise RuntimeError("organization vanished")
    return org


def _insert_entry(
    db: Session,
    *,
    organization_id: uuid.UUID,
    entry_type: LedgerEntryType,
    reserved_delta: int,
    used_delta: int,
    idempotency_key: str,
    upload_session_id: uuid.UUID | None = None,
    document_version_id: uuid.UUID | None = None,
    note: str | None = None,
) -> bool:
    """Returns True if the entry was newly applied, False if the key was already used."""
    stmt = (
        pg_insert(QuotaLedgerEntry)
        .values(
            id=uuid.uuid4(),
            organization_id=organization_id,
            entry_type=entry_type.value,
            reserved_delta=reserved_delta,
            used_delta=used_delta,
            idempotency_key=idempotency_key,
            upload_session_id=upload_session_id,
            document_version_id=document_version_id,
            note=note,
        )
        .on_conflict_do_nothing(constraint="uq_quota_ledger_idem")
        .returning(QuotaLedgerEntry.id)
    )
    return db.execute(stmt).first() is not None


def reserve(
    db: Session,
    *,
    organization_id: uuid.UUID,
    upload_session_id: uuid.UUID,
    size_bytes: int,
) -> None:
    org = _lock_org(db, organization_id)
    if org.quota_bytes is not None and (
        org.quota_used_bytes + org.quota_reserved_bytes + size_bytes > org.quota_bytes
    ):
        raise QuotaExceededError("Storage quota exceeded.")
    applied = _insert_entry(
        db,
        organization_id=organization_id,
        entry_type=LedgerEntryType.RESERVE,
        reserved_delta=size_bytes,
        used_delta=0,
        idempotency_key=f"reserve:{upload_session_id}",
        upload_session_id=upload_session_id,
    )
    if applied:
        org.quota_reserved_bytes += size_bytes


def commit(
    db: Session,
    *,
    organization_id: uuid.UUID,
    upload_session_id: uuid.UUID,
    reserved_bytes: int,
    actual_bytes: int,
    document_version_id: uuid.UUID,
) -> None:
    org = _lock_org(db, organization_id)
    applied = _insert_entry(
        db,
        organization_id=organization_id,
        entry_type=LedgerEntryType.COMMIT,
        reserved_delta=-reserved_bytes,
        used_delta=actual_bytes,
        idempotency_key=f"commit:{upload_session_id}",
        upload_session_id=upload_session_id,
        document_version_id=document_version_id,
    )
    if applied:
        org.quota_reserved_bytes -= reserved_bytes
        org.quota_used_bytes += actual_bytes


def charge_direct(
    db: Session,
    *,
    organization_id: uuid.UUID,
    reference_id: uuid.UUID,
    size_bytes: int,
    document_version_id: uuid.UUID,
) -> None:
    """Reserve+commit in one step for server-side creations (copy, restore-as-new-version)."""
    org = _lock_org(db, organization_id)
    if org.quota_bytes is not None and (
        org.quota_used_bytes + org.quota_reserved_bytes + size_bytes > org.quota_bytes
    ):
        raise QuotaExceededError("Storage quota exceeded.")
    applied = _insert_entry(
        db,
        organization_id=organization_id,
        entry_type=LedgerEntryType.COMMIT,
        reserved_delta=0,
        used_delta=size_bytes,
        idempotency_key=f"direct:{reference_id}",
        document_version_id=document_version_id,
    )
    if applied:
        org.quota_used_bytes += size_bytes


def release(
    db: Session,
    *,
    organization_id: uuid.UUID,
    upload_session_id: uuid.UUID,
    reserved_bytes: int,
    reason: str,
) -> None:
    org = _lock_org(db, organization_id)
    applied = _insert_entry(
        db,
        organization_id=organization_id,
        entry_type=LedgerEntryType.RELEASE,
        reserved_delta=-reserved_bytes,
        used_delta=0,
        idempotency_key=f"release:{upload_session_id}",
        upload_session_id=upload_session_id,
        note=reason[:500],
    )
    if applied:
        org.quota_reserved_bytes -= reserved_bytes


def reconcile(db: Session, organization_id: uuid.UUID, *, fix: bool = False) -> dict[str, int]:
    """Compare counters with (a) the ledger and (b) ground truth (stored versions + live
    reservations). Returns drift values; with ``fix`` realigns counters to ground truth."""
    org = _lock_org(db, organization_id)
    ledger_reserved, ledger_used = db.execute(
        select(
            func.coalesce(func.sum(QuotaLedgerEntry.reserved_delta), 0),
            func.coalesce(func.sum(QuotaLedgerEntry.used_delta), 0),
        ).where(QuotaLedgerEntry.organization_id == organization_id)
    ).one()
    versions_total = db.scalar(
        select(func.coalesce(func.sum(DocumentVersion.size_bytes), 0)).where(
            DocumentVersion.organization_id == organization_id
        )
    )
    live_reserved = db.scalar(
        select(func.coalesce(func.sum(UploadSession.reserved_bytes), 0)).where(
            UploadSession.organization_id == organization_id,
            UploadSession.state.in_([UploadState.INITIATED.value, UploadState.UPLOADED.value]),
        )
    )
    report = {
        "counter_used": org.quota_used_bytes,
        "counter_reserved": org.quota_reserved_bytes,
        "ledger_used": int(ledger_used),
        "ledger_reserved": int(ledger_reserved),
        "stored_versions_bytes": int(versions_total or 0),
        "live_reservations_bytes": int(live_reserved or 0),
    }
    report["drift_used_vs_versions"] = report["counter_used"] - report["stored_versions_bytes"]
    report["drift_reserved_vs_sessions"] = (
        report["counter_reserved"] - report["live_reservations_bytes"]
    )
    if fix:
        db.execute(
            update(Organization)
            .where(Organization.id == organization_id)
            .values(
                quota_used_bytes=int(versions_total or 0),
                quota_reserved_bytes=int(live_reserved or 0),
            )
        )
    return report
