"""
SentinelCloud Immutable Audit Trail
====================================
Wraps the in-memory audit deque with SQLite persistence.
Every security-relevant action is recorded and persisted.
"""

import logging
from collections import deque
from typing import Optional

from backend.core.event_schema import AuditRecord
from backend.persistence.sqlite_store import sqlite_store

logger = logging.getLogger("sentinel.audit")


class AuditTrail:
    """
    Immutable audit trail.
    Records are appended to both an in-memory ring buffer and SQLite.
    """

    def __init__(self, maxlen: int = 2000):
        self.records: deque[AuditRecord] = deque(maxlen=maxlen)
        self._load_from_db()

    def _load_from_db(self):
        """Load recent audit records from SQLite on startup."""
        try:
            rows = sqlite_store.get_audit_trail(limit=self.records.maxlen)
            for row in reversed(rows):  # oldest first
                self.records.append(AuditRecord(
                    audit_id=row["audit_id"],
                    action=row["action"],
                    actor=row.get("actor", "system"),
                    target=row.get("target", ""),
                    detail=row.get("detail", ""),
                ))
            if self.records:
                logger.info("Loaded %d audit records from SQLite", len(self.records))
        except Exception as e:
            logger.warning("Could not load audit history from SQLite: %s", e)

    def record(self, action: str, target: str = "", detail: str = "",
               actor: str = "system", metadata: Optional[dict] = None) -> AuditRecord:
        """Create and persist an audit record."""
        rec = AuditRecord(
            action=action,
            actor=actor,
            target=target,
            detail=detail,
            metadata=metadata or {},
        )
        self.records.append(rec)

        # Persist to SQLite
        try:
            sqlite_store.save_audit_record(rec)
        except Exception as e:
            logger.error("Failed to persist audit record: %s", e)

        return rec

    def append(self, record: AuditRecord) -> None:
        """Append an existing AuditRecord (used by pipeline)."""
        self.records.append(record)
        try:
            sqlite_store.save_audit_record(record)
        except Exception as e:
            logger.error("Failed to persist audit record: %s", e)

    def get_recent(self, limit: int = 100) -> list[AuditRecord]:
        """Get recent audit records from memory."""
        return list(self.records)[-limit:]

    def __len__(self):
        return len(self.records)

    def __iter__(self):
        return iter(self.records)


# Singleton
audit_trail = AuditTrail()
