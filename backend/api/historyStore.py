"""
History Store Module
====================

In-memory CRUD store for analysis history.

Stores the last MAX_ENTRIES analyses with automatic FIFO eviction.
Each entry is assigned a UUID on creation.  This is intentionally
in-memory (no database) — sufficient for the thesis prototype.

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from __future__ import annotations

import uuid
from collections import deque
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from .schemas import AnalysisResponse


# =============================================================================
# Constants
# =============================================================================

MAX_ENTRIES = 100


# =============================================================================
# History entry schema
# =============================================================================

class HistoryEntry(BaseModel):
    """Single analysis history record."""

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the history entry",
    )
    content: str = Field(..., description="Original content that was analysed")
    contentType: str = Field(
        default="auto", description="Content type (url, email, text, auto)"
    )
    response: AnalysisResponse = Field(..., description="Full analysis response")
    createdAt: datetime = Field(
        default_factory=datetime.now,
        description="When the analysis was performed",
    )


class HistoryListResponse(BaseModel):
    """Paginated list of history entries (newest first)."""

    entries: list[HistoryEntry] = Field(default_factory=list)
    total: int = Field(default=0, description="Total number of entries")


# =============================================================================
# In-memory store
# =============================================================================

class HistoryStore:
    """Thread-safe* in-memory history store.

    *FastAPI runs on a single event loop so concurrent access via async
    handlers is safe without locking.
    """

    def __init__(self, maxEntries: int = MAX_ENTRIES) -> None:
        self._maxEntries = maxEntries
        self._entries: deque[HistoryEntry] = deque(maxlen=maxEntries)

    # -- queries --

    def list(self, limit: int = MAX_ENTRIES, offset: int = 0) -> HistoryListResponse:
        """Return entries newest-first, with optional pagination."""
        allEntries = list(reversed(self._entries))
        page = allEntries[offset : offset + limit]
        return HistoryListResponse(entries=page, total=len(self._entries))

    def get(self, entryId: str) -> Optional[HistoryEntry]:
        """Retrieve a single entry by ID, or ``None``."""
        for entry in self._entries:
            if entry.id == entryId:
                return entry
        return None

    # -- mutations --

    def add(
        self,
        content: str,
        contentType: str,
        response: AnalysisResponse,
    ) -> HistoryEntry:
        """Create a new history entry and return it.

        When the store exceeds *maxEntries* the oldest entry is evicted
        automatically (FIFO via ``deque``).
        """
        entry = HistoryEntry(
            content=content,
            contentType=contentType,
            response=response,
        )
        self._entries.append(entry)
        return entry

    def delete(self, entryId: str) -> bool:
        """Delete a single entry by ID.  Returns ``True`` if found."""
        for i, entry in enumerate(self._entries):
            if entry.id == entryId:
                del self._entries[i]
                return True
        return False

    def clear(self) -> int:
        """Delete **all** entries.  Returns the number removed."""
        count = len(self._entries)
        self._entries.clear()
        return count

    @property
    def count(self) -> int:
        """Current number of entries in the store."""
        return len(self._entries)


# =============================================================================
# Module-level singleton
# =============================================================================

historyStore = HistoryStore()
