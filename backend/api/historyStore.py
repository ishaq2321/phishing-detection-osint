"""
History Store Module
====================

In-memory CRUD store for analysis history.

Stores the last MAX_ENTRIES analyses with automatic FIFO eviction.
Each entry is assigned a UUID on creation.  This is intentionally
in-memory (no database) — sufficient for the thesis prototype.

Tier 2.1: SQLite-backed persistence (opt-in)
--------------------------------------------

``HistoryStoreBase`` defines the storage contract.  The default
implementation (``HistoryStore``) is a ``deque``-backed FIFO ring
buffer that survives only the lifetime of the running process.

When ``PHISHGUARD_PERSIST_HISTORY=1`` is set in the environment,
``open_history_store()`` constructs a ``SqliteHistoryStore`` that
persists entries into a single SQLite file (default ``./data/history.db``).
Operators get:

* durability across application restarts;
* larger retention (configurable via ``PHISHGUARD_HISTORY_MAX_ENTRIES``);
* back-compat with the queue API (``add`` / ``list`` / ``get`` /
  ``delete`` / ``clear`` / ``count``).

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Protocol

from pydantic import BaseModel, Field

from .schemas import AnalysisResponse


# =============================================================================
# Constants
# =============================================================================

MAX_ENTRIES = 100
DEFAULT_DB_PATH = "./data/history.db"


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

class SqliteHistoryStore:
    """On-disk SQLite-backed history store.

    Wire-compatible with ``HistoryStore`` for read/write operations:
    exposes ``list``, ``get``, ``add``, ``delete``, ``clear``,
    ``count`` so module-level call sites that use the deque store
    today keep working.

    The database file is created on first open; the schema is applied
    idempotently.  A single ``threading.Lock`` guards every call so
    that the connector is safe to use from FastAPI's threaded
    dependency-injection paths.

    Schema::

        CREATE TABLE history (
            id          TEXT PRIMARY KEY,
            content     TEXT NOT NULL,
            contentType TEXT NOT NULL,
            response    TEXT NOT NULL,  -- JSON-encoded AnalysisResponse
            createdAt   TEXT NOT NULL   -- ISO-8601 UTC
        );

    Capacity is enforced through ``PHISHGUARD_HISTORY_MAX_ENTRIES``;
    when the count exceeds the cap, the oldest entries are deleted
    FIFO to fit within the limit.  This matches the in-memory
    ``deque(maxlen=...)`` eviction policy.
    """

    def __init__(
        self,
        dbPath: str,
        maxEntries: int = MAX_ENTRIES,
    ) -> None:
        import threading as _threading

        self._dbPath = dbPath
        self._maxEntries = maxEntries
        self._lock = _threading.Lock()
        # ``check_same_thread=False`` so a connection acquired on
        # one thread can be used on another (FastAPI spawns ad-hoc
        # threads for sync tasks).  We serialise via ``self._lock``.
        self._conn = sqlite3.connect(
            self._dbPath,
            check_same_thread=False,
            isolation_level=None,  # autocommit for our explicit BEGIN
        )
        self._conn.execute("PRAGMA journal_mode = WAL;")
        self._conn.execute("PRAGMA synchronous = NORMAL;")
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS history (
                    id TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    contentType TEXT NOT NULL,
                    response TEXT NOT NULL,
                    createdAt TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_history_createdAt "
                "ON history(createdAt DESC)"
            )

    def _evict_oldest(self, retain: int) -> int:
        """Delete all but the newest ``retain`` rows.  Returns count."""
        if retain < 0:
            retain = 0
        cur = self._conn.execute(
            "SELECT id FROM history ORDER BY createdAt DESC LIMIT -1 OFFSET ?",
            (retain,),
        )
        ids = [row[0] for row in cur.fetchall()]
        if not ids:
            return 0
        # Use a parameter placeholder per id -- SQLite accepts
        # a CSV in the IN (...) clause up to its parameter limit
        # (default 999), well within the row-count ceiling.
        placeholders = ",".join(["?"] * len(ids))
        self._conn.execute(
            f"DELETE FROM history WHERE id IN ({placeholders})", ids
        )
        return len(ids)

    def add(
        self,
        content: str,
        contentType: str,
        response: AnalysisResponse,
    ) -> HistoryEntry:
        """Persist a new entry.  See ``HistoryStore.add`` for semantics."""
        entry = HistoryEntry(
            content=content,
            contentType=contentType,
            response=response,
        )
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO history (id, content, contentType, response, createdAt) VALUES (?, ?, ?, ?, ?)",
                (
                    entry.id,
                    entry.content,
                    entry.contentType,
                    entry.response.model_dump_json(),
                    entry.createdAt.isoformat(),
                ),
            )
            self._evict_oldest(self._maxEntries)
        return entry

    def get(self, entryId: str) -> Optional[HistoryEntry]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT id, content, contentType, response, createdAt FROM history WHERE id = ?",
                (entryId,),
            )
            row = cur.fetchone()
        return _row_to_entry(row) if row else None

    def list(
        self, limit: int = MAX_ENTRIES, offset: int = 0
    ) -> HistoryListResponse:
        newest_first: list[HistoryEntry] = []
        total = 0
        with self._lock:
            cur = self._conn.execute(
                "SELECT COUNT(*) AS c FROM history"
            )
            total = cur.fetchone()[0]
            cur = self._conn.execute(
                "SELECT id, content, contentType, response, createdAt FROM history ORDER BY createdAt DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
            for row in cur.fetchall():
                entry = _row_to_entry(row)
                if entry is not None:
                    newest_first.append(entry)
        return HistoryListResponse(entries=newest_first, total=total)

    def delete(self, entryId: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM history WHERE id = ?", (entryId,)
            )
            return cur.rowcount > 0

    def clear(self) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM history")
            return cur.rowcount

    @property
    def count(self) -> int:
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM history")
            return cur.fetchone()[0]

    def close(self) -> None:
        """Close the underlying SQLite connection (test clean-up)."""
        with self._lock:
            self._conn.close()


def _row_to_entry(row: Any) -> Optional[HistoryEntry]:
    """Materialise a SQLite row tuple into a ``HistoryEntry``."""
    if row is None:
        return None
    entry_id, content, content_type, response_json, created_iso = row
    try:
        response = AnalysisResponse.model_validate_json(response_json)
    except Exception:
        return None
    try:
        created_at = datetime.fromisoformat(created_iso)
    except ValueError:
        created_at = datetime.utcnow()
    return HistoryEntry(
        id=entry_id,
        content=content,
        contentType=content_type,
        response=response,
        createdAt=created_at,
    )


def open_history_store() -> Any:
    """Factory: ``deque`` default, ``SQLite`` if persistence opted in.

    Used by ``backend/main.py`` lifespan to swap ``historyStore`` once
    on startup.  Tests that want to drive the SQLite path explicitly
    can call this directly.
    """
    if _is_persistence_enabled():
        dbPath = _resolve_db_path()
        # Ensure the parent directory exists.
        parent = Path(dbPath).expanduser().resolve().parent
        parent.mkdir(parents=True, exist_ok=True)
        return SqliteHistoryStore(
            dbPath=dbPath,
            maxEntries=_resolve_max_entries(),
        )
    return HistoryStore()


def set_store(newStore: Any) -> None:
    """Replace the module-level singleton.  Returns the previous store."""
    global historyStore
    previous = historyStore
    historyStore = newStore
    return previous




# Module-level singleton
# =============================================================================

historyStore = HistoryStore()


# =============================================================================
# Tier 2.1: SQLite-backed persistence (opt-in)
#
# Module-level helper functions (added at the very end of the file so
# existing imports keep working unchanged).  We DO NOT instantiate the
# module-level singleton lazily; existing call-sites that reference
# ``historyStore`` continue to get the in-memory default.  Operators
# who want the SQLite backend wire ``set_store(SqliteHistoryStore(...))``
# during application startup (see ``backend/main.py`` lifespan).
# =============================================================================


def _is_persistence_enabled() -> bool:
    """True iff the env-var opt-in for SQLite persistence is set."""
    flag = os.environ.get("PHISHGUARD_PERSIST_HISTORY", "").strip().lower()
    return flag in {"1", "true", "yes", "on"}


def _resolve_max_entries() -> int:
    """Maximum history entries. Operator-overridable."""
    raw = os.environ.get("PHISHGUARD_HISTORY_MAX_ENTRIES", "").strip()
    if not raw:
        return MAX_ENTRIES
    try:
        n = int(raw)
        if n < 1 or n > 1_000_000:
            return MAX_ENTRIES
        return n
    except ValueError:
        return MAX_ENTRIES


def _resolve_db_path() -> str:
    """SQLite file location, env-overridable."""
    return os.environ.get("PHISHGUARD_HISTORY_DB", DEFAULT_DB_PATH).strip() or DEFAULT_DB_PATH
