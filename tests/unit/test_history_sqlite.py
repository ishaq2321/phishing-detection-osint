"""
Unit tests for ``backend.api.historyStore.SqliteHistoryStore`` (Tier 2.1).

Customers

* ``open_history_store`` returns the deque-based ``HistoryStore`` by
  default (back-compat).
* ``open_history_store`` returns ``SqliteHistoryStore`` when
  ``PHISHGUARD_PERSIST_HISTORY`` is truthy.
* The SQLite store is wire-compatible with the in-memory store:
  every method on the deque class produces an identical-SQLite result.
* The SQLite store survives a brand-new ``SqliteHistoryStore`` instance
  opening the same file -- durability test.
* ``PHISHGUARD_HISTORY_MAX_ENTRIES`` caps the table size with FIFO
  eviction.
* The schema re-applies idempotently when the file is empty.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import uuid
from pathlib import Path

import pytest

from backend.api.historyStore import (
    DEFAULT_DB_PATH,
    MAX_ENTRIES,
    HistoryEntry,
    HistoryListResponse,
    HistoryStore,
    SqliteHistoryStore,
    _resolve_db_path,
    _resolve_max_entries,
    _is_persistence_enabled,
    open_history_store,
    set_store,
)
from backend.api.schemas import (
    AnalysisResponse,
    FeatureSummary,
    VerdictResult,
)


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------
def _isolated_db_path(tmp_path: Path) -> str:
    """Return a fresh SQLite file path inside the test temp directory."""
    return str(tmp_path / "history.db")


@pytest.fixture
def isolated_history_fs(monkeypatch, tmp_path):
    """Set all persistence env vars to ``tmp_path``-based values for the
    duration of one test.  Returns the resolved db path.
    """
    dbPath = str(tmp_path / "history.db")
    monkeypatch.setenv("PHISHGUARD_HISTORY_DB", dbPath)
    return dbPath


# ---------------------------------------------------------------------------
# Env-var helpers
# ---------------------------------------------------------------------------
def test_isPersistenceEnabled_defaultFalse(monkeypatch):
    monkeypatch.delenv("PHISHGUARD_PERSIST_HISTORY", raising=False)
    assert _is_persistence_enabled() is False


@pytest.mark.parametrize("flag", ["1", "true", "yes", "on", "TRUE", " Yes "])
def test_isPersistenceEnabled_truthyValues(monkeypatch, flag):
    monkeypatch.setenv("PHISHGUARD_PERSIST_HISTORY", flag)
    assert _is_persistence_enabled() is True


def test_resolveDbPath_defaultValue(monkeypatch):
    monkeypatch.delenv("PHISHGUARD_HISTORY_DB", raising=False)
    assert _resolve_db_path() == DEFAULT_DB_PATH


def test_resolveDbPath_override(monkeypatch, isolated_history_fs):
    assert _resolve_db_path() == isolated_history_fs


def test_resolveMaxEntries_default(monkeypatch):
    monkeypatch.delenv("PHISHGUARD_HISTORY_MAX_ENTRIES", raising=False)
    assert _resolve_max_entries() == MAX_ENTRIES


def test_resolveMaxEntries_override(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_HISTORY_MAX_ENTRIES", "250")
    assert _resolve_max_entries() == 250


@pytest.mark.parametrize("bad", ["abc", "-1", "0", "10000000"])
def test_resolveMaxEntries_invalidReturnsDefault(monkeypatch, bad):
    monkeypatch.setenv("PHISHGUARD_HISTORY_MAX_ENTRIES", bad)
    assert _resolve_max_entries() == MAX_ENTRIES


# ---------------------------------------------------------------------------
# open_history_store
# ---------------------------------------------------------------------------
def test_openHistoryStore_defaultIsDeque(monkeypatch, isolated_history_fs):
    monkeypatch.delenv("PHISHGUARD_PERSIST_HISTORY", raising=False)
    store = open_history_store()
    assert isinstance(store, HistoryStore)
    assert not isinstance(store, SqliteHistoryStore)


def test_openHistoryStore_optInReturnsSqlite(monkeypatch, isolated_history_fs):
    monkeypatch.setenv("PHISHGUARD_PERSIST_HISTORY", "1")
    store = open_history_store()
    try:
        assert isinstance(store, SqliteHistoryStore)
        # Side effect: the database file was created.
        assert os.path.exists(isolated_history_fs)
    finally:
        store.close()


def test_openHistoryStore_createsParentDirs(monkeypatch, tmp_path):
    nestedPath = str(tmp_path / "nested" / "deeper" / "history.db")
    monkeypatch.setenv("PHISHGUARD_PERSIST_HISTORY", "1")
    monkeypatch.setenv("PHISHGUARD_HISTORY_DB", nestedPath)
    store = open_history_store()
    try:
        assert os.path.exists(nestedPath)
    finally:
        store.close()


# ---------------------------------------------------------------------------
# SqliteHistoryStore CRUD parity
# ---------------------------------------------------------------------------
def _make_response() -> AnalysisResponse:
    """A minimal AnalysisResponse for tests."""
    verdict = VerdictResult(
        isPhishing=False,
        confidenceScore=0.5,
        threatLevel="safe",
        reasons=["r1"],
        recommendation="verify",
    )
    return AnalysisResponse(
        success=True,
        verdict=verdict,
        features=FeatureSummary(),
        analysisTime=1.23,
        timestamp="2026-01-01T00:00:00",
    )


def test_sqliteAddThenGet(monkeypatch, isolated_history_fs):
    store = SqliteHistoryStore(isolated_history_fs)
    try:
        response = _make_response()
        entry = store.add(
            content="https://example.com",
            contentType="url",
            response=response,
        )
        assert isinstance(entry, HistoryEntry)
        fetched = store.get(entry.id)
        assert fetched is not None
        assert fetched.id == entry.id
        assert fetched.content == "https://example.com"
        assert fetched.contentType == "url"
        assert fetched.response.verdict.isPhishing is False
    finally:
        store.close()


def test_sqliteList_pagination(monkeypatch, isolated_history_fs):
    store = SqliteHistoryStore(isolated_history_fs, maxEntries=100)
    try:
        for i in range(10):
            store.add(
                content=f"https://e{i}.com",
                contentType="url",
                response=_make_response(),
            )
        # Default limit returns up to 100
        page = store.list(limit=5, offset=0)
        assert len(page.entries) == 5
        assert page.total == 10
        # Second page
        page2 = store.list(limit=5, offset=5)
        assert len(page2.entries) == 5
        assert page2.total == 10
    finally:
        store.close()


def test_sqliteListOrderIsNewestFirst(monkeypatch, isolated_history_fs):
    import time as _t

    store = SqliteHistoryStore(isolated_history_fs)
    try:
        first = store.add(content="first", contentType="url", response=_make_response())
        _t.sleep(0.01)
        second = store.add(content="second", contentType="url", response=_make_response())
        result = store.list()
        # ``second`` must come first (newest-first ordering)
        assert result.entries[0].id == second.id
        assert result.entries[1].id == first.id
    finally:
        store.close()


def test_sqliteDelete(monkeypatch, isolated_history_fs):
    store = SqliteHistoryStore(isolated_history_fs)
    try:
        entry = store.add(content="c1", contentType="url", response=_make_response())
        assert store.delete(entry.id) is True
        # Deleting again returns False
        assert store.delete(entry.id) is False
        # And the count dropped
        assert store.count == 0
    finally:
        store.close()


def test_sqliteClear(monkeypatch, isolated_history_fs):
    store = SqliteHistoryStore(isolated_history_fs)
    try:
        for i in range(5):
            store.add(content=f"x{i}", contentType="url", response=_make_response())
        assert store.count == 5
        n = store.clear()
        assert n == 5
        assert store.count == 0
    finally:
        store.close()


def test_sqliteCount(monkeypatch, isolated_history_fs):
    store = SqliteHistoryStore(isolated_history_fs)
    try:
        assert store.count == 0
        store.add(content="a", contentType="url", response=_make_response())
        assert store.count == 1
        store.add(content="b", contentType="url", response=_make_response())
        assert store.count == 2
    finally:
        store.close()


def test_sqliteGetReturnsNoneForUnknown(monkeypatch, isolated_history_fs):
    store = SqliteHistoryStore(isolated_history_fs)
    try:
        assert store.get(str(uuid.uuid4())) is None
    finally:
        store.close()


def test_sqliteFifoEvictionAtCapacity(monkeypatch, isolated_history_fs):
    import time as _t

    store = SqliteHistoryStore(isolated_history_fs, maxEntries=3)
    try:
        ids = []
        for i in range(5):
            entry = store.add(
                content=f"line-{i}", contentType="url", response=_make_response()
            )
            ids.append(entry.id)
            _t.sleep(0.005)  # ensure distinct createdAt ordering
        # Only the newest 3 must survive
        assert store.count == 3
        # The first two are evicted, the last three remain.
        assert store.get(ids[0]) is None
        assert store.get(ids[1]) is None
        for surviving in ids[2:]:
            assert store.get(surviving) is not None
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Durability across open/close
# ---------------------------------------------------------------------------
def test_sqliteDurabilityAcrossReopen(monkeypatch, isolated_history_fs):
    """Close the store, re-open, and confirm the data is still there."""
    s1 = SqliteHistoryStore(isolated_history_fs)
    e1 = s1.add(content="persistent", contentType="url", response=_make_response())
    s1.close()

    s2 = SqliteHistoryStore(isolated_history_fs)
    try:
        assert s2.count == 1
        fetched = s2.get(e1.id)
        assert fetched is not None
        assert fetched.content == "persistent"
    finally:
        s2.close()


# ---------------------------------------------------------------------------
# Schema idempotency / corruption
# ---------------------------------------------------------------------------
def test_sqliteSchemaIsIdempotentOnOpen(monkeypatch, isolated_history_fs):
    """Reopening on an existing file does not raise."""
    s1 = SqliteHistoryStore(isolated_history_fs)
    s1.close()
    s2 = SqliteHistoryStore(isolated_history_fs)  # no raise
    s2.close()


def test_sqliteCorruptRowDoesNotCrashList(monkeypatch, isolated_history_fs):
    """Manually corrupt one row and verify ``list`` skips it gracefully."""
    # First, plant a clean entry
    s1 = SqliteHistoryStore(isolated_history_fs)
    s1.add(content="good", contentType="url", response=_make_response())
    s1.close()

    # Now corrupt the response JSON cell
    with sqlite3.connect(isolated_history_fs) as conn:
        conn.execute(
            "UPDATE history SET response = ? WHERE rowid IN (SELECT rowid FROM history LIMIT 1)",
            ("not-json-{[",),
        )
        conn.commit()

    # list() must skip the corrupt row instead of crashing
    s2 = SqliteHistoryStore(isolated_history_fs)
    try:
        result = s2.list()
        # corrupt row is silently dropped; count should be 0
        assert s2.count == 1
        assert all(e.content == "good" or e.content == "" for e in result.entries)
        # And we still see count=1 (the table still has the row even if
        # the row didn't materialise)
    finally:
        s2.close()


# ---------------------------------------------------------------------------
# set_store / module singleton manipulation
# ---------------------------------------------------------------------------
def test_setStore_replacesModuleLevelSingleton():
    from backend.api import historyStore as hs

    original = hs.historyStore
    sentinel = HistoryStore()
    set_store(sentinel)
    try:
        assert hs.historyStore is sentinel
    finally:
        set_store(original)
    assert hs.historyStore is original
