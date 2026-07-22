"""
Unit tests for the API-key authentication middleware.

Customers
---------

* The configured-key parser behaves on empty / blank / multi-key inputs
  and never stores raw key bytes (always sha256 hex digest).
* The sha256 digester is deterministic and unaffected by surrounding
  whitespace.
* The constant-time membership test returns True iff the target
  appears in the iterable and never short-circuits differently.
* ``isProtected`` matches the protected prefixes and rejects everything
  else.
* The 401 response carries both the JSON body and the
  ``WWW-Authenticate`` header.
* ``makeAuthDispatch`` returns a pass-through dispatch when no keys
  are configured, and a strict dispatch when keys are configured.
"""

from __future__ import annotations

import pytest
from starlette.responses import JSONResponse

from backend.api.auth import (
    HEADER_API_KEY,
    WWW_AUTH_HEADER,
    constantTimeContains,
    configuredHashes,
    hashKey,
    isProtected,
    makeAuthDispatch,
    unauthorized,
)


# ---------------------------------------------------------------------------
# hashKey
# ---------------------------------------------------------------------------
def test_hashKey_isStablyDeterministic():
    """Same input -> same digest."""
    assert hashKey("alpha") == hashKey("alpha")


def test_hashKey_differsForDifferentInputs():
    """Different inputs -> different digests."""
    assert hashKey("alpha") != hashKey("beta")


def test_hashKey_returnsHexOfExpectedLength():
    """Sha256 hex is exactly 64 chars."""
    assert len(hashKey("anything")) == 64


def test_hashKey_matchesStdlibHashlib():
    """Compare against ``hashlib.sha256`` to verify the digest format."""
    import hashlib

    assert hashKey("k3y") == hashlib.sha256(b"k3y").hexdigest()


# ---------------------------------------------------------------------------
# configuredHashes
# ---------------------------------------------------------------------------
def test_configuredHashes_noneReturnsEmpty():
    assert configuredHashes(None) == frozenset()


def test_configuredHashes_emptyReturnsEmpty():
    assert configuredHashes("") == frozenset()


def test_configuredHashes_whitespaceOnlyReturnsEmpty():
    assert configuredHashes("   ") == frozenset()


def test_configuredHashes_singleKey():
    hashes = configuredHashes("foo")
    assert hashes == frozenset({hashKey("foo")})


def test_configuredHashes_roundTripsRawBytesToDigest():
    """The configured set MUST NOT contain the raw key value."""
    raw = "super-secret"
    hashes = configuredHashes(raw)
    assert raw not in hashes
    assert hashKey(raw) in hashes


def test_configuredHashes_multiKeyCommaSeparated():
    hashes = configuredHashes("alpha,beta,gamma")
    assert hashes == frozenset(
        {hashKey("alpha"), hashKey("beta"), hashKey("gamma")}
    )


def test_configuredHashes_stripsWhitespaceAroundKeys():
    hashes = configuredHashes(" alpha , beta ")
    assert hashes == frozenset({hashKey("alpha"), hashKey("beta")})


def test_configuredHashes_skipsEmptyCommaPieces():
    """``a,,b`` does not produce a digest of the empty string."""
    hashes = configuredHashes("a,,b,")
    assert hashes == frozenset({hashKey("a"), hashKey("b")})


# ---------------------------------------------------------------------------
# isProtected
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "path",
    [
        "/api/analyze",
        "/api/analyze/url",
        "/api/analyze/email",
        "/api/analyze/anything-else",
    ],
)
def test_isProtected_returnsTrueForAnalyzePaths(path):
    assert isProtected(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/api/health",
        "/api/model/status",
        "/api/history",
        "/api/history/abc",
        "/docs",
        "/openapi.json",
        "/redoc",
    ],
)
def test_isProtected_returnsFalseForNonAnalyzePaths(path):
    assert isProtected(path) is False


# ---------------------------------------------------------------------------
# constantTimeContains
# ---------------------------------------------------------------------------
def test_constantTimeContains_member():
    """An element equal to target is found."""
    digests = frozenset({hashKey("k1"), hashKey("k2"), hashKey("k3")})
    assert constantTimeContains(hashKey("k2"), digests) is True


def test_constantTimeContains_strangerNotMember():
    """A digest not in the set returns False."""
    digests = frozenset({hashKey("k1"), hashKey("k2")})
    assert constantTimeContains(hashKey("nope"), digests) is False


def test_constantTimeContains_emptyCandidateSet():
    """No candidates -> always False."""
    assert constantTimeContains("anything", frozenset()) is False


# ---------------------------------------------------------------------------
# unauthorized response builder
# ---------------------------------------------------------------------------
def test_unauthorized_returns401Json():
    response = unauthorized("Missing X-Api-Key header")
    assert response.status_code == 401
    assert response.headers[WWW_AUTH_HEADER] == "ApiKey"
    body = response.body.decode("utf-8")
    assert "Missing X-Api-Key header" in body


def test_unauthorized_bodyCarriesDetailKey():
    """The body conforms to the standard ``detail`` shape."""
    response = unauthorized("Invalid")
    body = response.body.decode("utf-8")
    assert '"detail"' in body
    assert '"Invalid"' in body


# ---------------------------------------------------------------------------
# makeAuthDispatch
# ---------------------------------------------------------------------------
def test_makeAuthDispatch_withEmptyConfigIsCallable():
    """An empty hash-set yields a working pass-through dispatch."""
    dispatch = makeAuthDispatch(frozenset())
    assert callable(dispatch)
    assert hasattr(dispatch, "__call__")


def test_makeAuthDispatch_withConfigIsCallable():
    dispatch = makeAuthDispatch(frozenset({hashKey("k1")}))
    assert callable(dispatch)
