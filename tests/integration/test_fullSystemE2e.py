"""
Integration Test Suite — Frontend ↔ Backend End-to-End

Tests the complete system with both servers running simultaneously.
Validates all 8 test scenarios from Issue #57.

Usage:
    1. Start the backend:  cd project-root && uvicorn backend.main:app --port 8000
    2. Run this script:    python tests/integration/test_fullSystemE2e.py

Author: Ishaq Muhammad (PXPRGK)
"""

import json
import sys
import time
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

BASE_URL = "http://localhost:8000"
TIMEOUT = 30
RESULTS: list[dict] = []


def log(status: str, test: str, detail: str = "") -> None:
    """Log a test result."""
    icon = "✅" if status == "PASS" else "❌"
    RESULTS.append({"test": test, "status": status, "detail": detail})
    extra = f" — {detail}" if detail else ""
    print(f"  {icon} {test}{extra}")


def post(path: str, payload: dict) -> dict:
    """Send a POST request and return JSON response."""
    data = json.dumps(payload).encode("utf-8")
    req = Request(
        f"{BASE_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read())


def get(path: str) -> dict:
    """Send a GET request and return JSON response."""
    req = Request(f"{BASE_URL}{path}", method="GET")
    with urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read())


def delete(path: str) -> dict:
    """Send a DELETE request and return JSON response."""
    req = Request(f"{BASE_URL}{path}", method="DELETE")
    with urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read())


# ─────────────────────────────────────────────────────────────────
#  Test 1: Health Check
# ─────────────────────────────────────────────────────────────────
def test1HealthCheck() -> None:
    """GET /api/health → healthy status with all services."""
    name = "1. Health Check"
    try:
        resp = get("/api/health")
        assert resp["status"] == "healthy", f"status={resp['status']}"
        assert resp["services"]["osint"] is True
        assert resp["services"]["analyzer"] is True
        assert resp["services"]["ml"] is True
        assert "version" in resp
        assert "timestamp" in resp
        log("PASS", name, f"v{resp['version']}, all services up")
    except Exception as e:
        log("FAIL", name, str(e))


# ─────────────────────────────────────────────────────────────────
#  Test 2: URL Analysis E2E
# ─────────────────────────────────────────────────────────────────
def test2UrlAnalysis() -> None:
    """POST /api/analyze/url → full analysis response."""
    name = "2. URL Analysis (safe)"
    try:
        start = time.time()
        resp = post("/api/analyze/url", {"url": "https://www.google.com"})
        elapsed = time.time() - start

        assert resp["success"] is True, "success should be True"
        assert "verdict" in resp, "missing verdict"
        assert "osint" in resp, "missing osint"
        assert "features" in resp, "missing features"
        assert resp["verdict"]["threatLevel"] in (
            "safe", "suspicious", "dangerous", "critical"
        ), f"invalid threatLevel={resp['verdict']['threatLevel']}"
        assert 0 <= resp["verdict"]["confidenceScore"] <= 1
        assert isinstance(resp["verdict"]["reasons"], list)
        assert elapsed < 30, f"took {elapsed:.1f}s (>30s)"

        score = resp["verdict"]["confidenceScore"]
        level = resp["verdict"]["threatLevel"]
        log("PASS", name, f"score={score:.2f}, level={level}, {elapsed:.1f}s")
    except Exception as e:
        log("FAIL", name, str(e))


# ─────────────────────────────────────────────────────────────────
#  Test 3: Email Analysis E2E
# ─────────────────────────────────────────────────────────────────
def test3EmailAnalysis() -> None:
    """POST /api/analyze/email → email-specific analysis."""
    name = "3. Email Analysis"
    try:
        start = time.time()
        resp = post("/api/analyze/email", {
            "content": "Dear customer, your account has been compromised. "
                       "Click here immediately to verify your credentials.",
            "subject": "URGENT: Account Verification Required",
            "sender": "security@bank-supp0rt.com",
        })
        elapsed = time.time() - start

        assert resp["success"] is True
        assert resp["verdict"]["threatLevel"] in (
            "suspicious", "dangerous", "critical"
        ), f"Expected phishing detection, got {resp['verdict']['threatLevel']}"
        assert len(resp["verdict"]["reasons"]) > 0

        level = resp["verdict"]["threatLevel"]
        score = resp["verdict"]["confidenceScore"]
        reasons = len(resp["verdict"]["reasons"])
        log("PASS", name, f"score={score:.2f}, level={level}, {reasons} reasons, {elapsed:.1f}s")
    except Exception as e:
        log("FAIL", name, str(e))


# ─────────────────────────────────────────────────────────────────
#  Test 4: Auto-Detect Content Type
# ─────────────────────────────────────────────────────────────────
def test4AutoDetect() -> None:
    """POST /api/analyze (auto) → correct content type detection."""
    name = "4. Auto-Detect (URL)"
    try:
        resp = post("/api/analyze", {
            "content": "https://www.example.com",
            "contentType": "auto",
        })
        assert resp["success"] is True
        assert "verdict" in resp
        log("PASS", name, f"level={resp['verdict']['threatLevel']}")
    except Exception as e:
        log("FAIL", name, str(e))


# ─────────────────────────────────────────────────────────────────
#  Test 5: Validation Errors
# ─────────────────────────────────────────────────────────────────
def test5ValidationErrors() -> None:
    """POST with invalid data → 422 validation error."""
    name = "5. Validation Errors"
    try:
        # Empty URL should fail validation
        data = json.dumps({"url": ""}).encode("utf-8")
        req = Request(
            f"{BASE_URL}/api/analyze/url",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urlopen(req, timeout=TIMEOUT)
            log("FAIL", name, "Expected 422 but got 200")
        except HTTPError as e:
            if e.code == 422:
                log("PASS", name, "422 Unprocessable Entity returned")
            else:
                log("FAIL", name, f"Expected 422, got {e.code}")
    except Exception as e:
        log("FAIL", name, str(e))


# ─────────────────────────────────────────────────────────────────
#  Test 6: History CRUD
# ─────────────────────────────────────────────────────────────────
def test6HistoryCrud() -> None:
    """Analyse → History list → View → Delete → Verify deletion."""
    name = "6. History CRUD"
    try:
        # Clear history first
        delete("/api/history")

        # Perform an analysis (auto-saved to history)
        post("/api/analyze/url", {"url": "https://www.example.com"})

        # List history
        history = get("/api/history")
        assert history["total"] >= 1, f"Expected ≥1 entries, got {history['total']}"

        # Get single entry
        entryId = history["entries"][0]["id"]
        entry = get(f"/api/history/{entryId}")
        assert entry["id"] == entryId
        assert entry["contentType"] in ("url", "email", "text", "auto")

        # Delete the entry
        deleteResp = delete(f"/api/history/{entryId}")
        assert deleteResp.get("deleted") is True or "success" in str(deleteResp).lower()

        # Verify deletion
        remaining = get("/api/history")
        remainingIds = [e["id"] for e in remaining["entries"]]
        assert entryId not in remainingIds, "Entry should be deleted"

        log("PASS", name, f"create→list→view→delete cycle OK, {remaining['total']} remaining")
    except Exception as e:
        log("FAIL", name, str(e))


# ─────────────────────────────────────────────────────────────────
#  Test 7: Response Time
# ─────────────────────────────────────────────────────────────────
def test7ResponseTime() -> None:
    """Single analysis should complete within 5 seconds."""
    name = "7. Response Time (<5s)"
    try:
        start = time.time()
        resp = post("/api/analyze", {
            "content": "https://www.wikipedia.org",
            "contentType": "url",
        })
        elapsed = time.time() - start

        assert resp["success"] is True
        assert elapsed < 5.0, f"Response took {elapsed:.2f}s (limit: 5s)"
        log("PASS", name, f"{elapsed:.2f}s")
    except Exception as e:
        log("FAIL", name, str(e))


# ─────────────────────────────────────────────────────────────────
#  Test 8: Concurrent Requests
# ─────────────────────────────────────────────────────────────────
def test8ConcurrentRequests() -> None:
    """Multiple sequential requests don't cause errors."""
    name = "8. Sequential Stress (5 requests)"
    try:
        urls = [
            "https://www.google.com",
            "https://www.github.com",
            "https://www.example.com",
            "https://www.python.org",
            "https://www.wikipedia.org",
        ]
        times = []
        for url in urls:
            start = time.time()
            resp = post("/api/analyze/url", {"url": url})
            elapsed = time.time() - start
            times.append(elapsed)
            assert resp["success"] is True, f"Failed for {url}"

        avgTime = sum(times) / len(times)
        log("PASS", name, f"all succeeded, avg={avgTime:.2f}s")
    except Exception as e:
        log("FAIL", name, str(e))


# ─────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────
def main() -> int:
    print("\n" + "=" * 60)
    print("  PhishGuard — Full System Integration Tests")
    print("=" * 60)
    print(f"  Backend: {BASE_URL}")
    print()

    # Verify backend is reachable
    try:
        get("/api/health")
    except (URLError, ConnectionRefusedError):
        print("  ❌ Backend not reachable at", BASE_URL)
        print("     Start it with: uvicorn backend.main:app --port 8000")
        return 1

    tests = [
        test1HealthCheck,
        test2UrlAnalysis,
        test3EmailAnalysis,
        test4AutoDetect,
        test5ValidationErrors,
        test6HistoryCrud,
        test7ResponseTime,
        test8ConcurrentRequests,
    ]

    for test in tests:
        test()

    # Summary
    passed = sum(1 for r in RESULTS if r["status"] == "PASS")
    failed = sum(1 for r in RESULTS if r["status"] == "FAIL")
    total = len(RESULTS)

    print()
    print("-" * 60)
    print(f"  Results: {passed}/{total} passed", end="")
    if failed > 0:
        print(f", {failed} failed")
    else:
        print(" ✅ All integration tests passed!")
    print("-" * 60)
    print()

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
