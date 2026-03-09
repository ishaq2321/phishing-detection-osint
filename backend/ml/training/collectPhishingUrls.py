"""
PhishTank Dataset Collector
===========================

Downloads verified phishing URLs from the PhishTank online database.
PhishTank (phishtank.org) is a community-driven phishing URL verification
service, widely used in academic research for phishing detection.

This script downloads the publicly available verified phishing URL feed,
filters for confirmed phishing entries, deduplicates, cleans, and outputs
a structured CSV ready for feature extraction.

Usage:
    python -m backend.ml.training.collectPhishingUrls

Output:
    data/raw/phishing_urls.csv

Author: Ishaq Muhammad (PXPRGK)
Course: BSc Thesis - ELTE Faculty of Informatics
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

# ============================================================================
# Configuration
# ============================================================================

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
OUTPUT_DIR = PROJECT_ROOT / "data" / "raw"
OUTPUT_FILE = OUTPUT_DIR / "phishing_urls.csv"

# PhishTank publishes a downloadable database of verified phishing URLs.
# The "verified_online.csv" endpoint is the community-verified feed.
# No API key needed for the CSV download (only for API queries).
PHISHTANK_CSV_URL = (
    "http://data.phishtank.com/data/online-valid.csv"
)

# Alternative: PhishTank JSON feed (larger but more structured)
PHISHTANK_JSON_URL = (
    "http://data.phishtank.com/data/online-valid.json"
)

# OpenPhish community feed — free, updated regularly (~2K URLs)
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"

# URLhaus by abuse.ch — recent malicious URLs (includes phishing)
URLHAUS_CSV_URL = (
    "https://urlhaus.abuse.ch/downloads/csv_recent/"
)

# PhishStats — scored phishing URLs (public, no auth)
PHISHSTATS_URL = (
    "https://phishstats.info/phish_score.csv"
)

# Minimum acceptable dataset size
MIN_PHISHING_URLS = 1000

# Request settings
REQUEST_TIMEOUT = 120
REQUEST_HEADERS = {
    "User-Agent": "phishtank/ishaq-thesis-research"
}


# ============================================================================
# Domain Extraction
# ============================================================================

def extractDomain(url: str) -> str:
    """
    Extract the domain from a URL, handling edge cases.

    Args:
        url: Raw URL string.

    Returns:
        Cleaned domain string, or empty string on failure.
    """
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc or parsed.path.split("/")[0]
        # Remove port, userinfo
        netloc = netloc.split("@")[-1].split(":")[0]
        return netloc.lower().strip(".")
    except Exception:
        return ""


# ============================================================================
# CSV Feed Download
# ============================================================================

def downloadPhishtankCsv() -> list[dict]:
    """
    Download PhishTank's verified online CSV feed.

    Returns:
        List of dicts with keys: url, domain, source, label, phishtankId,
        verificationTime, target.

    Raises:
        RuntimeError: If download fails or dataset is too small.
    """
    logger.info("Downloading PhishTank CSV feed...")
    print("📥 Downloading PhishTank verified phishing URLs...")
    print(f"   Source: {PHISHTANK_CSV_URL}")

    try:
        response = requests.get(
            PHISHTANK_CSV_URL,
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT,
            stream=True,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        logger.warning(f"CSV download failed: {exc}. Trying JSON feed...")
        return downloadPhishtankJson()

    contentLength = response.headers.get("Content-Length", "unknown")
    print(f"   Download size: {contentLength} bytes")

    # PhishTank CSV columns:
    # phish_id, url, phish_detail_url, submission_time,
    # verified, verification_time, online, target
    rawText = response.text
    reader = csv.DictReader(io.StringIO(rawText))

    entries: list[dict] = []
    seenUrls: set[str] = set()
    skippedCount = 0

    for row in reader:
        url = row.get("url", "").strip()
        verified = row.get("verified", "").strip().lower()
        online = row.get("online", "").strip().lower()

        # Only take verified, currently online phishing URLs
        if verified != "yes" or online != "yes":
            skippedCount += 1
            continue

        # Deduplicate
        normalizedUrl = url.lower().rstrip("/")
        if normalizedUrl in seenUrls:
            continue
        seenUrls.add(normalizedUrl)

        domain = extractDomain(url)
        if not domain:
            continue

        entries.append({
            "url": url,
            "domain": domain,
            "source": "phishtank",
            "label": 1,
            "phishtankId": row.get("phish_id", ""),
            "verificationTime": row.get("verification_time", ""),
            "target": row.get("target", ""),
        })

    logger.info(
        f"PhishTank CSV: {len(entries)} verified URLs "
        f"({skippedCount} skipped)"
    )
    return entries


def downloadPhishtankJson() -> list[dict]:
    """
    Fallback: download PhishTank's JSON feed.

    Returns:
        List of dicts with same structure as CSV download.

    Raises:
        RuntimeError: If download fails.
    """
    logger.info("Downloading PhishTank JSON feed (fallback)...")
    print("📥 Trying PhishTank JSON feed (fallback)...")

    try:
        response = requests.get(
            PHISHTANK_JSON_URL,
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(
            f"Both PhishTank CSV and JSON downloads failed: {exc}. "
            "PhishTank may require registration or rate-limit. "
            "Please visit https://phishtank.org/developer_info.php "
            "and download the feed manually, then place it at "
            f"{OUTPUT_DIR / 'online-valid.csv'}"
        ) from exc

    data = response.json()
    entries: list[dict] = []
    seenUrls: set[str] = set()

    for item in data:
        url = item.get("url", "").strip()
        verified = item.get("verified", "")
        online = item.get("details", [{}])

        # Only verified entries
        if verified != "yes":
            continue

        normalizedUrl = url.lower().rstrip("/")
        if normalizedUrl in seenUrls:
            continue
        seenUrls.add(normalizedUrl)

        domain = extractDomain(url)
        if not domain:
            continue

        entries.append({
            "url": url,
            "domain": domain,
            "source": "phishtank",
            "label": 1,
            "phishtankId": str(item.get("phish_id", "")),
            "verificationTime": item.get("verification_time", ""),
            "target": item.get("target", ""),
        })

    return entries


# ============================================================================
# OpenPhish Feed Download
# ============================================================================

def downloadOpenPhishFeed() -> list[dict]:
    """
    Download phishing URLs from the OpenPhish community feed.

    OpenPhish (openphish.com) provides a free community feed of
    active phishing URLs, updated regularly. No API key required.

    Returns:
        List of phishing URL dicts.
    """
    logger.info("Downloading OpenPhish community feed...")
    print("📥 Downloading OpenPhish community feed...")

    try:
        response = requests.get(
            OPENPHISH_FEED_URL,
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        logger.warning(f"OpenPhish download failed: {exc}")
        return []

    entries: list[dict] = []
    seenUrls: set[str] = set()

    for line in response.text.strip().splitlines():
        url = line.strip()
        if not url or url.startswith("#"):
            continue

        normalizedUrl = url.lower().rstrip("/")
        if normalizedUrl in seenUrls:
            continue
        seenUrls.add(normalizedUrl)

        domain = extractDomain(url)
        if not domain:
            continue

        entries.append({
            "url": url,
            "domain": domain,
            "source": "openphish",
            "label": 1,
            "phishtankId": "",
            "verificationTime": "",
            "target": "",
        })

    logger.info(f"OpenPhish: {len(entries)} phishing URLs")
    return entries


# ============================================================================
# URLhaus Feed Download
# ============================================================================

def downloadUrlhausFeed() -> list[dict]:
    """
    Download malicious URLs from URLhaus (abuse.ch).

    URLhaus provides a CSV feed of recent malicious URLs including
    phishing sites. Free, no authentication required.

    Returns:
        List of phishing URL dicts (filtered to phishing-related tags).
    """
    logger.info("Downloading URLhaus recent feed...")
    print("📥 Downloading URLhaus malicious URL feed...")

    try:
        response = requests.get(
            URLHAUS_CSV_URL,
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        logger.warning(f"URLhaus download failed: {exc}")
        return []

    entries: list[dict] = []
    seenUrls: set[str] = set()

    # URLhaus CSV has comment lines starting with #
    lines = [
        line for line in response.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]

    if not lines:
        return []

    reader = csv.reader(io.StringIO("\n".join(lines)))

    for row in reader:
        if len(row) < 4:
            continue

        # URLhaus CSV columns:
        # id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        url = row[2].strip().strip('"')
        threat = row[5].strip().strip('"') if len(row) > 5 else ""
        tags = row[6].strip().strip('"') if len(row) > 6 else ""

        if not url or not url.startswith("http"):
            continue

        normalizedUrl = url.lower().rstrip("/")
        if normalizedUrl in seenUrls:
            continue
        seenUrls.add(normalizedUrl)

        domain = extractDomain(url)
        if not domain:
            continue

        entries.append({
            "url": url,
            "domain": domain,
            "source": "urlhaus",
            "label": 1,
            "phishtankId": "",
            "verificationTime": "",
            "target": tags,
        })

    logger.info(f"URLhaus: {len(entries)} malicious URLs")
    return entries


# ============================================================================
# PhishStats Feed Download
# ============================================================================

def downloadPhishStatsFeed() -> list[dict]:
    """
    Download phishing URLs from PhishStats.

    PhishStats (phishstats.info) provides a scored CSV of phishing URLs
    with confidence scores. Free, no auth required.

    Returns:
        List of high-confidence phishing URL dicts.
    """
    logger.info("Downloading PhishStats feed...")
    print("📥 Downloading PhishStats phishing URL feed...")

    try:
        response = requests.get(
            PHISHSTATS_URL,
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        logger.warning(f"PhishStats download failed: {exc}")
        return []

    entries: list[dict] = []
    seenUrls: set[str] = set()

    # PhishStats CSV has comment lines starting with #
    lines = [
        line for line in response.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]

    if not lines:
        return []

    reader = csv.reader(io.StringIO("\n".join(lines)))

    for row in reader:
        if len(row) < 3:
            continue

        # PhishStats columns: date, score, url, ip
        try:
            score = float(row[1].strip().strip('"'))
        except (ValueError, IndexError):
            continue

        url = row[2].strip().strip('"')

        # Only take high-confidence phishing (score >= 5)
        if score < 5:
            continue

        if not url or not url.startswith("http"):
            continue

        normalizedUrl = url.lower().rstrip("/")
        if normalizedUrl in seenUrls:
            continue
        seenUrls.add(normalizedUrl)

        domain = extractDomain(url)
        if not domain:
            continue

        entries.append({
            "url": url,
            "domain": domain,
            "source": "phishstats",
            "label": 1,
            "phishtankId": "",
            "verificationTime": "",
            "target": "",
        })

    logger.info(f"PhishStats: {len(entries)} phishing URLs (score>=5)")
    return entries


# ============================================================================
# Local File Fallback
# ============================================================================

def loadLocalPhishtankFile() -> list[dict]:
    """
    Load PhishTank data from a previously downloaded local file.

    Checks for CSV or JSON files in data/raw/.

    Returns:
        List of phishing URL dicts, or empty list if no local file.
    """
    csvPath = OUTPUT_DIR / "online-valid.csv"
    jsonPath = OUTPUT_DIR / "online-valid.json"

    if csvPath.exists():
        print(f"📂 Loading local PhishTank CSV: {csvPath}")
        with open(csvPath, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            entries: list[dict] = []
            seenUrls: set[str] = set()

            for row in reader:
                url = row.get("url", "").strip()
                if not url:
                    continue
                normalizedUrl = url.lower().rstrip("/")
                if normalizedUrl in seenUrls:
                    continue
                seenUrls.add(normalizedUrl)

                domain = extractDomain(url)
                if not domain:
                    continue

                entries.append({
                    "url": url,
                    "domain": domain,
                    "source": "phishtank",
                    "label": 1,
                    "phishtankId": row.get("phish_id", ""),
                    "verificationTime": row.get("verification_time", ""),
                    "target": row.get("target", ""),
                })
            return entries

    if jsonPath.exists():
        print(f"📂 Loading local PhishTank JSON: {jsonPath}")
        with open(jsonPath, "r", encoding="utf-8") as f:
            data = json.load(f)

        entries = []
        seenUrls: set[str] = set()
        for item in data:
            url = item.get("url", "").strip()
            if not url:
                continue
            normalizedUrl = url.lower().rstrip("/")
            if normalizedUrl in seenUrls:
                continue
            seenUrls.add(normalizedUrl)

            domain = extractDomain(url)
            if not domain:
                continue

            entries.append({
                "url": url,
                "domain": domain,
                "source": "phishtank",
                "label": 1,
                "phishtankId": str(item.get("phish_id", "")),
                "verificationTime": item.get("verification_time", ""),
                "target": item.get("target", ""),
            })
        return entries

    return []


# ============================================================================
# Existing Curated Data
# ============================================================================

def loadCuratedPhishingUrls() -> list[dict]:
    """
    Load previously curated phishing URLs from the project data.

    Returns:
        List of phishing URL dicts from data/phishtank/phishingUrls.json.
    """
    curatedPath = PROJECT_ROOT / "data" / "phishtank" / "phishingUrls.json"
    if not curatedPath.exists():
        return []

    print(f"📂 Loading curated phishing URLs: {curatedPath}")
    with open(curatedPath, "r", encoding="utf-8") as f:
        data = json.load(f)

    entries: list[dict] = []
    for item in data.get("urls", []):
        url = item.get("url", "").strip()
        if not url:
            continue
        domain = extractDomain(url)
        entries.append({
            "url": url,
            "domain": domain or "unknown",
            "source": "curated",
            "label": 1,
            "phishtankId": "",
            "verificationTime": "",
            "target": item.get("target", ""),
        })

    return entries


# ============================================================================
# Merging & Deduplication
# ============================================================================

def mergeAndDeduplicate(sources: list[list[dict]]) -> list[dict]:
    """
    Merge multiple URL sources and deduplicate by normalized URL.

    Args:
        sources: List of URL entry lists to merge.

    Returns:
        Deduplicated, merged list.
    """
    seenUrls: set[str] = set()
    merged: list[dict] = []

    for source in sources:
        for entry in source:
            normalizedUrl = entry["url"].lower().rstrip("/")
            if normalizedUrl not in seenUrls:
                seenUrls.add(normalizedUrl)
                merged.append(entry)

    return merged


# ============================================================================
# Save to CSV
# ============================================================================

def saveToCsv(entries: list[dict], outputPath: Path) -> None:
    """
    Save phishing URL entries to a CSV file.

    Args:
        entries: List of URL dicts.
        outputPath: Output CSV path.
    """
    outputPath.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "url", "domain", "source", "label",
        "phishtankId", "verificationTime", "target",
    ]

    with open(outputPath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(entries)


# ============================================================================
# Statistics
# ============================================================================

def printStatistics(entries: list[dict]) -> None:
    """Print dataset statistics."""
    print(f"\n📊 Phishing URL Dataset Statistics:")
    print(f"   Total unique URLs: {len(entries)}")

    # Source breakdown
    sourceCounts: dict[str, int] = {}
    for entry in entries:
        src = entry.get("source", "unknown")
        sourceCounts[src] = sourceCounts.get(src, 0) + 1
    print("   Sources:")
    for src, count in sorted(sourceCounts.items(), key=lambda x: -x[1]):
        print(f"     {src}: {count}")

    # Target breakdown
    targetCounts: dict[str, int] = {}
    for entry in entries:
        target = entry.get("target", "")
        if target:
            targetCounts[target] = targetCounts.get(target, 0) + 1
    if targetCounts:
        print("   Top targets:")
        for target, count in sorted(
            targetCounts.items(), key=lambda x: -x[1]
        )[:10]:
            print(f"     {target}: {count}")

    # Domain TLD breakdown
    tldCounts: dict[str, int] = {}
    for entry in entries:
        domain = entry.get("domain", "")
        parts = domain.rsplit(".", 1)
        if len(parts) == 2:
            tld = parts[1]
            tldCounts[tld] = tldCounts.get(tld, 0) + 1
    if tldCounts:
        print("   Top TLDs:")
        for tld, count in sorted(
            tldCounts.items(), key=lambda x: -x[1]
        )[:10]:
            print(f"     .{tld}: {count}")


# ============================================================================
# Main
# ============================================================================

def main() -> None:
    """
    Main entry point: collect phishing URLs from all available sources.

    Strategy:
    1. Try downloading from PhishTank (CSV → JSON fallback)
    2. Check for locally downloaded PhishTank file
    3. Load curated phishing URLs from project data
    4. Merge all sources, deduplicate, save
    """
    startTime = time.time()
    print("=" * 60)
    print("  PhishTank Phishing URL Collector")
    print("  BSc Thesis — Ishaq Muhammad (PXPRGK)")
    print("=" * 60)

    allSources: list[list[dict]] = []

    # Source 1: Live PhishTank download
    try:
        liveData = downloadPhishtankCsv()
        if liveData:
            print(f"   ✅ PhishTank live feed: {len(liveData)} URLs")
            allSources.append(liveData)
    except Exception as exc:
        print(f"   ⚠️  PhishTank download failed: {exc}")
        logger.warning(f"PhishTank download failed: {exc}")

    # Source 2: OpenPhish community feed
    try:
        openphishData = downloadOpenPhishFeed()
        if openphishData:
            print(f"   ✅ OpenPhish feed: {len(openphishData)} URLs")
            allSources.append(openphishData)
    except Exception as exc:
        print(f"   ⚠️  OpenPhish download failed: {exc}")
        logger.warning(f"OpenPhish download failed: {exc}")

    # Source 3: URLhaus malicious URLs
    try:
        urlhausData = downloadUrlhausFeed()
        if urlhausData:
            print(f"   ✅ URLhaus feed: {len(urlhausData)} URLs")
            allSources.append(urlhausData)
    except Exception as exc:
        print(f"   ⚠️  URLhaus download failed: {exc}")
        logger.warning(f"URLhaus download failed: {exc}")

    # Source 4: PhishStats scored URLs
    try:
        phishstatsData = downloadPhishStatsFeed()
        if phishstatsData:
            print(f"   ✅ PhishStats feed: {len(phishstatsData)} URLs")
            allSources.append(phishstatsData)
    except Exception as exc:
        print(f"   ⚠️  PhishStats download failed: {exc}")
        logger.warning(f"PhishStats download failed: {exc}")

    # Source 5: Local PhishTank file (manual download)
    localData = loadLocalPhishtankFile()
    if localData:
        print(f"   ✅ Local PhishTank file: {len(localData)} URLs")
        allSources.append(localData)

    # Source 6: Curated dataset (always available)
    curatedData = loadCuratedPhishingUrls()
    if curatedData:
        print(f"   ✅ Curated dataset: {len(curatedData)} URLs")
        allSources.append(curatedData)

    # Merge and deduplicate
    merged = mergeAndDeduplicate(allSources)

    if not merged:
        print("\n❌ No phishing URLs collected from any source!")
        print("   Please download the PhishTank feed manually:")
        print("   1. Visit https://phishtank.org/developer_info.php")
        print("   2. Download 'online-valid.csv'")
        print(f"   3. Place it at: {OUTPUT_DIR / 'online-valid.csv'}")
        print("   4. Re-run this script")
        sys.exit(1)

    # Save
    saveToCsv(merged, OUTPUT_FILE)

    elapsed = time.time() - startTime
    print(f"\n✅ Saved {len(merged)} phishing URLs to {OUTPUT_FILE}")
    print(f"   Time: {elapsed:.1f}s")
    printStatistics(merged)

    if len(merged) < MIN_PHISHING_URLS:
        print(
            f"\n⚠️  Warning: Only {len(merged)} URLs collected. "
            f"Target is {MIN_PHISHING_URLS}+."
        )
        print("   For better results, download the PhishTank feed manually.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
