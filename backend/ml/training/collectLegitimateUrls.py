"""
Tranco Legitimate URL Dataset Collector
=======================================

Downloads the Tranco top-1M domains list and extracts legitimate URLs
for use as the negative (non-phishing) class in model training.

Tranco (tranco-list.eu) is the gold-standard legitimate domain ranking
in academic research, superseding the discontinued Alexa Top Sites.
It aggregates rankings from Chrome UX Report, Cisco Umbrella,
Majestic Million, and Cloudflare Radar for robustness.

Usage:
    python -m backend.ml.training.collectLegitimateUrls

Output:
    data/raw/legitimate_urls.csv

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
import zipfile
from pathlib import Path

import requests

# ============================================================================
# Configuration
# ============================================================================

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
OUTPUT_DIR = PROJECT_ROOT / "data" / "raw"
OUTPUT_FILE = OUTPUT_DIR / "legitimate_urls.csv"

# Tranco publishes a daily top-1M list. We use the latest "hardened"
# list which is stable and reproducible.
# The ID "X425G" is a permanent Tranco list (you can generate your own
# at https://tranco-list.eu/configure). Using the latest list endpoint.
TRANCO_LATEST_URL = "https://tranco-list.eu/top-1m.csv.zip"

# How many top domains to sample (higher rank = more trustworthy)
SAMPLE_SIZE = 15000

# Request settings
REQUEST_TIMEOUT = 60
REQUEST_HEADERS = {
    "User-Agent": "phishing-detection-thesis/1.0 (academic research)"
}


# ============================================================================
# Download Tranco List
# ============================================================================

def downloadTrancoList() -> list[tuple[int, str]]:
    """
    Download and parse the Tranco top-1M domains list.

    Returns:
        List of (rank, domain) tuples, sorted by rank ascending.

    Raises:
        RuntimeError: If download fails.
    """
    logger.info("Downloading Tranco top-1M domains list...")
    print("📥 Downloading Tranco top-1M domains list...")
    print(f"   Source: {TRANCO_LATEST_URL}")

    try:
        response = requests.get(
            TRANCO_LATEST_URL,
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(
            f"Tranco download failed: {exc}. "
            "You can manually download from https://tranco-list.eu "
            f"and place the CSV at {OUTPUT_DIR / 'tranco_top1m.csv'}"
        ) from exc

    contentLength = len(response.content)
    print(f"   Downloaded: {contentLength / 1024 / 1024:.1f} MB")

    # Tranco serves a ZIP file containing a single CSV
    domains: list[tuple[int, str]] = []

    try:
        with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
            csvFilename = zf.namelist()[0]
            with zf.open(csvFilename) as csvFile:
                reader = csv.reader(
                    io.TextIOWrapper(csvFile, encoding="utf-8")
                )
                for row in reader:
                    if len(row) >= 2:
                        try:
                            rank = int(row[0])
                            domain = row[1].strip().lower()
                            if domain:
                                domains.append((rank, domain))
                        except (ValueError, IndexError):
                            continue
    except zipfile.BadZipFile:
        # Not a ZIP — try parsing as plain CSV
        print("   Note: Response is plain CSV (not ZIP)")
        reader = csv.reader(io.StringIO(response.text))
        for row in reader:
            if len(row) >= 2:
                try:
                    rank = int(row[0])
                    domain = row[1].strip().lower()
                    if domain:
                        domains.append((rank, domain))
                except (ValueError, IndexError):
                    continue

    # Sort by rank
    domains.sort(key=lambda x: x[0])

    print(f"   Parsed: {len(domains)} domains")
    return domains


# ============================================================================
# Local File Fallback
# ============================================================================

def loadLocalTrancoFile() -> list[tuple[int, str]]:
    """
    Load Tranco data from a previously downloaded local file.

    Returns:
        List of (rank, domain) tuples, or empty list.
    """
    localCsv = OUTPUT_DIR / "tranco_top1m.csv"
    if not localCsv.exists():
        return []

    print(f"📂 Loading local Tranco CSV: {localCsv}")
    domains: list[tuple[int, str]] = []

    with open(localCsv, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                try:
                    rank = int(row[0])
                    domain = row[1].strip().lower()
                    if domain:
                        domains.append((rank, domain))
                except (ValueError, IndexError):
                    continue

    domains.sort(key=lambda x: x[0])
    return domains


# ============================================================================
# Existing Curated Data
# ============================================================================

def loadCuratedLegitimateUrls() -> list[dict]:
    """
    Load previously curated legitimate URLs from the project data.

    Returns:
        List of legitimate URL dicts.
    """
    curatedPath = PROJECT_ROOT / "data" / "legitimate" / "legitimateUrls.json"
    if not curatedPath.exists():
        return []

    print(f"📂 Loading curated legitimate URLs: {curatedPath}")
    with open(curatedPath, "r", encoding="utf-8") as f:
        data = json.load(f)

    entries: list[dict] = []
    for item in data.get("urls", []):
        url = item.get("url", "").strip()
        domain = item.get("domain", "").strip()
        if url and domain:
            entries.append({
                "url": url,
                "domain": domain.replace("www.", ""),
                "source": "curated",
                "label": 0,
                "rank": item.get("approximateRank", 0),
                "category": item.get("category", ""),
            })

    return entries


# ============================================================================
# Domain Filtering
# ============================================================================

def filterDomains(
    domains: list[tuple[int, str]],
    sampleSize: int,
) -> list[tuple[int, str]]:
    """
    Filter and sample top domains for legitimate URL dataset.

    Applies quality filters:
    - Skip domains that look suspicious (very short, numeric-only)
    - Skip known CDN/infrastructure domains (not real websites)
    - Take top-ranked domains (most trustworthy)

    Args:
        domains: Sorted (rank, domain) list.
        sampleSize: Number of domains to select.

    Returns:
        Filtered list of (rank, domain) tuples.
    """
    # Infrastructure/CDN domains to skip (not real websites users visit)
    INFRASTRUCTURE_PATTERNS = frozenset({
        "googleapis.com", "gstatic.com", "googleusercontent.com",
        "cloudflare.com", "cloudfront.net", "akamaized.net",
        "amazonaws.com", "azurewebsites.net", "fbcdn.net",
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "googletagmanager.com", "google-analytics.com", "gvt1.com",
        "gvt2.com", "2mdn.net", "adsymptotic.com",
    })

    filtered: list[tuple[int, str]] = []

    for rank, domain in domains:
        # Skip very short domains (likely not real websites)
        if len(domain) < 4:
            continue

        # Skip numeric-only domains
        if domain.replace(".", "").isdigit():
            continue

        # Skip infrastructure domains
        if any(domain.endswith(infra) for infra in INFRASTRUCTURE_PATTERNS):
            continue

        filtered.append((rank, domain))

        if len(filtered) >= sampleSize:
            break

    return filtered


# ============================================================================
# Build Entries
# ============================================================================

def buildEntries(
    domains: list[tuple[int, str]],
) -> list[dict]:
    """
    Convert filtered domains to URL entry dicts.

    Args:
        domains: List of (rank, domain) tuples.

    Returns:
        List of entry dicts with url, domain, source, label, rank.
    """
    entries: list[dict] = []

    for rank, domain in domains:
        entries.append({
            "url": f"https://{domain}",
            "domain": domain,
            "source": "tranco",
            "label": 0,
            "rank": rank,
            "category": "",
        })

    return entries


# ============================================================================
# Merge & Deduplicate
# ============================================================================

def mergeAndDeduplicate(sources: list[list[dict]]) -> list[dict]:
    """
    Merge URL sources and deduplicate by domain.

    Args:
        sources: List of entry lists.

    Returns:
        Deduplicated merged list.
    """
    seenDomains: set[str] = set()
    merged: list[dict] = []

    for source in sources:
        for entry in source:
            domain = entry["domain"].lower().replace("www.", "")
            if domain not in seenDomains:
                seenDomains.add(domain)
                merged.append(entry)

    return merged


# ============================================================================
# Save to CSV
# ============================================================================

def saveToCsv(entries: list[dict], outputPath: Path) -> None:
    """
    Save legitimate URL entries to CSV.

    Args:
        entries: List of URL dicts.
        outputPath: Output file path.
    """
    outputPath.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = ["url", "domain", "source", "label", "rank", "category"]

    with open(outputPath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(entries)


# ============================================================================
# Statistics
# ============================================================================

def printStatistics(entries: list[dict]) -> None:
    """Print dataset statistics."""
    print(f"\n📊 Legitimate URL Dataset Statistics:")
    print(f"   Total unique domains: {len(entries)}")

    # Source breakdown
    sourceCounts: dict[str, int] = {}
    for entry in entries:
        src = entry.get("source", "unknown")
        sourceCounts[src] = sourceCounts.get(src, 0) + 1
    print("   Sources:")
    for src, count in sorted(sourceCounts.items(), key=lambda x: -x[1]):
        print(f"     {src}: {count}")

    # TLD breakdown
    tldCounts: dict[str, int] = {}
    for entry in entries:
        domain = entry.get("domain", "")
        parts = domain.rsplit(".", 1)
        if len(parts) == 2:
            tld = parts[1]
            tldCounts[tld] = tldCounts.get(tld, 0) + 1
    print("   Top TLDs:")
    for tld, count in sorted(tldCounts.items(), key=lambda x: -x[1])[:10]:
        print(f"     .{tld}: {count}")

    # Category breakdown (for curated entries)
    catCounts: dict[str, int] = {}
    for entry in entries:
        cat = entry.get("category", "")
        if cat:
            catCounts[cat] = catCounts.get(cat, 0) + 1
    if catCounts:
        print("   Categories (curated):")
        for cat, count in sorted(catCounts.items(), key=lambda x: -x[1]):
            print(f"     {cat}: {count}")

    # Rank range
    ranks = [e.get("rank", 0) for e in entries if e.get("rank")]
    if ranks:
        print(f"   Rank range: {min(ranks)} – {max(ranks)}")


# ============================================================================
# Main
# ============================================================================

def main() -> None:
    """
    Main entry point: collect legitimate URLs from all available sources.

    Strategy:
    1. Download Tranco top-1M list and sample top N domains
    2. Load curated legitimate URLs from project data
    3. Merge, deduplicate, save
    """
    startTime = time.time()
    print("=" * 60)
    print("  Tranco Legitimate URL Collector")
    print("  BSc Thesis — Ishaq Muhammad (PXPRGK)")
    print("=" * 60)

    allSources: list[list[dict]] = []

    # Source 1: Tranco top-1M download
    try:
        trancoDomains = downloadTrancoList()
        if trancoDomains:
            filtered = filterDomains(trancoDomains, SAMPLE_SIZE)
            trancoEntries = buildEntries(filtered)
            print(f"   ✅ Tranco top domains: {len(trancoEntries)} URLs")
            allSources.append(trancoEntries)
    except Exception as exc:
        print(f"   ⚠️  Tranco download failed: {exc}")
        logger.warning(f"Tranco download failed: {exc}")

        # Try local file
        localDomains = loadLocalTrancoFile()
        if localDomains:
            filtered = filterDomains(localDomains, SAMPLE_SIZE)
            localEntries = buildEntries(filtered)
            print(f"   ✅ Local Tranco file: {len(localEntries)} URLs")
            allSources.append(localEntries)

    # Source 2: Curated dataset
    curatedData = loadCuratedLegitimateUrls()
    if curatedData:
        print(f"   ✅ Curated dataset: {len(curatedData)} URLs")
        allSources.append(curatedData)

    # Merge and deduplicate
    merged = mergeAndDeduplicate(allSources)

    if not merged:
        print("\n❌ No legitimate URLs collected from any source!")
        print("   Please download Tranco list manually:")
        print("   1. Visit https://tranco-list.eu/download_daily/latest")
        print("   2. Extract the CSV from the ZIP")
        print(f"   3. Place it at: {OUTPUT_DIR / 'tranco_top1m.csv'}")
        print("   4. Re-run this script")
        sys.exit(1)

    # Save
    saveToCsv(merged, OUTPUT_FILE)

    elapsed = time.time() - startTime
    print(f"\n✅ Saved {len(merged)} legitimate URLs to {OUTPUT_FILE}")
    print(f"   Time: {elapsed:.1f}s")
    printStatistics(merged)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
