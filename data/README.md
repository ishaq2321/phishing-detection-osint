# Data Directory

## Overview
This directory contains datasets used for phishing detection research and model evaluation.

## Structure
```
data/
├── phishtank/
│   └── phishingUrls.json      # 115 verified phishing URL patterns
├── legitimate/
│   └── legitimateUrls.json    # 225 verified legitimate URLs
├── scripts/
│   ├── collectPhishtank.py    # PhishTank data collection script
│   └── collectLegitimate.py   # Legitimate URL collection script
└── README.md
```

## Datasets

### Phishing URLs (`phishtank/phishingUrls.json`)
- **Source:** PhishTank community database patterns
- **Count:** 115 URLs
- **Categories:** credential_harvesting, subdomain_abuse, homograph, ip_based, url_shortener, fear_tactic, urgency, reward_scam, punycode, and more
- **Targets:** PayPal, Apple, Microsoft, Google, Amazon, Netflix, banks, government agencies, crypto platforms

### Legitimate URLs (`legitimate/legitimateUrls.json`)
- **Source:** Tranco Top Sites List + manual curation
- **Count:** 225 URLs
- **Categories:** search_engine, social_media, ecommerce, technology, news, email, financial, education, entertainment, government, cloud, developer, and more

## Usage

### Regenerate Datasets
```bash
python data/scripts/collectPhishtank.py
python data/scripts/collectLegitimate.py
```

### JSON Structure
Each dataset JSON has:
```json
{
  "metadata": {
    "source": "...",
    "totalUrls": 115,
    "categories": ["..."],
    "collectedAt": "2026-02-10T..."
  },
  "urls": [
    {
      "id": 1,
      "url": "http://...",
      "domain": "...",
      "category": "...",
      "isPhishing": true/false
    }
  ]
}
```

## Notes
- All phishing URLs are patterns based on real-world attacks documented by PhishTank
- Legitimate URLs are from globally recognized, verified top-ranked domains
- Data is used for model evaluation and thesis research only
