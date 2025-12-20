# Background Research: Phishing Detection Using OSINT-Enhanced Features

## 1. Phishing Threat Landscape

### What is Phishing?
Phishing is a cybersecurity attack that uses deceptive emails, websites, or messages to trick users into revealing sensitive information (passwords, credit cards, personal data). Attackers impersonate trusted entities like banks, social media platforms, or colleagues.

### Types of Phishing
| Type | Description |
|------|-------------|
| **Email Phishing** | Mass emails mimicking legitimate organizations |
| **Spear Phishing** | Targeted attacks on specific individuals |
| **Whaling** | Targeting high-profile executives |
| **Smishing** | SMS-based phishing |
| **Vishing** | Voice call phishing |
| **Clone Phishing** | Cloning legitimate emails with malicious links |

### Why Traditional Detection Fails
- Relies only on email text/structure
- No external intelligence about domain authenticity
- Attackers constantly evolve tactics
- Zero-day phishing sites bypass signature-based detection

---

## 2. OSINT (Open-Source Intelligence) Techniques

### What is OSINT?
Publicly available information collected from open sources to enrich threat intelligence.

### OSINT Features for Phishing Detection

| Feature | Source | Why It Matters |
|---------|--------|----------------|
| **Domain Age** | WHOIS | New domains (<30 days) are often malicious |
| **Registrar Info** | WHOIS | Cheap/anonymous registrars = red flag |
| **DNS Records** | DNS Lookup | Missing MX records, suspicious IPs |
| **SSL Certificate** | Certificate Transparency | Self-signed, mismatched, or missing certs |
| **Alexa/Popularity Rank** | Web APIs | Legitimate sites have traffic history |
| **Blacklist Status** | PhishTank, Google Safe Browsing | Known malicious URLs |
| **IP Geolocation** | MaxMind, IP2Location | Hosting in suspicious regions |
| **Redirects** | HTTP Analysis | Multiple redirects = evasion technique |

### Tools We'll Use
- **python-whois** - WHOIS lookups for domain info
- **dnspython** - DNS record resolution
- **Google Safe Browsing API** - Blacklist checking
- **PhishTank API** - Crowd-sourced phishing database

---

## 3. Machine Learning Approaches

### Feature Categories

#### Text-Based Features (NLP)
- Urgency keywords ("act now", "verify immediately")
- Suspicious phrases ("confirm your account")
- Grammar/spelling errors
- Sender name vs email mismatch

#### URL-Based Features
- URL length (phishing URLs tend to be longer)
- Number of dots/subdomains
- Presence of IP address in URL
- Use of URL shorteners
- HTTPS vs HTTP
- Special characters (@, -, numbers)

#### OSINT-Based Features (Our Enhancement)
- Domain age in days
- Registrar reputation score
- DNS record completeness
- Blacklist presence
- SSL validity
- Historical WHOIS changes

### ML Algorithms Comparison

| Algorithm | Pros | Cons | Use Case |
|-----------|------|------|----------|
| **Random Forest** | High accuracy, handles mixed features | Less interpretable | Our primary model |
| **Logistic Regression** | Fast, interpretable | Limited for complex patterns | Baseline comparison |
| **SVM** | Good for high-dimensional data | Slow training on large datasets | Alternative model |
| **XGBoost** | State-of-the-art accuracy | Overfitting risk, complex tuning | Advanced comparison |
| **Neural Networks** | Can learn complex patterns | Needs large data, black-box | Future work |

### Our Approach
1. **Baseline Model**: Text + URL features only (scikit-learn)
2. **Enhanced Model**: Text + URL + OSINT features
3. **Compare**: Accuracy, precision, recall, F1-score

---

## 4. Datasets

### PhishTank (Primary Dataset)
- **Source**: https://phishtank.org/
- **Format**: JSON/CSV with verified phishing URLs
- **Size**: ~75,000+ verified phishing URLs
- **Features**: URL, submission time, verification status, target brand
- **Update**: Hourly updates available

### Additional Datasets

| Dataset | Description | Size |
|---------|-------------|------|
| **Kaggle Phishing Dataset** | Labeled phishing/legitimate URLs | ~10,000 |
| **ISCX-URL-2016** | Academic benchmark dataset | 36,400 URLs |
| **Alexa Top Sites** | Legitimate URLs for training | Top 1M |
| **OpenPhish** | Community-driven phishing feed | Real-time |

### Data Preprocessing Pipeline
1. Clean and normalize URLs
2. Extract domain from full URL
3. Collect OSINT features (WHOIS, DNS)
4. Extract text features if email content available
5. Label: 1 (phishing) / 0 (legitimate)
6. Split: 80% train, 20% test

---

## 5. Existing Solutions & Baseline Comparisons

### Academic Research

| Paper | Method | Accuracy | Year |
|-------|--------|----------|------|
| "Phishing Detection Using ML" (IEEE) | Random Forest + URL features | 97.2% | 2021 |
| "OSINT-based Phishing Analysis" | WHOIS + DNS features | 94.5% | 2022 |
| "Deep Learning for Phishing" | CNN + NLP | 98.1% | 2023 |
| "Explainable Phishing Detection" | SHAP + Random Forest | 96.3% | 2023 |

### Commercial Tools

| Tool | Approach | Limitation |
|------|----------|------------|
| Google Safe Browsing | Blacklist-based | Misses zero-day attacks |
| PhishTank | Crowd-sourced verification | Delayed detection |
| Proofpoint | Email gateway filtering | Enterprise-only, expensive |
| Microsoft Defender | Heuristic + ML | Closed-source |

### Our Differentiator
- **Open-source** and transparent
- **OSINT enrichment** for better context
- **Explainable results** - users see WHY something is phishing
- **Real-time analysis** - not just blacklist checking

---

## 6. Technology Stack

### Backend
| Technology | Purpose | Why Chosen |
|------------|---------|------------|
| **Python 3.10+** | Core language | ML ecosystem, async support |
| **FastAPI** | REST API framework | Fast, modern, async, auto-docs |
| **scikit-learn** | ML models | Industry standard, easy to use |
| **spaCy** | NLP processing | Fast, production-ready |
| **python-whois** | WHOIS lookups | Simple API |
| **dnspython** | DNS resolution | Comprehensive DNS library |

### Frontend
| Technology | Purpose | Why Chosen |
|------------|---------|------------|
| **HTML/CSS/JS** | Web UI | Simple, no build step for MVP |
| **React (future)** | Advanced UI | Component-based, scalable |

### APIs
| API | Purpose | Cost |
|-----|---------|------|
| **Google Safe Browsing** | URL reputation | Free (quota limits) |
| **PhishTank** | Phishing database | Free (with attribution) |
| **VirusTotal (optional)** | Multi-engine scan | Free tier available |

---

## 7. Evaluation Metrics

### Classification Metrics
- **Accuracy** - Overall correctness
- **Precision** - Of predicted phishing, how many were correct
- **Recall** - Of actual phishing, how many were detected
- **F1-Score** - Harmonic mean of precision and recall
- **ROC-AUC** - Model discrimination ability

### Our Target
| Metric | Target | Baseline (text-only) | Enhanced (OSINT) |
|--------|--------|---------------------|------------------|
| Accuracy | >95% | ~92% | ~96% (expected) |
| Precision | >90% | ~88% | ~94% (expected) |
| Recall | >95% | ~90% | ~96% (expected) |
| F1-Score | >93% | ~89% | ~95% (expected) |

---

## 8. Limitations & Future Work

### Known Limitations
- OSINT lookups add latency (1-3 seconds per URL)
- WHOIS privacy protection hides some data
- New domains with no history are harder to classify
- API rate limits (Google Safe Browsing, PhishTank)

### Future Improvements
- Real-time streaming detection
- Browser extension integration
- Email client plugin
- Deep learning models (BERT for text)
- Phishing campaign clustering

---

## 9. References

1. Mohammad, R. M., et al. "Predicting phishing websites based on self-structuring neural network." Neural Computing and Applications, 2014.

2. Sahingoz, O. K., et al. "Machine learning based phishing detection from URLs." Expert Systems with Applications, 2019.

3. Abutair, H., et al. "Using Case-Based Reasoning for Phishing Detection." Procedia Computer Science, 2019.

4. Rao, R. S., & Pais, A. R. "Detection of phishing websites using an efficient feature-based machine learning framework." Neural Computing and Applications, 2019.

5. PhishTank Documentation: https://phishtank.org/developer_info.php

6. Google Safe Browsing API: https://developers.google.com/safe-browsing

7. WHOIS Protocol (RFC 3912): https://datatracker.ietf.org/doc/html/rfc3912

---

*Research compiled for BSc Thesis: Phishing Detection Using OSINT-Enhanced Features*
*ELTE Faculty of Informatics - December 2025*
