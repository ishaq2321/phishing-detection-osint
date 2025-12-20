# Milestone 1 Plan (Deadline: December 20, 2025)

## Project: Phishing Detection Using OSINT-Enhanced Features

---

## ✅ Tasks Breakdown

### 1. Background Research (Day 1-2: Dec 13-14)
- [ ] Research existing phishing detection methods
- [ ] Study OSINT techniques (WHOIS, DNS, domain reputation)
- [ ] Review PhishTank dataset structure
- [ ] Find 2-3 baseline papers/projects for comparison
- [ ] Document findings in `docs/research.md`

**Deliverable:** Research summary document

---

### 2. System Design (Day 2-3: Dec 14-15)
- [ ] Design system architecture diagram (components: UI, API, ML Model, OSINT Module, Database)
- [ ] Design database schema (if storing results/logs)
- [ ] Create UI wireframes (submission form, results display)
- [ ] Define API endpoints (POST /analyze, GET /history)
- [ ] Document in `docs/architecture.md`

**Deliverable:** Architecture diagrams + API design

---

### 3. GitLab Repository Setup (Day 3: Dec 15)
- [ ] Create GitLab repository
- [ ] Add README with project description
- [ ] Create 4 milestones (Dec 20, Feb 20, Mar 25, Apr 15)
- [ ] Set up .gitignore for Python
- [ ] Initialize project structure

**Deliverable:** GitLab repo with proper setup

---

### 4. Dataset Preparation (Day 4: Dec 16)
- [ ] Download PhishTank dataset
- [ ] Explore dataset structure
- [ ] Prepare sample data for initial testing
- [ ] Document dataset statistics in `docs/dataset.md`

**Deliverable:** Dataset ready for use

---

### 5. Initial Prototype (Day 4-6: Dec 16-18)
- [ ] Set up Python virtual environment
- [ ] Install core dependencies (FastAPI, scikit-learn, spaCy)
- [ ] Create basic FastAPI server (Hello World endpoint)
- [ ] Implement simple URL analysis function
- [ ] Create basic HTML form for testing
- [ ] Test OSINT tools (python-whois, dnspython)

**Deliverable:** Working "Hello World" prototype

---

### 6. Documentation & Commit (Day 7: Dec 19-20)
- [ ] Write README with setup instructions
- [ ] Document current progress
- [ ] Prepare milestone report for Arafat
- [ ] Final commit and push to GitLab

**Deliverable:** Complete Milestone 1 submission

---

## 📂 Project Structure (Initial)

```
Thesis/
├── .github/
│   └── copilot-instructions.md
├── backend/
│   ├── main.py                 # FastAPI app
│   ├── osintModule.py          # OSINT data collection
│   ├── mlModel.py              # ML model (placeholder)
│   └── requirements.txt
├── frontend/
│   ├── index.html              # Simple UI
│   └── styles.css
├── data/
│   └── phishtank/              # Dataset
├── docs/
│   ├── milestones/
│   │   ├── milestone-1.md
│   │   ├── milestone-2.md
│   │   ├── milestone-3.md
│   │   └── milestone-4.md
│   ├── research.md
│   ├── architecture.md
│   └── dataset.md
├── tests/                      # Unit tests
├── README.md
└── .gitignore
```

---

## 🎯 Quick Win for Today (Dec 13)

1. Start background research (2 hours)
2. Create project structure locally
3. Set up Python virtual environment
4. Install FastAPI and test basic "Hello World"

**Ready to start? Let me know and I'll help you create the project structure!**
