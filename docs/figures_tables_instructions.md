## Instructions for Figures and Tables

### FIGURE 2-1: Phishing Attack Taxonomy Diagram

**How to create:**
1. Use a diagramming tool (draw.io, Lucidchart, PowerPoint SmartArt, or Python library like `graphviz`)
2. Create a hierarchical tree structure:
   - **Root node:** "Phishing Attacks"
   - **Level 2 branches:**
     - "Attack Vector" → Email, SMS, Voice, Social Media, Web
     - "Targeting Strategy" → Mass, Spear, Whaling
     - "Technical Method" → URL Spoofing, Clone, MITM, Malware
3. Use different colors for each category (e.g., blue for Attack Vector, green for Targeting Strategy, orange for Technical Method)
4. Export as PNG (300 DPI) or vector format (SVG, PDF)

**Caption:**
"Figure 2-1: Hierarchical taxonomy of phishing attacks classified by attack vector, targeting strategy, and technical method. Phishing attacks can employ multiple techniques simultaneously (e.g., spear phishing via email using URL spoofing)."

---

### TABLE 2-1: Types of Phishing Attacks
Already provided in the text. Format as a 4-column table with alternating row shading.

---

### TABLE 2-2: Comparison of Traditional Phishing Detection Methods
Already provided in the text. Use checkmarks (✅) and crosses (❌) for visual clarity.

---

### TABLE 2-3: Machine Learning Algorithms for Phishing Detection - Literature Review
Already provided in the text. Highlight the "This Work (PhishGuard)" row in a different color or bold.

---

### TABLE 2-4: OSINT Data Sources and Their Utility
Already provided in the text. Format as a 4-column table.

---

### TABLE 2-5: Feature Comparison with Existing Solutions
Already provided in the text. Use symbols (✅ Yes, ❌ No, ⚠️ Limited) for visual clarity. Highlight the "PhishGuard" column.

---

### FIGURE 2-2: OSINT Data Collection and Feature Engineering Pipeline

**How to create:**
1. Create a flowchart using draw.io, Lucidchart, or Python (`matplotlib`, `graphviz`)
2. Structure:
   - **Start:** "Input URL"
   - **Step 1:** "Extract Domain"
   - **Parallel Branches:**
     - Branch A: "WHOIS Lookup" → "Parse Registration Date, Registrar, Privacy" → "Domain Age Score"
     - Branch B: "DNS Resolution" → "Query A, MX, NS, CNAME" → "DNS Validity Features"
     - Branch C: "Reputation APIs" → "VirusTotal, AbuseIPDB" → "Reputation Score"
   - **Merge:** All branches merge into "Feature Vector (21 dimensions)"
   - **End:** "XGBoost Classifier" → "Phishing Probability"
3. Use arrows to show data flow
4. Export as high-resolution PNG or vector format

**Caption:**
"Figure 2-2: OSINT data collection and feature engineering pipeline. The input URL undergoes parallel OSINT enrichment (WHOIS, DNS, reputation APIs) to generate OSINT-derived features, which are combined with URL structural features to form the complete 21-dimensional feature vector for ML classification."

---

**Next Chapter:**
Let me know when you're ready, and I'll proceed to **Chapter 3: System Design and Architecture** (8-10 pages).

---

### FIGURE 8-1: Asynchronous Analysis Orchestrator Pipeline

**How to create:**
1. Use a sequence diagram tool (e.g., Mermaid.js, draw.io, or PlantUML).
2. Define the following actors/components:
   - Client (Frontend)
   - Orchestrator (`backend/api/orchestrator.py`)
   - NLP Module
   - OSINT Gatherer (`asyncio.gather` block)
   - ML Predictor (`XGBoost`)
3. Create the following flow:
   - **Client** sends `POST /analyze` to **Orchestrator**.
   - **Orchestrator** concurrently dispatches tasks:
     - `asyncio.create_task` to **NLP Module**.
     - `asyncio.wait_for(asyncio.gather(...), timeout=15.0)` to **OSINT Gatherer** (which further splits into WHOIS, DNS, and Reputation).
   - Show the 15-second timeout boundary enforcing a strict SLA.
   - Once OSINT returns, **Orchestrator** passes `OsintData` and URL to **ML Predictor**.
   - **Orchestrator** awaits all results, applies `_combineVerdict` weighting logic, and returns the final `AnalysisResponse` to the **Client**.
4. Export as a high-resolution PNG or SVG.

**Caption:**
"Figure 8-1: Sequence diagram illustrating the asynchronous execution pipeline within the Analysis Orchestrator. The diagram highlights the concurrent execution of NLP and OSINT gathering tasks, bounded by a strict 15.0-second global timeout to ensure API responsiveness."

---

### FIGURE 9-1: PhishGuard Quality Assurance Architecture

**How to create:**
1. Use a block architecture tool (e.g., Lucidchart, draw.io, or Visio).
2. Create two distinct vertical sections: "Backend Testing" and "Frontend Testing".
3. **Backend Section:**
   - Draw a large box for `pytest`.
   - Inside the box, place three tiers (pyramid style):
     - Bottom (Unit): "Isolated Tests (`tests/unit/`)" pointing to "Mocked OSINT Data (`conftest.py`)".
     - Middle (Integration): "FastAPI TestClient" pointing to "Batch Analysis".
     - Top (Smoke): "SLA Enforcement (< 5.0s, < 1.0s)".
4. **Frontend Section:**
   - Draw a large box for "Next.js QA".
   - Inside the box, place two tiers:
     - Bottom (Component/State): "Jest & React Testing Library" pointing to "State Stores & UI DOM".
     - Top (End-to-End): "Playwright" pointing to "Browser Automation (Simulating User Flow)".
5. Draw a horizontal bar at the very bottom spanning both sections labeled: "Static Analysis (Pyright & TypeScript / ESLint)".
6. Export as a high-resolution PNG or SVG (300 DPI).

**Caption:**
"Figure 9-1: The multi-tiered Quality Assurance architecture of the PhishGuard platform, illustrating the strict separation between backend execution (`pytest` and mocked dependencies) and frontend UI automation (Jest and Playwright), underpinned by rigorous static type checking."
